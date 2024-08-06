//! Rust ML-KEM encodings following the [FIPS 203 Initial Public Draft](https://csrc.nist.gov/pubs/fips/203/ipd)
//!
//! This code was drawn almost directly from the [`ml-kem`](https://docs.rs/ml-kem) crate.

use crate::{EncodingSize, FieldElement, NttArray, ARR_LEN, RHO_LEN};

// ========================================================================== //
// FIPs spec Encoding
// ========================================================================== //

// Algorithm 4 ByteEncode_d(F)
//
// Note: This algorithm performs compression as well as encoding.
pub(crate) fn byte_encode<D>(
    rho: &[u8; 32],
    ntt_vals: &NttArray<{ D::K }>,
) -> [u8; <D as EncodingSize>::ENCODED_SIZE]
where
    D: EncodingSize,
    [(); <D as EncodingSize>::ENCODED_SIZE]:,
{
    let val_step = D::VALUE_STEP;
    let byte_step = D::BYTE_STEP;

    let mut bytes = [0u8; D::ENCODED_SIZE];
    bytes[..RHO_LEN].copy_from_slice(&rho[..]);

    let vc = ntt_vals.as_flattened().chunks(val_step);
    let bc = bytes[RHO_LEN..].chunks_mut(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut x = 0u128;
        for (j, vj) in v.iter().enumerate() {
            x |= u128::from(*vj) << (D::USIZE * j);
        }

        let xb = x.to_le_bytes();
        b.copy_from_slice(&xb[..byte_step]);
    }

    bytes
}

// Algorithm 5 ByteDecode_d(F)
//
// Note: This function performs decompression as well as decoding.
pub(crate) fn byte_decode<D: EncodingSize>(
    bytes: impl AsRef<[u8]>,
) -> ([u8; 32], NttArray<{ D::K }>) {
    let val_step = D::VALUE_STEP;
    let byte_step = D::BYTE_STEP;
    let mask = (1 << D::USIZE) - 1;

    let mut vals = [[0u16; ARR_LEN]; D::K];

    let vc = vals.as_flattened_mut().chunks_mut(val_step);
    let bc = bytes.as_ref().chunks(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut xb = [0u8; 16];
        xb[..byte_step].copy_from_slice(b);

        let x = u128::from_le_bytes(xb);
        for (j, v_out) in v.iter_mut().enumerate() {
            let val: u16 = (x >> (D::USIZE * j)) as u16;
            let mut vj = val & mask;

            if D::USIZE == 12 {
                vj %= FieldElement::Q;
            }
            *v_out = vj;
        }
    }

    // TODO: decode rho
    ([0u8; 32], vals)
}

#[cfg(test)]
mod tests {
    use super::{byte_decode, byte_encode};
    use crate::EncodingSize;

    use kem::{Decapsulate, Encapsulate};
    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768, RawBytes};

    fn try_raw<P: KemCore>() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = P::generate(&mut rng);

        let (rho, ntt) = <P::EncapsulationKey as RawBytes>::as_raw(&ek);

        let ek = P::EncapsulationKey::from_raw(rho.as_ref(), ntt);

        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();

        let k_recv = dk.decapsulate(&ct).unwrap();
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn to_from_raw() {
        try_raw::<MlKem512>();
        try_raw::<MlKem768>();
        try_raw::<MlKem1024>();
    }

    fn fips_encode_trial<D>()
    where
        D: KemCore + EncodingSize,
        [(); <D as EncodingSize>::K]:,
        [(); <D as EncodingSize>::ENCODED_SIZE]:,
    {
        let mut rng = rand::thread_rng();
        let (_, ek) = D::generate(&mut rng);

        let bytes_in = ek.as_bytes().to_vec();
        assert!(!bytes_in.is_empty());
        let (rho, ntt) = byte_decode::<D>(&bytes_in);

        let bytes_out = byte_encode::<D>(&rho, &ntt);
        assert_eq!(bytes_in, bytes_out);

        let tmp = Encoded::<<D as KemCore>::EncapsulationKey>::try_from(&bytes_out[..])
            .expect("failed to build hybrid_array::Array from bytes");
        let reconst_ek = <D as KemCore>::EncapsulationKey::from_bytes(&tmp);
        assert_eq!(ek, reconst_ek);
    }

    #[test]
    fn custom_fips() {
        fips_encode_trial::<MlKem512>();
        fips_encode_trial::<MlKem768>();
        fips_encode_trial::<MlKem1024>();
    }
}
