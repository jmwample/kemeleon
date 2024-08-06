//! Rust ML-KEM encodings following the [FIPS 203 Initial Public Draft](https://csrc.nist.gov/pubs/fips/203/ipd)
//!
//! This code was drawn almost directly from the [`ml-kem`](https://docs.rs/ml-kem) crate.

use crate::{EncodingSize, FieldElement, NttArray, ARR_LEN, RHO_LEN};
use std::io::Error;

// ========================================================================== //
// FIPs spec Encoding
// ========================================================================== //

// Algorithm 4 ByteEncode_d(F)
//
// Note: This algorithm performs compression as well as encoding.
pub(crate) fn byte_encode<D: EncodingSize>(
    rho: &[u8; 32],
    ntt_vals: &NttArray<{ D::K }>,
) -> Vec<u8> {
    let val_step = D::VALUE_STEP;
    let byte_step = D::BYTE_STEP;

    let mut bytes = Vec::with_capacity(D::ENCODED_SIZE);
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
) -> Result<([u8; 32], NttArray<{ D::K }>), Error> {
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
        for j in 0..v.len() {
            let val: u16 = (x >> (D::USIZE * j)) as u16;
            let mut vj = val & mask;

            if D::USIZE == 12 {
                vj %= FieldElement::Q;
            }
            v[j] = vj;
        }
    }

    // TODO: decode rho
    Ok(([0u8; 32], vals))
}

#[cfg(test)]
mod tests {
    use kem::{Decapsulate, Encapsulate};
    use ml_kem::{KemCore, MlKem1024, MlKem512, MlKem768, RawBytes};

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
}
