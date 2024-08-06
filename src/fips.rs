//! Rust ML-KEM encodings following the [FIPS 203 Initial Public Draft](https://csrc.nist.gov/pubs/fips/203/ipd)
//!
//! This code was drawn almost directly from the [`ml-kem`](https://docs.rs/ml-kem) crate.
//!
//!
//!
//! # Strategies
//!
//! I have three options for integrating with the ['ml_kem'] crate because none has
//! emerged as obviously best / easiest.
//!
//! 1. Implement my own `byte_encode(f)` and `byte_decode(f)` fips encoding
//! functions and interface with 'ml_kem' crate by using it's as_bytes() then
//! parsing to my own local format before re-encoding to kemeleon (and reverse
//! when decoding back to ml_kem).
//!
//! 2. Make changes to the `ml_kem` crate that allow exposing the raw bytes
//! of the ntt polynomials and rho. Then just access them directly from the key
//! and build key from the pieces once a key is parsed from kemeleon representation.
//!
//! 3. Make a local copy of the key struct and use an unsafe transmute to convert
//! to my own struct type where I have access to the internal fields. This requires
//! no changes to the `ml_kem` library, and is used directly like option (2).

use crate::{EncodingSize, FieldElement, Barr8, NttArray, ARR_LEN, RHO_LEN};

use core::cmp::min;

// ========================================================================== //
// FIPs spec Encoding
// ========================================================================== //

// Algorithm 4 ByteEncode_d(F)
//
// Note: This algorithm performs compression as well as encoding.
pub(crate) fn byte_encode<D>(
    rho: &[u8; 32],
    ntt_vals: &NttArray<{ D::K }>,
) -> Barr8<{ D::UNENCODED_SIZE }>
where
    D: EncodingSize,
    // [(); <D as EncodingSize>::UNENCODED_SIZE]:,
{
    let val_step = D::VALUE_STEP;
    let byte_step = D::BYTE_STEP;

    let mut bytes = [0u8; D::UNENCODED_SIZE];
    bytes[..RHO_LEN].copy_from_slice(&rho[..]);

    let vc = ntt_vals.as_flattened().chunks(val_step);
    let bc = bytes[RHO_LEN..].chunks_mut(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut x = 0u128;
        for (j, vj) in v.iter().enumerate() {
            x |= u128::from(*vj) << (D::USIZE * j);
        }

        let xb = x.to_le_bytes();
        b.copy_from_slice(&xb[..min(byte_step, b.len())]);
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
    let mut rho = [0u8; RHO_LEN];
    rho.copy_from_slice(&bytes.as_ref()[..RHO_LEN]);

    let vc = vals.as_flattened_mut().chunks_mut(val_step);
    let bc = bytes.as_ref()[RHO_LEN..].chunks(byte_step);
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
    (rho, vals)
}

#[cfg(test)]
mod tests {
    use super::{byte_decode, byte_encode};
    use crate::{EncodingSize, RHO_LEN};

    use kem::{Decapsulate, Encapsulate};
    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768, RawBytes};


// =================================================
//          Strategy 2 (implement FIPs conversion)
// =================================================

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

// =================================================
//          Strategy 1 (implement FIPs conversion)
// =================================================

    fn fips_encode_trial<D>()
    where
        D: KemCore + EncodingSize,
        [(); <D as EncodingSize>::K]:,
        [(); <D as EncodingSize>::UNENCODED_SIZE]:,
    {
        let mut rng = rand::thread_rng();
        let (_, ek) = D::generate(&mut rng);

        let bytes_in = ek.as_bytes().to_vec();
        assert!(!bytes_in.is_empty());
        let (rho, ntt) = byte_decode::<D>(&bytes_in);

        let bytes_out = byte_encode::<D>(&rho, &ntt);
        // check that the byte representation of rho matches.
        assert_eq!(hex::encode(&bytes_in[..RHO_LEN]), hex::encode(&bytes_out[..RHO_LEN]), "rho values do not match");
        // check that the byte representation of the polynomials matches.
        assert_eq!(hex::encode(&bytes_in[RHO_LEN..]), hex::encode(&bytes_out[RHO_LEN..]), "polynomials do not match");

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
