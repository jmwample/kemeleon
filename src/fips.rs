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

use crate::{Barr8, EncodingSize, FieldElement, NttArray, ARR_LEN, RHO_LEN};

// ========================================================================== //
// FIPs spec Encoding
// ========================================================================== //

// Algorithm 4 ByteEncode_d(F)
//
// Note: This algorithm performs compression as well as encoding.
pub(crate) fn byte_encode<D>(
    rho: &[u8; 32],
    ntt_vals: &NttArray<{ D::K }>,
) -> Barr8<{ D::FIPS_ENCODED_SIZE }>
where
    D: EncodingSize,
{
    let mut bytes = [0u8; D::FIPS_ENCODED_SIZE];
    let idx = D::FIPS_ENCODED_SIZE - RHO_LEN;
    bytes[idx..].copy_from_slice(&rho[..]);

    let val_step = D::VALUE_STEP;
    let byte_step = D::BYTE_STEP;

    let vc = ntt_vals.as_flattened().chunks(val_step);
    let bc = bytes[..idx].chunks_mut(byte_step);
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
    //TODO: Lenth check on input for safety?

    let mut rho = [0u8; RHO_LEN];
    let idx = bytes.as_ref().len() - RHO_LEN;
    rho.copy_from_slice(&bytes.as_ref()[idx..]);

    let val_step = D::VALUE_STEP;
    let byte_step = D::BYTE_STEP;
    let mask = (1 << D::USIZE) - 1;

    let mut vals = [[0u16; ARR_LEN]; D::K];

    let vc = vals.as_flattened_mut().chunks_mut(val_step);
    let bc = bytes.as_ref()[..idx].chunks(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut xb = [0u8; 16];
        xb[..byte_step].copy_from_slice(b);

        let x = u128::from_le_bytes(xb);
        for (j, v_out) in v.iter_mut().enumerate() {
            // TODO: is the truncate implementation really necessary?
            let val: u16 = (x >> (D::USIZE * j)).truncate();
            *v_out = val & mask;

            if D::USIZE == 12 {
                *v_out %= FieldElement::Q;
            }
        }
    }
    (rho, vals)
}

/// Safely truncate an unsigned integer value to shorter representation
pub trait Truncate<T> {
    fn truncate(self) -> T;
}

macro_rules! define_truncate {
    ($from:ident, $to:ident) => {
        impl Truncate<$to> for $from {
            fn truncate(self) -> $to {
                // This line is marked unsafe because the `unwrap_unchecked` call is UB when its
                // `self` argument is `Err`.  It never will be, because we explicitly zeroize the
                // high-order bits before converting.  We could have used `unwrap()`, but chose to
                // avoid the possibility of panic.
                unsafe { (self & $from::from($to::MAX)).try_into().unwrap_unchecked() }
            }
        }
    };
}

define_truncate!(u32, u16);
define_truncate!(u64, u32);
define_truncate!(usize, u8);
define_truncate!(u128, u16);
define_truncate!(u128, u8);

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
        [(); <D as EncodingSize>::FIPS_ENCODED_SIZE]:,
    {
        let mut rng = rand::thread_rng();
        let (_, ek) = D::generate(&mut rng);

        let bytes_in = ek.as_bytes().to_vec();
        assert!(!bytes_in.is_empty());
        let (rho, ntt) = byte_decode::<D>(&bytes_in);

        let bytes_out = byte_encode::<D>(&rho, &ntt);
        // check that the byte representation of rho matches.
        assert_eq!(
            hex::encode(&bytes_in[..RHO_LEN]),
            hex::encode(&bytes_out[..RHO_LEN]),
            "rho values do not match"
        );
        // check that the byte representation of the polynomials matches.
        assert_eq!(
            hex::encode(&bytes_in[RHO_LEN..]),
            hex::encode(&bytes_out[RHO_LEN..]),
            "polynomials do not match"
        );

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

    #[test]
    fn fixed_encap_key() {
        let encoded_key = "1d04f737d1811f950ccc2340bff7640bd95ac2350b92ee6a5dcb4ccd05799bd2a25ad5b04a7a90a064387f9f8b6e77c60309a09b0d3307de9c936a91b797906674134fc9fbb5f1b450d5daa7ddc74c26d43aa8b351b4673f6bc32d89f460666475a28765ce722b42e682941b04635371a5234f6b168142c3366ce6bbd24a52a644619856c4303b0292227e9ae16ccaf33fc4f1a9fb537294b0261f7b1ca6ea14fa02bb12871add605345e4b18d446d5d33951d563b606c4329648b1c92a54f307ab7722294a95c1c42b3734586fd5044e39553c81458e1f85e4dec0275c9248ebc56f623cd08824386c16918a993e3454d1581c8a9c3a032b79d18e21f84c08e033bae46c098f6d55f83c28bef252aa43335dde63c96465125e46101accca40437a0810f616584d73cac1c54071a05c32f21bde9d2ad90e809f61862db966671eb2ace541290502d90185d819a7d0e566fa5e454e3cc7da8c93187a3af32dc831421c9b7ea984ad7c45483a119bca58ba8a1fc2201598884ce93255e359e8f989224548ab7f91657a56f83d68a21656d854432362a71d0727f45ca0138605885ac4314d2a1c8f61522e8aa91813fd6ab0ac438c04c182e25e774ac2c3c967306eda695d15505182a788191a46b3252a9917b56e23c92a7a51fc09f43221b806178272c11de8598f6a049d5ca2b342c08c4f13ca8d79ab7447bc0871ed525653b19b78bdb1fef17a3a14a2607dbcb7952a043012642a782d22706c08487bbcb95a6494dff891f75a86ce15c77c73c880e516a41139df7f0adf4d393cc564b68896d419948dcbb74740b5f85115c65ba0e5602449d10b20783abbd56b1b1b2cf5c73768563056eb76e8338515da7af1b62b29a05a1ed531de0b84b4c3033e80c3d50866dd3c0a17b9387e97963165720b587785912bdab15c946893024579923f16a46bbac862aa823d81619c616af92a0575019af5732c4a80686c1c4f81ac743611e45453e820878aa6498c28984b17b073d38945a73c8f8e033c038a5a25504a3324679490285be911109c35dec1c7ffa48d62c3acaddb348150b9a0de15dc40000000000000000000000000000000000000000000000000000000000000000";

        let ek_bytes = hex::decode(&encoded_key).expect("failed to unhex");
        let ek_encoded =
            Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem512Params>>::try_from(
                &ek_bytes[..],
            )
            .expect("failed to build hybrid array");
        let ek_decoded_in =
            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem512Params>::from_bytes(&ek_encoded);

        let (rho, ntt) = byte_decode::<MlKem512>(&ek_bytes);

        let bytes_out = byte_encode::<MlKem512>(&rho, &ntt);

        let ek_encoded =
            Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem512Params>>::try_from(
                &bytes_out[..],
            )
            .expect("failed to build hybrid array");
        let ek_decoded_out =
            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem512Params>::from_bytes(&ek_encoded);

        assert_eq!(ek_decoded_in, ek_decoded_out);
    }
}

// // ========================================================================== //
// // Unsafe struct transmute
// // ========================================================================== //
//
// use hybrid_array::{typenum::{U256, U32}, Array};
// use ml_kem::{kem::Kem, ArraySize, KemCore, PkeParams};
//
// /// An `EncapsulationKey` provides the ability to encapsulate a shared key so that it can only be
// /// decapsulated by the holder of the corresponding decapsulation key.
// #[derive(Clone, Debug, PartialEq)]
// pub struct EncapsulationKey<P>
// where
//     P: ml_kem::kem::KemParams,
// {
//     ek_pke: EncryptionKey<P>,
//     h: B32,
// }
//
// /// An `EncryptionKey` provides the ability to encrypt a value so that it can only be
// /// decrypted by the holder of the corresponding decapsulation key.
// #[derive(Clone, Default, Debug, PartialEq)]
// pub struct EncryptionKey<P>
// where
//     P: PkeParams,
// {
//     t_hat: NttVector<P::K>,
//     rho: B32,
// }
//
// impl<P> EncapsulationKey<P>
// where
//     P: PkeParams,
// {
//     fn twin(key: ml_kem::kem::EncapsulationKey<P>) -> Self {
//         unsafe {
//             std::mem::transmute(key)
//         }
//     }
// }
//
//
// /// A 32-byte array, defined here for brevity because it is used several times
// pub type B32 = Array<u8, U32>;
//
// /// A vector of K NTT-domain polynomials
// #[derive(Clone, Default, Debug, PartialEq)]
// pub struct NttVector<K: ArraySize>(pub Array<NttPolynomial, K>);
//
// /// An element of the ring `T_q`, i.e., a tuple of 128 elements of the direct sum components of `T_q`.
// #[derive(Clone, Default, Debug, PartialEq)]
// pub struct NttPolynomial(pub Array<FE, U256>);
//
// pub type Integer = u16;
//
// /// An element of GF(q).  Although `q` is only 16 bits wide, we use a wider uint type to so that we
// /// can defer modular reductions.
// #[derive(Copy, Clone, Debug, Default, PartialEq)]
// pub struct FE(pub Integer);
