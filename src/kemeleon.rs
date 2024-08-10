use crate::RHO_LEN;
use crate::{fips, Barr8, EncodingSize, FieldElement, Transcode, ARR_LEN};

use core::cmp::min;
use core::marker::PhantomData;
use std::io::Error as IoError;

use ml_kem::{Encoded, EncodedSizeUser, KemCore};
use num_bigint::BigUint;

pub use crate::mlkem::EncodedCiphertext;
pub use crate::mlkem::KEncapsulationKey as EncapsulationKey;

pub trait Encode {
    /// Encapsulation Key Type
    type EK;
    /// Encoded type (i.e Encoded Encapsulation Key, or Encoded Ciphertext)
    type ET;

    /// Error Type returned on failed decode
    type Error;

    fn as_bytes(&self) -> Self::ET;

    /// Try to parse from bytes
    ///
    /// # Errors
    /// - length error: input ciphertext is the wrong size
    ///
    fn try_from_bytes(c: impl AsRef<[u8]>) -> Result<Self::EK, Self::Error>;
}

// ========================================================================== //
// Encapsulation Key
// ========================================================================== //

pub trait Encodable: Encode {
    fn satisfies_sampling(&self) -> bool;
}

impl<P> Encode for EncapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); <P as EncodingSize>::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K]:,
{
    type EK = Self;
    type ET = Barr8<{ <P as EncodingSize>::ENCODED_SIZE }>;
    type Error = IoError;

    /// In this formulation a is 1 indexed (as oposed to being 0 indexed)
    ///
    /// Kemeleon.Encode(a):
    /// ```txt ignore
    ///     1 𝑟 ← sum(𝑖=1, 𝑘·𝑛, 𝑞^(𝑖−1) · a[𝑖]
    ///     2 if 𝑟 .bit( ⌈log2 (𝑞^(𝑛·𝑘) + 1) ⌉) = 1:
    ///     3     return ⊥ // most significant bit is 1
    ///     4 return 𝑟 .bit(0 : ⌈log2 (𝑞^(𝑛·𝑘) + 1) ⌉ − 1)
    /// ```
    ///
    /// The intuition here is to accumulate (sum) the integer coefficients,
    /// resulting in a single larger integer whose intermediary bits are no longer
    /// biased.
    fn as_bytes(&self) -> Self::ET {
        let mut dst = [0u8; <P as EncodingSize>::ENCODED_SIZE];
        // we know there will be no size error and we know the key will be encodable
        // so we do not need the result.
        let _ = self.encode_priv(&mut dst);

        dst
        // todo!("key as bytes implementation incomplete")
    }

    /// Kemeleon.Decode(𝑟):
    /// ```txt ignore
    ///     1 𝑟 .bit( ⌈log2(𝑞^(𝑛·𝑘 + 1) ⌉) ← 0
    ///         // set most significant bit to 0
    ///
    ///     2 for 𝑖 = 1 to 𝑘 · 𝑛:
    ///     3     a[𝑖] ← ( 𝑟− sum(𝑗=1, 𝑖−1, 𝑝𝑘 [𝑗]) ) / ( 𝑞^(𝑖−1) ) mod 𝑞
    ///     4 return a
    /// ```
    fn try_from_bytes(c: impl AsRef<[u8]>) -> Result<Self::EK, Self::Error> {
        EncapsulationKey::<P>::decode(c.as_ref())
    }
}

impl<P> Encodable for EncapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); <P as EncodingSize>::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K]:,
{
    fn satisfies_sampling(&self) -> bool {
        let mut dst = [0u8; <P as EncodingSize>::ENCODED_SIZE];
        self.encode_priv(&mut dst).expect("should never fail")
    }
}

impl<P> EncapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); <P as EncodingSize>::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K]:,
{
    fn decode(c: impl AsRef<[u8]>) -> Result<Self, IoError>
    where
        P: KemCore + EncodingSize,
    {
        if c.as_ref().len() < <P as EncodingSize>::ENCODED_SIZE {
            return Err(IoError::other("incorrect length"));
        }

        // TODO: get the random mask byte from the high order bits
        let rand_byte = c.as_ref()[P::ENCODED_SIZE - (RHO_LEN + 1)] & P::MSB_BITMASK;

        let mut rho = [0u8; RHO_LEN];
        rho[..].clone_from_slice(&c.as_ref()[P::ENCODED_SIZE - RHO_LEN..]);

        let base = BigUint::from(FieldElement::Q);
        let mut r = BigUint::from_bytes_le(&c.as_ref()[..P::ENCODED_SIZE - RHO_LEN]);

        // remove the randomized the high order bits by setting every bit above
        // the HIGH_ORDER_BIT to 0.
        if r.bits() > P::HIGH_ORDER_BIT {
            (P::HIGH_ORDER_BIT..r.bits()).for_each(|i| r.set_bit(i, false));
        }

        let mut vals = [[0u16; ARR_LEN]; P::K];
        for (i, val) in vals.as_flattened_mut().iter_mut().enumerate() {
            let pk_i = &r % &base;
            r = (&r - &pk_i) / &base;

            let k = pk_i.to_u32_digits();
            *val = if k.is_empty() { 0u16 } else { k[0] as u16 };
            if i < 3 {
                println!("xxx_dec {i} {} {}", hex::encode(pk_i.to_bytes_le()), val);
            }
        }

        let bytes = fips::byte_encode::<P>(&rho, &vals);

        let ek_bytes =
            Encoded::<<P as KemCore>::EncapsulationKey>::try_from(&bytes[..]).map_err(|e| {
                IoError::other(format!("failed to convert to hybrid_array::Array: {e}"))
            })?;
        let key = <P as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
        let mut ek = EncapsulationKey::from_fips(key);
        ek.byte = rand_byte;

        Ok(ek)
    }

    fn encode_priv(&self, mut dst: impl AsMut<[u8]>) -> Result<bool, IoError> {
        let k = dst.as_mut();
        if k.len() < P::ENCODED_SIZE {
            return Err(IoError::other(format!(
                "invalid dst array size. {} != {}",
                P::ENCODED_SIZE,
                k.len()
            )));
        }

        let mut out = BigUint::ZERO;
        let base = BigUint::from(FieldElement::Q);

        let vals_fips_encoded = self.key.as_bytes().to_vec();
        let (rho, vals) = fips::byte_decode::<P>(vals_fips_encoded);

        let mut offset = BigUint::from(1u64);
        for (i, val) in vals.as_flattened().iter().enumerate() {
            let bigx = BigUint::from(*val);
            if i < 3 {
                println!("xxx_enc {i} {val} {val:04x}");
            }
            out += bigx * &offset;
            offset *= &base;
        }
        // for (i, x) in vals.iter() {
        //     for (j, val) in x.iter().enumerate() {
        //         let bigx = BigUint::from(*val);
        //         out += bigx * &offset;
        //         offset *= &base;
        //     }
        // }

        // write out the bytes of the Encapsulation Key
        let b = out.to_bytes_le();
        let l = min(P::ENCODED_SIZE - RHO_LEN, b.len());
        k[..l].copy_from_slice(&b[..l]);

        // randomize the high order bits
        k[P::ENCODED_SIZE - (RHO_LEN + 1)] &= self.byte & <P as EncodingSize>::MSB_BITMASK;

        // append rho
        k[P::ENCODED_SIZE - RHO_LEN..].copy_from_slice(&rho[..]);

        Ok(!out.bit(2996))
    }
}

// ========================================================================== //
// CipherText
// ========================================================================== //

impl<P> Encode for EncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
    [(); <P as EncodingSize>::K * RHO_LEN]:,
{
    /// Encapsulation Key
    type EK = Self;

    /// Encoded Cuphertext Type
    type ET = Barr8<{ P::K * RHO_LEN }>;

    /// Error Type returned on failed decode
    type Error = IoError;

    fn as_bytes(&self) -> Self::ET {
        // self.bytes.clone()
        todo!("Ciphertext encoding not implemented yet")
    }

    fn try_from_bytes(b: impl AsRef<[u8]>) -> Result<Self, IoError> {
        if b.as_ref().is_empty() {
            return Err(IoError::other("bad bytestring provided"));
        }
        Ok(Self {
            bytes: b.as_ref().to_vec(),
            _p: PhantomData,
        })
    }
}

// fn decode_ctxt_priv<P>(
//     c: impl AsRef<[u8]>,
//     dst: impl Write,
// ) -> Result<ml_kem::Ciphertext<P>, IoError>
// where
//     P: KemCore + EncodingSize,
// {
//     let idx_r1 = P::DV * ARR_LEN;
//     let r1 = &c.as_ref()[..c.as_ref().len() - idx_r1];
//     let r2 = &c.as_ref()[idx_r1..];
//
//     let u = decode::<P>(r2).map_err(|e| IoError::other("error occured while decoding"))?;
//     let c1 = compress(Into::<[u16; ARR_LEN]>::into(u), P::DU);
//     let ctxt: Vec<u8> = c1.iter().zip(r2).map(|(v1, v2)| v1 | v2).collect();
//
//     #[allow(deprecated)]
//     Ok(*Ciphertext::<P>::from_slice(&ctxt))
// }
//
// const QFD: f64 = 4096.0 / 3329.0;
// const DFQ: f64 = 3329.0 / 4096.0;
//
// /// x −→ ⌈((2^d)/q)· x⌋
// fn compress(u: impl AsRef<[u16]>, _du: usize) -> Vec<u16> {
//     u.as_ref().iter().map(|v| (*v as f64 * QFD + 0.5) as u16).collect()
// }
//
// /// y −→ ⌈(q/(2^d))· y⌋
//
// fn decompress(c: impl AsRef<[u16]>, _du: usize) -> Vec<u16> {
//     c.as_ref().iter().map(|v| (*v as f64 * DFQ + 0.5) as u16).collect()
// }

// ========================================================================== //
// Tests
// ========================================================================== //

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::Kemx;
    use ml_kem::MlKem512;

    fn encode_decode_trial<P>()
    where
        P: KemCore + EncodingSize,
        [(); <P as EncodingSize>::FIPS_ENCODED_SIZE]:,
        [(); <P as EncodingSize>::ENCODED_SIZE]:,
        [(); <P as EncodingSize>::K]:,
    {
        let mut rng = rand::thread_rng();
        // This is the repeated trial generate from random and any key created
        // is guaranteed to be representable, otherwise it would have panicked
        let (_dk, ek) = Kemx::<P>::generate(&mut rng);
        let orig = ek.key.as_bytes().to_vec();

        // let mut dst: <P as EncodingSize>::EncodedKeyType;
        let mut dst = [0u8; <P as EncodingSize>::ENCODED_SIZE];
        _ = ek.encode_priv(&mut dst).expect("failed kemeleon encode");

        // Encapsulation Key decoded from bytes sent over the wire.
        let recv_ek = EncapsulationKey::<P>::decode(dst).expect("failed decode");

        assert_eq!(hex::encode(&orig), hex::encode(recv_ek.key.as_bytes()));
    }

    #[test]
    fn encode_decode() {
        encode_decode_trial::<ml_kem::MlKem512>();
        encode_decode_trial::<ml_kem::MlKem768>();
        encode_decode_trial::<ml_kem::MlKem1024>();
    }

    #[test]
    fn compute_constants() {
        let q = BigUint::from(FieldElement::Q);
        let expected_lengths = [2995, 5990, 8986, 11981];

        let n = 256;
        for k in [1, 2, 3, 4] {
            let v: BigUint = q.pow(n * k) + 1u32;

            let bits = v.bits() - 1;
            assert_eq!(bits, expected_lengths[k as usize - 1]);
            // println!("{} {}", bits, bits%8)
        }
    }

    fn test_encode_decode(encoded_key: &str) {
        let ek_bytes = hex::decode(encoded_key).expect("failed to unhex");
        let ek_encoded =
            Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem512Params>>::try_from(
                &ek_bytes[..],
            )
            .expect("failed to build hybrid array");
        let ek_decoded_in =
            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem512Params>::from_bytes(&ek_encoded);
        let ek_in = EncapsulationKey::<MlKem512>::from_fips(ek_decoded_in);

        // Encode encapsulation key using Kemeleon
        let mut dst = [0u8; MlKem512::ENCODED_SIZE];
        _ = ek_in.encode_priv(&mut dst).expect("failed kemeleon encode");

        // Encapsulation Key decoded from bytes sent over the wire.
        let recv_ek = EncapsulationKey::<MlKem512>::decode(dst).expect("failed decode");

        assert_eq!(
            hex::encode(ek_in.key.as_bytes()),
            hex::encode(recv_ek.key.as_bytes())
        );
    }

    #[test]
    fn encode_fixed_encap_key() {
        let mut zero = [0u8; 800];
        // test_encode_decode(&hex::encode(zero));

        // zero[0] = 1u8;
        // test_encode_decode(&hex::encode(zero));

        // zero[0] = 0u8;
        // zero[1] = 1u8;
        // test_encode_decode(&hex::encode(zero));

        // zero[0] = 1u8;
        // zero[1] = 1u8;
        // test_encode_decode(&hex::encode(zero));

        // zero[0] = 0xffu8;
        // zero[1] = 0xffu8;
        // test_encode_decode(&hex::encode(zero));

        zero[0] = 0x00u8;
        zero[1] = 0x00u8;
        zero[767] = 0xffu8;
        test_encode_decode(&hex::encode(zero));
        // let encoded_key = "1d04f737d1811f950ccc2340bff7640bd95ac2350b92ee6a5dcb4ccd05799bd2a25ad5b04a7a90a064387f9f8b6e77c60309a09b0d3307de9c936a91b797906674134fc9fbb5f1b450d5daa7ddc74c26d43aa8b351b4673f6bc32d89f460666475a28765ce722b42e682941b04635371a5234f6b168142c3366ce6bbd24a52a644619856c4303b0292227e9ae16ccaf33fc4f1a9fb537294b0261f7b1ca6ea14fa02bb12871add605345e4b18d446d5d33951d563b606c4329648b1c92a54f307ab7722294a95c1c42b3734586fd5044e39553c81458e1f85e4dec0275c9248ebc56f623cd08824386c16918a993e3454d1581c8a9c3a032b79d18e21f84c08e033bae46c098f6d55f83c28bef252aa43335dde63c96465125e46101accca40437a0810f616584d73cac1c54071a05c32f21bde9d2ad90e809f61862db966671eb2ace541290502d90185d819a7d0e566fa5e454e3cc7da8c93187a3af32dc831421c9b7ea984ad7c45483a119bca58ba8a1fc2201598884ce93255e359e8f989224548ab7f91657a56f83d68a21656d854432362a71d0727f45ca0138605885ac4314d2a1c8f61522e8aa91813fd6ab0ac438c04c182e25e774ac2c3c967306eda695d15505182a788191a46b3252a9917b56e23c92a7a51fc09f43221b806178272c11de8598f6a049d5ca2b342c08c4f13ca8d79ab7447bc0871ed525653b19b78bdb1fef17a3a14a2607dbcb7952a043012642a782d22706c08487bbcb95a6494dff891f75a86ce15c77c73c880e516a41139df7f0adf4d393cc564b68896d419948dcbb74740b5f85115c65ba0e5602449d10b20783abbd56b1b1b2cf5c73768563056eb76e8338515da7af1b62b29a05a1ed531de0b84b4c3033e80c3d50866dd3c0a17b9387e97963165720b587785912bdab15c946893024579923f16a46bbac862aa823d81619c616af92a0575019af5732c4a80686c1c4f81ac743611e45453e820878aa6498c28984b17b073d38945a73c8f8e033c038a5a25504a3324679490285be911109c35dec1c7ffa48d62c3acaddb348150b9a0de15dc40000000000000000000000000000000000000000000000000000000000000000";
        // test_encode_decode(encoded_key)
    }
}
