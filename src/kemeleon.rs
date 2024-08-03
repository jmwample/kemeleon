use crate::{fips, Barr, EncodingSize, FieldElement, Transcode, ValueArray, ARR_LEN};

use core::marker::PhantomData;
use std::io::{Error as IoError, Write};

use ml_kem::Ciphertext;
use ml_kem::{Encoded, EncodedSizeUser, KemCore};
use num_bigint::BigUint;

pub use crate::mlkem::EncodedCiphertext;
pub use crate::mlkem::KEncapsulationKey as EncapsulationKey;

pub trait Encode {
    /// EncapsulationKey
    type EK;
    /// Encoded type (i.e Encoded Encapsulation Key, or Encoded Ciphertext)
    type ET;

    /// Error Type returned on failed decode
    type Error;

    fn as_bytes(&self) -> Self::ET;

    fn try_from_bytes(c: impl AsRef<[u8]>) -> Result<Self::EK, Self::Error>;
}

// ========================================================================== //
// Encapsulation Key
// ========================================================================== //

pub trait KemeleonEk: Encode {
    fn satisfies_sampling(&self) -> bool;
}

impl<P> Encode for EncapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); <P as EncodingSize>::ENCODED_SIZE ]:,
{
    type EK = Self;
    type ET = Barr<{ <P as EncodingSize>::ENCODED_SIZE }>;
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

        // let mut dst = <Self as Encode>::ET::default();
        let mut dst: Barr::<{<P as EncodingSize>::ENCODED_SIZE}> = [0u8; <P as EncodingSize>::ENCODED_SIZE];
        self.encode_priv(&mut dst);

        todo!("key as bytes implementation incomplete")
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
        #[allow(deprecated)] // I don't understand what they want for the TryFrom format.
        let ek_bytes = Encoded::<<P as KemCore>::EncapsulationKey>::from_slice(c.as_ref());
        let key = <P as KemCore>::EncapsulationKey::from_bytes(ek_bytes);

        Ok(EncapsulationKey { key, byte: 0x00 })
    }
}

impl<P> KemeleonEk for EncapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); <P as EncodingSize>::ENCODED_SIZE ]:,
{
    fn satisfies_sampling(&self) -> bool {
        // TODO: Example of current incongruity -> encode_priv takes byte array as ValueArray
        // but we have an EncapsulationKey. So what to encode?
        // let mut dst = <Self as Encode>::ET::default();
        let mut dst: Barr::<{<P as EncodingSize>::ENCODED_SIZE}> = [0u8; <P as EncodingSize>::ENCODED_SIZE];
        self.encode_priv(&mut dst)
    }
}

impl<P> EncapsulationKey<P>
where 
    P: KemCore + EncodingSize,
{

    fn decode(c: impl AsRef<[u8]>) -> Result<Self, IoError>
    where
        P: KemCore + EncodingSize,
    {
        // if c.as_ref().len() < ValueArray::LENGTH * 2 {
        //     return Err(Error::other("incorrect length"));
        // }

        let base = BigUint::from(FieldElement::Q);
        let r = BigUint::from_bytes_le(c.as_ref());

        let mut out = [FieldElement(0u16); ARR_LEN];
        let mut scratch: BigUint;
        for i in 0..ARR_LEN {
            scratch = BigUint::ZERO;
            let pk_i = ((&r - &scratch) / base.pow(i as u32)) % FieldElement::Q;
            scratch += &pk_i;
            out[i] = FieldElement(pk_i.to_u32_digits()[0] as u16);
        }

        let bytes = fips::byte_encode::<P>(&out);

        #[allow(deprecated)] // I don't understand what they want for the TryFrom format.
        let ek_bytes = Encoded::<<P as KemCore>::EncapsulationKey>::from_slice(&bytes);
        let key = <P as KemCore>::EncapsulationKey::from_bytes(ek_bytes);
        Ok(EncapsulationKey::from_fips(key))
    }

    fn encode_priv(&self, mut dst: impl AsMut<[u8]>) -> bool {
        let k = dst.as_mut();
        let mut out = BigUint::ZERO;
        let base = BigUint::from(FieldElement::Q);

        let vals_fips_encoded = self.key.as_bytes().to_vec();
        // can never fail since the format is guaranteed correct by the ml_kem library
        let vals = fips::byte_decode::<P>(vals_fips_encoded).unwrap();

        for (i, x) in vals.iter().enumerate() {
            let bigx = BigUint::from(x.0);
            out += bigx * base.pow(i as u32);
        }

        k[<P as EncodingSize>::ENCODED_SIZE-1] &= self.byte & <P as EncodingSize>::MSB_BITMASK;

        // (out.to_bytes_le(), !out.bit(2996))
        !out.bit(2996)
    }
}

// ========================================================================== //
// CipherText
// ========================================================================== //

impl<P> Encode for EncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
{
    /// Encapsulation Key
    type EK = Self;

    /// Encoded Cuphertext Type
    type ET = <P as EncodingSize>::EncodedCiphertextType;

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

// fn encode_ctxt_priv<P: EncodingSize>(_p: &ValueArray) -> Vec<u8> {
//     vec![]
// }
// 
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
// 
// ========================================================================== //
// Tests
// ========================================================================== //

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::Kemx;
    use core::fmt::Debug;

    fn encode_decode_trial<P>()
    where
        P: KemCore + EncodingSize,
        <P as KemCore>::EncapsulationKey: Debug,
        [(); <P as EncodingSize>::ENCODED_SIZE ]:,
    {
        let mut rng = rand::thread_rng();
        // This is the repeated trial generate from random and any key created
        // is guaranteed to be representable, otherwise it would have panicked
        let (_dk, ek) = Kemx::<P>::generate(&mut rng).expect("failed generation");

        // let mut dst: <P as EncodingSize>::EncodedKeyType;
        let mut dst: Barr::<{<P as EncodingSize>::ENCODED_SIZE}> = [0u8; <P as EncodingSize>::ENCODED_SIZE];
        _ = ek.encode_priv(&mut dst);

        // Encapsulation Key decoded from bytes sent over the wire.
        let recv_ek = EncapsulationKey::<P>::decode(dst).expect("failed decode");

        assert_eq!(ek.key, recv_ek.key);
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
}
