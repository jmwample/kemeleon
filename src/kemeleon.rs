use crate::{
    mlkem::EncodedCiphertext, mlkem::KEncapsulationKey as EncapsulationKey, EncodingSize,
    FieldElement, ValueArray, ARR_LEN,
};

use core::marker::PhantomData;
use std::io::Error as IoError;

use ml_kem::{Encoded, EncodedSizeUser, KemCore};
use num_bigint::BigUint;

pub trait Encode {
    type EK;
    type Error;

    fn as_bytes(&self) -> Vec<u8>;

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
{
    type EK = Self;
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
    fn as_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
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
{
    fn satisfies_sampling(&self) -> bool {
        // TODO: Example of current incongruity -> encode_priv takes byte array as ValueArray
        // but we have an EncapsulationKey. So what to encode?
        encode_priv::<P>(self.key).1
    }
}

fn decode<P: EncodingSize>(c: impl AsRef<[u8]>) -> Result<ValueArray, IoError> {
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

    Ok(out)
}

fn encode_priv<P: EncodingSize>(p: &ValueArray) -> (Vec<u8>, bool) {
    let mut out = BigUint::ZERO;
    let base = BigUint::from(FieldElement::Q);

    for (i, x) in p.iter().enumerate() {
        let bigx = BigUint::from(x.0);
        out += bigx * base.pow(i as u32);
    }

    (out.to_bytes_le(), !out.bit(2996))
}

// ========================================================================== //
// CipherText
// ========================================================================== //

impl<P> Encode for EncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
{
    type EK = Self;
    type Error = IoError;

    fn as_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
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

// ========================================================================== //
// Tests
// ========================================================================== //

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlKem1024, MlKem512, MlKem768};

    fn encode_decode_trial<P: KemCore + EncodingSize>() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = P::generate(&mut rng);

        // TODO: Example of current incongruity -> encode_priv takes byte array as ValueArray
        // but we have an EncapsulationKey. So what to encode?
        let c = encode_priv(&ek).0;

        let p = decode(c).expect("failed decode");

        assert_eq!(ek, p)
    }

    #[test]
    fn encode_decode() {
        encode_decode_trial::<MlKem512>();
        encode_decode_trial::<MlKem768>();
        encode_decode_trial::<MlKem1024>();
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
