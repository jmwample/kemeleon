use crate::{EncodingSize, FieldElement, ValueArray, ARR_LEN};

use core::marker::PhantomData;
use std::io::{Error as IoError, Write};

use ml_kem::Ciphertext;
use ml_kem::{Encoded, EncodedSizeUser, KemCore};
use num_bigint::BigUint;

pub use crate::mlkem::EncodedCiphertext;
pub use crate::mlkem::KEncapsulationKey as EncapsulationKey;

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

fn encode_ctxt_priv<P: EncodingSize>(p: &ValueArray) -> Vec<u8> {
    vec![]
}

fn decode_ctxt_priv<P>(
    c: impl AsRef<[u8]>,
    dst: impl Write,
) -> Result<ml_kem::Ciphertext<P>, IoError>
where
    P: KemCore + EncodingSize,
{
    let idx_r1 = P::DV * ARR_LEN;
    let r1 = &c.as_ref()[..c.as_ref().len() - idx_r1];
    let r2 = &c.as_ref()[idx_r1..];

    let u = decode::<P>(r2).map_err(|e| IoError::other("error occured while decoding"))?;
    let c1 = compress(Into::<[u16; ARR_LEN]>::into(u), P::DU);
    let ctxt: Vec<u8> = c1.iter().zip(r2).map(|(v1, v2)| v1 | v2).collect();

    #[allow(deprecated)]
    Ok(*Ciphertext::<P>::from_slice(&ctxt))
}

const QFD: f64 = 4096.0 / 3329.0;
const DFQ: f64 = 3329.0 / 4096.0;

/// x −→ ⌈((2^d)/q)· x⌋
fn compress(u: impl AsRef<[u16]>, du: usize) -> Vec<u16> {
    u.as_ref().iter().map(|v| (*v as f64 * QFD + 0.5) as u16).collect()
}

/// y −→ ⌈(q/(2^d))· y⌋

fn decompress(c: impl AsRef<[u16]>, du: usize) -> Vec<u16> {
    c.as_ref().iter().map(|v| (*v as f64 * DFQ + 0.5) as u16).collect()
}

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
    {
        let mut rng = rand::thread_rng();
        let (dk, ek) = Kemx::<P>::generate(&mut rng).expect("failed generation");

        // TODO: Example of current incongruity -> encode_priv takes byte array as ValueArray
        // but we have an EncapsulationKey. So what to encode?
        let c = encode_priv(&ek).0;

        let plaintext = decode(c).expect("failed decode");

        assert_eq!(ek, plaintext)
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
