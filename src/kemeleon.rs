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

        let mut rho = [0u8; RHO_LEN];
        rho[..].clone_from_slice(&c.as_ref()[P::ENCODED_SIZE - RHO_LEN..]);

        let base = BigUint::from(FieldElement::Q);
        let r = BigUint::from_bytes_le(&c.as_ref()[..P::ENCODED_SIZE - RHO_LEN]);

        let mut vals = [[0u16; ARR_LEN]; P::K];
        let mut scratch: BigUint;
        for (i, val) in vals.as_flattened_mut().iter_mut().enumerate() {
            scratch = BigUint::ZERO;
            let pk_i = ((&r - &scratch) / base.pow(i as u32)) % FieldElement::Q;
            scratch += &pk_i;
            let k = pk_i.to_u32_digits();
            *val = if k.is_empty() { 0u16 } else { k[0] as u16 };
        }

        // TODO: get the random mask byte from the high order bits

        let bytes = fips::byte_encode::<P>(&rho, &vals);

        let ek_bytes =
            Encoded::<<P as KemCore>::EncapsulationKey>::try_from(&bytes[..]).map_err(|e| {
                IoError::other(format!("failed to convert to hybrid_array::Array: {e}"))
            })?;
        let key = <P as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
        Ok(EncapsulationKey::from_fips(key))
    }

    fn encode_priv(&self, mut dst: impl AsMut<[u8]>) -> Result<bool, IoError> {
        // TODO: do we need to enforce dst length?
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

        for (i, x) in vals.iter().enumerate() {
            for (j, val) in x.iter().enumerate() {
                let bigx = BigUint::from(*val);
                out += bigx * base.pow((i * x.len() + j) as u32);
            }
        }

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

        assert_eq!(hex::encode(&orig), hex::encode(recv_ek.as_bytes()));
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
