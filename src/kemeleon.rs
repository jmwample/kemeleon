pub use crate::mlkem::KEncapsulationKey as EncapsulationKey;
use crate::{EncodingSize, FipsEncodingSize, FieldElement};

use core::cmp::min;
use std::io::Error as IoError;

use ml_kem::KemCore;
use num_bigint::BigUint;

mod ciphertext;
mod encapsulation_key;

pub trait Encode
where
    Self: Sized,
{
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
    fn try_from_bytes(c: impl AsRef<[u8]>) -> Result<Self, Self::Error>;
}

pub trait Encodable: Encode {
    fn satisfies_sampling(&self) -> bool;
}

pub fn vector_encode<P>(p: impl AsRef<[u16]>, mut c: impl AsMut<[u8]>) -> Result<bool, IoError>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
{
    let dst = c.as_mut();
    if dst.len() < P::T_HAT_LEN {
        return Err(IoError::other(format!(
            "invalid dst array size. {} < {}",
            P::T_HAT_LEN,
            dst.len()
        )));
    }

    let mut out = BigUint::ZERO;
    let base = BigUint::from(FieldElement::Q);

    // encode values into an obfuscated object
    let mut offset = BigUint::from(1u64);
    for val in p.as_ref() {
        let bigx = BigUint::from(*val);
        out += bigx * &offset;
        offset *= &base;
    }

    // avoid out-of-bounds access if high order byte is 0x00
    let b = out.to_bytes_le();
    let l = min(P::T_HAT_LEN, b.len());
    dst[..l].copy_from_slice(&b[..l]);

    // Sample failure if High order bit is set.
    Ok(dst[P::T_HAT_LEN - 1] & P::MSB_BITMASK == 0)
}

pub fn vector_decode<P>(c: impl AsRef<[u8]>, mut p: impl AsMut<[u16]>) -> Result<(), IoError>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{
    if c.as_ref().len() < <P as EncodingSize>::T_HAT_LEN {
        return Err(IoError::other("incorrect ciphertext length"));
    }

    let base = BigUint::from(FieldElement::Q);
    let mut r = BigUint::from_bytes_le(c.as_ref());

    // extract the values
    for val in p.as_mut().iter_mut() {
        let pk_i = &r % &base;
        r = (&r - &pk_i) / &base;

        let k = pk_i.to_u32_digits();
        *val = if k.is_empty() { 0u16 } else { k[0] as u16 };
    }
    Ok(())
}
