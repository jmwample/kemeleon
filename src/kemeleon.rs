/// An ML-KEM ciphertext
pub use crate::mlkem::KCiphertext as Ciphertext;
/// A `DecapsulationKey` provides the ability to generate a new key pair, and decapsulate
/// an encapsulated shared key.
pub use crate::mlkem::KDecapsulationKey as DecapsulationKey;
/// An `EncapsulationKey` provides the ability to encapsulate a shared key so that it can
/// only be decapsulated by the holder of the corresponding decapsulation key.
pub use crate::mlkem::KEncapsulationKey as EncapsulationKey;
use crate::{EncodeError, EncodingSize, FieldElement, FipsEncodingSize};

use alloc::format;
use core::cmp::min;

use ml_kem::KemCore;
use num_bigint::BigUint;

mod ciphertext;
mod encapsulation_key;

// TODO: is this used / useful?
/// Generic trait for Encodable objects
pub trait Encode
where
    Self: Sized,
{
    /// Encoded type (i.e Encoded Encapsulation Key, or Encoded Ciphertext)
    type ET;

    /// Error Type returned on failed decode
    type Error;

    /// Convert object to the serialized byte representation
    fn as_bytes(&self) -> Self::ET;

    /// Try to parse from bytes. Throws an [`EncodeError::ParseError`] if the
    /// provided value cannot be parsed for any reason.
    fn try_from_bytes(c: impl AsRef<[u8]>) -> Result<Self, Self::Error>;
}

/// Trait indicating that an object could fail sampling, and testing whether that
/// object passes or fails that sampling.
pub trait Encodable: Encode {
    /// Checks if the objcet is encodable given the Kemeleon sampling criteria
    fn is_encodable(&self) -> bool;
}

pub(crate) fn vector_encode<P>(
    p: impl AsRef<[u16]>,
    mut c: impl AsMut<[u8]>,
) -> Result<bool, EncodeError>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
{
    let dst = c.as_mut();
    if dst.len() < P::T_HAT_LEN {
        return Err(EncodeError::EncodeError(format!(
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

pub(crate) fn vector_decode<P>(
    c: impl AsRef<[u8]>,
    mut p: impl AsMut<[u16]>,
) -> Result<(), EncodeError>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{
    if c.as_ref().len() < <P as EncodingSize>::T_HAT_LEN {
        return Err(EncodeError::DecodeError(format!(
            "incorrect ciphertext length {}",
            c.as_ref().len()
        )));
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
