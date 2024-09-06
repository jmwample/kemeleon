#[cfg(doc)]
use crate::{Ciphertext, EncapsulationKey};

use alloc::string::String;
use core::array::TryFromSliceError;

/// Errors encountered while using the Kemeleon encoding strategy.
#[derive(Debug)]
pub enum EncodeError {
    /// A function that always returns an encodable object failed to find
    /// an encodable option. This can only happen if the provided rng is an
    /// insufficient source of randomness.
    BadRngSource,
    /// One or more of the provided items failed to deserialized based on a formatting issue.
    ParseError(String),
    /// Failure while encoding an [`EncapsulationKey`] or [`Ciphertext`] using a kemeleon
    /// algorithm.
    EncodeError(String),
    /// Failure while Decoding an [`EncapsulationKey`] or [`Ciphertext`] using a kemeleon
    /// algorithm.
    DecodeError(String),
    /// A [`ml_kem`] operation failed.
    MlKemError(TryFromSliceError),
    /// Failed while attempting to perform an ML-KEM encapsulation.
    EncapsulationError(String),
    /// Failed while attempting to decapsulate an ML-KEM ciphertext.
    DecapsulationError(String),
}

impl core::error::Error for EncodeError {}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // TODO: make error printing better
            EncodeError::ParseError(e) => write!(f, "failed to parse: {e}"),
            _ => write!(f, "error occured"),
        }
    }
}

impl From<TryFromSliceError> for EncodeError {
    fn from(e: TryFromSliceError) -> Self {
        EncodeError::MlKemError(e)
    }
}
