#[cfg(doc)]
use crate::{Ciphertext, EncapsulationKey};

use core::array::TryFromSliceError;

#[cfg(feature = "alloc")]
use alloc::format;

#[cfg(not(feature = "alloc"))]
type Internal = &'static str;

#[cfg(feature = "alloc")]
type Internal = alloc::string::String;

/// Errors encountered while using the Kemeleon encoding strategy.
#[derive(Debug)]
pub enum EncodeError {
    /// A function that always returns an encodable object failed to find
    /// an encodable option. This can only happen if the provided rng is an
    /// insufficient source of randomness.
    BadRngSource,
    /// One or more of the provided items failed to deserialized based on a formatting issue.
    ParseError(Internal),
    /// A [`ml_kem`] operation failed.
    MlKemError(TryFromSliceError),
    /// Failed while attempting to perform an ML-KEM encapsulation.
    EncapsulationError,
    /// Failed while attempting to decapsulate an ML-KEM ciphertext.
    DecapsulationError,
    /// The provided buffer is insufficient
    DstBufError(Internal),
}

impl core::error::Error for EncodeError {}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncodeError::ParseError(e) => write!(f, "failed to parse: {e}"),
            EncodeError::DecapsulationError => write!(f, "{DECAPSULATION_FAILURE}"),
            EncodeError::EncapsulationError => write!(f, "{MLKEM_ENCAP_ERR}"),
            EncodeError::BadRngSource => write!(f, "{BAD_RNG}"),
            EncodeError::MlKemError(e) => write!(f, "ml_kem error: {e}"),
            EncodeError::DstBufError(e) => write!(f, "dst buffer issue: {e}"),
        }
    }
}

impl From<TryFromSliceError> for EncodeError {
    fn from(e: TryFromSliceError) -> Self {
        EncodeError::MlKemError(e)
    }
}

impl EncodeError {
    pub(crate) fn bad_dst_array(__want: usize, __have: usize) -> Self {
        #[cfg(feature = "alloc")]
        {
            Self::DstBufError(format!("{BAD_DST_ARRAY}: {__have} < {__want}"))
        }

        #[cfg(not(feature = "alloc"))]
        {
            Self::DstBufError(BAD_DST_ARRAY)
        }
    }

    pub(crate) fn invalid_ctxt_len(__have: usize) -> Self {
        #[cfg(feature = "alloc")]
        {
            Self::ParseError(format!("{INVALID_CTXT_LENGTH}: {__have}"))
        }

        #[cfg(not(feature = "alloc"))]
        {
            Self::ParseError(INVALID_CTXT_LENGTH)
        }
    }

    pub(crate) fn invalid_ek_len(__have: usize) -> Self {
        #[cfg(feature = "alloc")]
        {
            Self::ParseError(format!("{INCORRECT_EK_LENGTH}: {__have}"))
        }

        #[cfg(not(feature = "alloc"))]
        {
            Self::ParseError(INCORRECT_EK_LENGTH)
        }
    }
}

const DECAPSULATION_FAILURE: &str = "failed to decapsulate";
const BAD_DST_ARRAY: &str = "invalid dst array size";
const INVALID_CTXT_LENGTH: &str = "incorrect ciphertext length";
const INCORRECT_EK_LENGTH: &str = "incorrect encapsulation key length";
const MLKEM_ENCAP_ERR: &str = "ML-KEM encapsulation error";
const BAD_RNG: &str = "Failed iterated operation: rng source insufficient";
