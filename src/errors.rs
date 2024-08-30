use core::array::TryFromSliceError;

#[derive(Debug)]
pub enum EncodeError {
    /// Indicates that an ['EncapsulationKey'] or ['Ciphertext'] failed sampling check.
    NotEncodable,
    /// One or more of the provided items failed to deserialized based on a formatting issue.
    ParseError(String),
    /// Failure while encoding an ['EncapsulationKey'] or ['Ciphertext'] using a kemeleon
    /// algorithm.
    EncodeError(String),
    /// Failure while Decoding an ['EncapsulationKey'] or ['Ciphertext'] using a kemeleon
    /// algorithm.
    DecodeError(String),
    /// A ['ml_kem'] operation failed.
    MlKemError(TryFromSliceError),
    /// Failed while attempting to perform an ML-KEM encapsulation.
    EncapsulationError(String),
    /// Failed while attempting to decapsulate an ML_KEM ciphertext.
    DecapsulationError(String),
}

impl core::error::Error for EncodeError {}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // TODO: make error printing better
            _ => write!(f, "error occured"),
        }
    }
}
