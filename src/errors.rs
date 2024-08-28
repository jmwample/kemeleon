
use core::array::TryFromSliceError;

#[derive(Debug)]
pub enum EncodeError {
    NotEncodable,
    DecodeError,
    MlKemError(TryFromSliceError),

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
