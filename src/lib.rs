// #![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`
#![allow(clippy::cast_possible_truncation)]
// do not warn about downcasting
#![deny(missing_docs)] // Require all public interfaces to be documented
#![allow(clippy::missing_errors_doc)] // adding Errors section is more than I want to do
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![doc = include_str!("../README.md")]

use core::fmt::Debug;

mod errors;
mod fips;
mod kemeleon;
mod mlkem;

pub use errors::*;
pub use kemeleon::*;

#[derive(Copy, Clone, Default, PartialEq, PartialOrd)]
pub(crate) struct FieldElement(pub u16);

impl Debug for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<u16> for FieldElement {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for FieldElement {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for FieldElement {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

const ARR_LEN: usize = 256;
const RHO_LEN: usize = 32;

/// byte array
type Barr8<const N: usize> = [u8; N];
/// value array -- array of polynomial values
type ValueArray<const N: usize, const K: usize> = [[u16; N]; K];
type NttArray<const K: usize> = ValueArray<ARR_LEN, K>;

#[allow(dead_code)]
impl FieldElement {
    pub const Q: u16 = 3329;
    pub const Q32: u32 = Self::Q as u32;
    pub const Q64: u64 = Self::Q as u64;
}

/// Convert between Kemeleon and [`ml_kem`](https://docs.rs/ml-kem/latest/ml_kem/) values.
pub trait Transcode {
    /// Fips equivalent type
    type Fips;

    /// convert to a reference to the fips equivalent object.
    fn as_fips(&self) -> &Self::Fips;

    /// consume and convert to the fips equivalent object.
    fn to_fips(self) -> Self::Fips;

    /// create a new object from the fips equivalent.
    fn from_fips(t: Self::Fips) -> Self;
}

// ========================================================================== //
// Encoding Sizes and Generics
// ========================================================================== //

/// Core sizes used for encoding ML KEM Encapsulation Keys and Ciphertexts.
///
/// Many of the Arrray Sizes defined here are based off of the length of
/// the result of a Kemeleon `VectorEncode()` function. For a vector of
/// `K` Field elements with $n=256$ values per field element this is found
/// by:
///
/// $$
/// HIGH\\\_ORDER\\\_BIT = \left\lceil log_{2}(q^{n\cdot k}+1) - 1 \right\rceil
/// $$
///
pub trait EncodingSize {
    /// Number of bits used to represent field elements
    const USIZE: usize = 12_usize;

    /// Number of field elements per equation.
    const K: usize;

    /// Bitmask for the high order byte which will be less than a full byte of
    /// random bits when encoded.
    ///
    /// Computed as: $(HIGH\\_ORDER\\_BIT -1)\ mod\ 8$
    const MSB_BITMASK: u8;
    /// Bitmask for the high order byte which will be less than a full byte of
    /// random bits when encoded. Inversion of [`EncodingSize::MSB_BITMASK`].
    const MSB_BITMASK_INV: u8 = !Self::MSB_BITMASK;

    /// The bit width of encoded integers in the `u` vector in a ciphertext
    const DU: usize;
    /// The bit width of encoded integers in the `v` vector in a ciphertext
    const DV: usize;

    /// Number of bytes for just `t_hat` values in a kemeleon encoded value
    ///
    /// Computed as: $\left\lceil (HIGH\\_ORDER\\_BIT -1)/8 \right\rceil$
    const T_HAT_LEN: usize;
    /// Size of the Kemeleon encoded string as bytes.
    ///
    /// Computed as: $T\\_HAT\\_LEN + RHO\\_LEN$
    const ENCODED_SIZE: usize = Self::T_HAT_LEN + RHO_LEN;

    /// Size of the U value of the kemeleon encoded ciphertext. Matches `T_HAT_LEN`.
    const ENCODED_USIZE: usize = Self::T_HAT_LEN;
    #[allow(clippy::doc_markdown)]
    /// Size of the V value of the Kemeleon encoded ciphertext. N values of Dv Bit size.
    /// The number of bytes is computed as $ ENCODED_VSIZE = n * D_v / 8 \text{ --- for } n=256 $
    const ENCODED_VSIZE: usize = 32 * Self::DV;
    /// Size of the combined kemeleon encoded ciphertext.
    const ENCODED_CT_SIZE: usize = Self::ENCODED_USIZE + Self::ENCODED_VSIZE;
}

/// Fips encoding size values
pub trait FipsEncodingSize: EncodingSize {
    /// Length of an NTT Vector encoded and compressed
    const FIPS_T_HAT_LEN: usize = Self::K * 12 * 32;
    /// Length of an encoded FIPS encapsulation key
    const FIPS_ENCODED_SIZE: usize = Self::FIPS_T_HAT_LEN + RHO_LEN;

    /// Size of the compressed U element of an ML-KEM ciphertext.
    const FIPS_ENCODED_USIZE: usize = 32 * Self::DU * Self::K;
    /// Size of the compressed V element of an ML-KEM ciphertext.
    const FIPS_ENCODED_VSIZE: usize = 32 * Self::DV;
    /// Size of a ciphertext encoded and compressed using FIPS standard.
    const FIPS_ENCODED_CT_SIZE: usize = Self::FIPS_ENCODED_USIZE + Self::FIPS_ENCODED_VSIZE;
}
impl<T: EncodingSize> FipsEncodingSize for T {}

impl EncodingSize for ml_kem::MlKem512 {
    const K: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    const T_HAT_LEN: usize = 749;
    const MSB_BITMASK: u8 = 0b1100_0000;
}

impl EncodingSize for ml_kem::MlKem768 {
    const K: usize = 3;
    const DU: usize = 10;
    const DV: usize = 4;

    const T_HAT_LEN: usize = 1124;
    const MSB_BITMASK: u8 = 0b1111_1100;
}

impl EncodingSize for ml_kem::MlKem1024 {
    const K: usize = 4;
    const DU: usize = 11;
    const DV: usize = 5;

    const T_HAT_LEN: usize = 1498;
    const MSB_BITMASK: u8 = 0b1110_0000;
}

// ========================================================================== //
// Public Interface objects
// ========================================================================== //

/// ML-KEM with the parameter set for security category 1, corresponding to key search on a block cipher with a 128-bit key.
pub type MlKem512 = mlkem::Kemx<ml_kem::MlKem512>;

/// ML-KEM with the parameter set for security category 3, corresponding to key search on a block cipher with a 192-bit key.
pub type MlKem768 = mlkem::Kemx<ml_kem::MlKem768>;

/// ML-KEM with the parameter set for security category 5, corresponding to key search on a block cipher with a 256-bit key.
pub type MlKem1024 = mlkem::Kemx<ml_kem::MlKem1024>;

impl<P> EncodingSize for mlkem::Kemx<P>
where
    P: ml_kem::KemCore + EncodingSize,
{
    const K: usize = P::K;
    const DU: usize = P::DU;
    const DV: usize = P::DV;

    const T_HAT_LEN: usize = P::T_HAT_LEN;
    const MSB_BITMASK: u8 = P::MSB_BITMASK;
}
