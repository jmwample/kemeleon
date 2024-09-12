#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`
#![allow(clippy::cast_possible_truncation)]
// do not warn about downcasting
#![deny(missing_docs)] // Require all public interfaces to be documented
#![allow(clippy::missing_errors_doc)] // adding Errors section is more than I want to do
#![doc = include_str!("../README.md")]

use core::fmt::Debug;
use core::ops::{Add, Mul};

#[cfg(feature = "alloc")]
extern crate alloc;

mod errors;
mod fips;
mod kemeleon;
mod mlkem;

pub use errors::*;
pub use kemeleon::*;

use hybrid_array::{
    sizes::{U1124, U1498, U749},
    typenum::{
        operator_aliases::{Prod, Sum},
        U10, U11, U12, U2, U256, U3, U32, U384, U4, U5,
    },
    Array, ArraySize,
};

#[derive(Copy, Clone, Default, PartialEq, PartialOrd)]
pub(crate) struct FieldElement(pub u16);

impl Debug for FieldElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

#[allow(non_camel_case_types)]
type ARR_LEN = U256;
#[allow(non_camel_case_types)]
type RHO_LEN = U32;

/// byte array
type ByteArray<N: ArraySize> = Array<u8, N>;
/// value array -- array of polynomial values
type ValueArray<P: EncodingSize> = Array<Array<u16, ARR_LEN>, P::K>;
type NttArray<P: EncodingSize> = ValueArray<P>;

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
#[allow(non_camel_case_types)]
pub trait EncodingSize {
    /// Number of bits used to represent field elements
    type USIZE: ArraySize;

    /// Number of field elements per equation.
    type K: ArraySize;

    /// The bit width of encoded integers in the `u` vector in a ciphertext
    type DU: ArraySize;
    /// The bit width of encoded integers in the `v` vector in a ciphertext
    type DV: ArraySize;

    /// Number of bytes for just `t_hat` values in a kemeleon encoded value
    ///
    /// Computed as: $\left\lceil (HIGH\\_ORDER\\_BIT -1)/8 \right\rceil$
    type T_HAT_LEN: ArraySize;

    /// Bitmask for the high order byte which will be less than a full byte of
    /// random bits when encoded.
    ///
    /// Computed as: $(HIGH\\_ORDER\\_BIT -1)\ mod\ 8$
    const MSB_BITMASK: u8;
    /// Bitmask for the high order byte which will be less than a full byte of
    /// random bits when encoded. Inversion of [`EncodingSize::MSB_BITMASK`].
    const MSB_BITMASK_INV: u8 = !Self::MSB_BITMASK;
}

///
#[allow(non_camel_case_types)]
pub trait KemeleonEncodingSize: EncodingSize {
    /// Size of the U value of the kemeleon encoded ciphertext. Matches `T_HAT_LEN`.
    type ENCODED_USIZE: ArraySize;
    #[allow(clippy::doc_markdown)]
    /// Size of the V value of the Kemeleon encoded ciphertext. N values of Dv Bit size.
    /// The number of bytes is computed as $ ENCODED_VSIZE = n * D_v / 8 \text{ --- for } n=256 $
    type ENCODED_VSIZE: ArraySize;
}

impl<T: EncodingSize> KemeleonEncodingSize for T
where
    <T as EncodingSize>::DV: Mul<U32>,
    <<T as EncodingSize>::DV as Mul<U32>>::Output: ArraySize,

    <T as EncodingSize>::T_HAT_LEN: Add<<<T as EncodingSize>::DV as Mul<U32>>::Output>,
    <<T as EncodingSize>::T_HAT_LEN as Add<<<T as EncodingSize>::DV as Mul<U32>>::Output>>::Output:
        ArraySize,
{
    type ENCODED_USIZE = T::T_HAT_LEN;
    type ENCODED_VSIZE = Prod<Self::DV, U32>;
}

/// Fips encoding size values
#[allow(non_camel_case_types)]
pub trait FipsEncodingSize: EncodingSize {
    /// Length of an NTT Vector encoded and compressed
    type FIPS_T_HAT_LEN: ArraySize;

    /// Size of the compressed U element of an ML-KEM ciphertext. $Du * K * 256 / 8$
    type FIPS_ENCODED_USIZE: ArraySize;
    /// Size of the compressed V element of an ML-KEM ciphertext. $Dv * 256 / 8$
    type FIPS_ENCODED_VSIZE: ArraySize;
}

impl<T: EncodingSize> FipsEncodingSize for T
where
    <T as EncodingSize>::K: Mul<U384>,
    <<T as EncodingSize>::K as Mul<U384>>::Output: ArraySize,

    <T as EncodingSize>::DV: Mul<U32>,
    <<T as EncodingSize>::DV as Mul<U32>>::Output: ArraySize,

    <T as EncodingSize>::K: Mul<<T as EncodingSize>::DU>,
    <<T as EncodingSize>::K as Mul<<T as EncodingSize>::DU>>::Output: ArraySize,

    <<T as EncodingSize>::K as Mul<<T as EncodingSize>::DU>>::Output: Mul<U32>,
    <<<T as EncodingSize>::K as Mul<<T as EncodingSize>::DU>>::Output as Mul<U32>>::Output:
        ArraySize,
{
    type FIPS_T_HAT_LEN = Prod<Self::K, U384>;
    type FIPS_ENCODED_USIZE = Prod<Prod<T::K, T::DU>, U32>;
    type FIPS_ENCODED_VSIZE = Prod<T::DV, U32>;
}

/// Lengths associated with the FIPS ML-KEM encoding of Encapsulation Keys and Ciphertexts.
#[allow(non_camel_case_types)]
pub trait FipsByteArraySize: FipsEncodingSize {
    /// Length of an encoded encapsulation key
    type ENCODED_EK_SIZE: ArraySize;

    /// Size of a ciphertext encoded and compressed.
    type ENCODED_CT_SIZE: ArraySize;
}

/// Lengths associated with the Kemeleon ML-KEM encoding of Encapsulation Keys and Ciphertexts.
#[allow(non_camel_case_types)]
pub trait KemeleonByteArraySize: KemeleonEncodingSize {
    /// Length of a Kemeleon encoded encapsulation key as bytes.
    ///
    /// Computed as: $T\\_HAT\\_LEN + RHO\\_LEN$
    type ENCODED_EK_SIZE: ArraySize;

    /// Size of a ciphertext encoded and compressed.
    type ENCODED_CT_SIZE: ArraySize;
}

impl<T: FipsEncodingSize> FipsByteArraySize for T
where
    <T as FipsEncodingSize>::FIPS_ENCODED_USIZE: Add<<T as FipsEncodingSize>::FIPS_ENCODED_VSIZE>,
    <<T as FipsEncodingSize>::FIPS_ENCODED_USIZE as Add<
        <T as FipsEncodingSize>::FIPS_ENCODED_VSIZE,
    >>::Output: ArraySize,

    <T as FipsEncodingSize>::FIPS_T_HAT_LEN: Add<RHO_LEN>,
    <<T as FipsEncodingSize>::FIPS_T_HAT_LEN as Add<RHO_LEN>>::Output: ArraySize,
{
    type ENCODED_EK_SIZE = Sum<T::FIPS_T_HAT_LEN, RHO_LEN>;
    type ENCODED_CT_SIZE = Sum<T::FIPS_ENCODED_USIZE, T::FIPS_ENCODED_VSIZE>;
}

impl<T: KemeleonEncodingSize> KemeleonByteArraySize for T
where
    <T as KemeleonEncodingSize>::ENCODED_USIZE: Add<<T as KemeleonEncodingSize>::ENCODED_VSIZE>,
    <<T as KemeleonEncodingSize>::ENCODED_USIZE as Add<
        <T as KemeleonEncodingSize>::ENCODED_VSIZE,
    >>::Output: ArraySize,

    <T as EncodingSize>::T_HAT_LEN: Add<RHO_LEN>,
    <<T as EncodingSize>::T_HAT_LEN as Add<RHO_LEN>>::Output: ArraySize,
{
    type ENCODED_EK_SIZE = Sum<T::T_HAT_LEN, RHO_LEN>;
    type ENCODED_CT_SIZE = Sum<T::ENCODED_USIZE, T::ENCODED_VSIZE>;
}

impl EncodingSize for ml_kem::MlKem512 {
    type USIZE = U12;
    type K = U2;
    type DU = U10;
    type DV = U4;

    type T_HAT_LEN = U749;
    const MSB_BITMASK: u8 = 0b1100_0000;
}

impl EncodingSize for ml_kem::MlKem768 {
    type USIZE = U12;
    type K = U3;
    type DU = U10;
    type DV = U4;

    type T_HAT_LEN = U1124;
    const MSB_BITMASK: u8 = 0b1111_1100;
}

impl EncodingSize for ml_kem::MlKem1024 {
    type USIZE = U12;
    type K = U4;
    type DU = U11;
    type DV = U5;

    type T_HAT_LEN = U1498;
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
{ //_1011_1001_0100
    type USIZE = P::USIZE;
    type K = P::K;
    type DU = P::DU;
    type DV = P::DV;

    type T_HAT_LEN = P::T_HAT_LEN;
    const MSB_BITMASK: u8 = P::MSB_BITMASK;
}
