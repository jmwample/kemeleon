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
use core::ops::{Add, Div, Mul, Rem, Sub};

#[cfg(feature = "alloc")]
extern crate alloc;

mod errors;
mod fips;
mod kemeleon;
mod mlkem;

pub use errors::*;
pub use kemeleon::*;

use hybrid_array::{
    typenum::{
        operator_aliases::{Gcf, Prod, Quot, Sum},
        type_operators::Gcd,
        Const, ToUInt, U0, U12, U16, U2, U256, U3, U32, U384, U4, U6, U64, U8,
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

type ARR_LEN = U256;
type RHO_LEN = U32;

/// byte array
type Barr8<const N: usize> = [u8; N];
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
pub trait EncodingSize {
    /// Number of bits used to represent field elements
    type USIZE;

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

pub trait KemeleonEncodingSize: EncodingSize
where
    <Self::ENCODED_USIZE as Add<Self::ENCODED_VSIZE>>::Output: ArraySize
{
    /// Size of the Kemeleon encoded string as bytes.
    ///
    /// Computed as: $T\\_HAT\\_LEN + RHO\\_LEN$
    type ENCODED_SIZE: ArraySize;

    /// Size of the U value of the kemeleon encoded ciphertext. Matches `T_HAT_LEN`.
    type ENCODED_USIZE: ArraySize + Add<Self::ENCODED_VSIZE>;
    #[allow(clippy::doc_markdown)]
    /// Size of the V value of the Kemeleon encoded ciphertext. N values of Dv Bit size.
    /// The number of bytes is computed as $ ENCODED_VSIZE = n * D_v / 8 \text{ --- for } n=256 $
    type ENCODED_VSIZE: ArraySize;
    // /// Size of the combined kemeleon encoded ciphertext.
    // type ENCODED_CT_SIZE: ArraySize;
}

impl<T: EncodingSize> KemeleonEncodingSize for T
where
    <T as EncodingSize>::T_HAT_LEN: Add<RHO_LEN>,
    <<T as EncodingSize>::T_HAT_LEN as Add<RHO_LEN>>::Output: ArraySize,

    <T as EncodingSize>::DV: Mul<U32>,
    <<T as EncodingSize>::DV as Mul<U32>>::Output: ArraySize,
{
    /// Size of the Kemeleon encoded string as bytes.
    ///
    /// Computed as: $T\\_HAT\\_LEN + RHO\\_LEN$
    type ENCODED_SIZE = Sum<Self::T_HAT_LEN, RHO_LEN>;

    /// Size of the U value of the kemeleon encoded ciphertext. Matches `T_HAT_LEN`.
    type ENCODED_USIZE = T::T_HAT_LEN;

    #[allow(clippy::doc_markdown)]
    /// Size of the V value of the Kemeleon encoded ciphertext. N values of Dv Bit size.
    /// The number of bytes is computed as $ ENCODED_VSIZE = n * D_v / 8 \text{ --- for } n=256 $
    type ENCODED_VSIZE = Prod<Self::DV, U32>;
    // /// Size of the combined kemeleon encoded ciphertext.
    // type ENCODED_CT_SIZE = Sum<Self::ENCODED_USIZE, Self::ENCODED_VSIZE>;
}


/// Fips encoding size values
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

{
    /// Length of an NTT Vector encoded and compressed K * 12 * (256/8) = K * 384
    type FIPS_T_HAT_LEN = Prod<Self::K, U384>;

    /// Size of the compressed U element of an ML-KEM ciphertext. $Du * K * 256 / 8$
    type FIPS_ENCODED_USIZE = Prod<Prod<T::K, T::DU>, U32>;
    /// Size of the compressed V element of an ML-KEM ciphertext. $Dv * 256 / 8$
    type FIPS_ENCODED_VSIZE = Prod<T::DV, U32>;
}

trait ByteArraySize {
    /// Length of an encoded encapsulation key
    type ENCODED_EK_SIZE: ArraySize;

    /// Size of a ciphertext encoded and compressed.
    type ENCODED_CT_SIZE: ArraySize;
}

impl<T: FipsEncodingSize> ByteArraySize for T
where
    <T as FipsEncodingSize>::FIPS_ENCODED_USIZE: Add<<T as FipsEncodingSize>::FIPS_ENCODED_VSIZE>,
    <<T as FipsEncodingSize>::FIPS_ENCODED_USIZE as Add<<T as FipsEncodingSize>::FIPS_ENCODED_VSIZE>>::Output: ArraySize,

    <T as FipsEncodingSize>::FIPS_T_HAT_LEN: Add<RHO_LEN>,
    <<T as FipsEncodingSize>::FIPS_T_HAT_LEN as Add<RHO_LEN>>::Output: ArraySize,
{
    type ENCODED_EK_SIZE = Sum<T::FIPS_T_HAT_LEN, RHO_LEN>;
    
    type ENCODED_CT_SIZE = Sum<T::FIPS_ENCODED_USIZE, T::FIPS_ENCODED_VSIZE>;
}

impl<T: KemeleonEncodingSize> ByteArraySize for T
where
    <T as KemeleonEncodingSize>::ENCODED_USIZE: Add<<T as KemeleonEncodingSize>::ENCODED_VSIZE>,
    <<T as KemeleonEncodingSize>::ENCODED_USIZE as Add<<T as KemeleonEncodingSize>::ENCODED_VSIZE>>::Output: ArraySize,

    <T as KemeleonEncodingSize>::T_HAT_LEN: Add<RHO_LEN>,
    <<T as KemeleonEncodingSize>::T_HAT_LEN as Add<RHO_LEN>>::Output: ArraySize,
{
    type ENCODED_EK_SIZE = Sum<T::T_HAT_LEN, RHO_LEN>;
    
    type ENCODED_CT_SIZE = Sum<T::ENCODED_USIZE, T::ENCODED_VSIZE>;
}


use hybrid_array::{typenum::{U5, U10, U11, }, sizes::{U749, U1124, U1498}};

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
{
    type USIZE = P::USIZE;
    type K = P::K;
    type DU = P::DU;
    type DV = P::DV;

    type T_HAT_LEN = P::T_HAT_LEN;
    const MSB_BITMASK: u8 = P::MSB_BITMASK;
}
