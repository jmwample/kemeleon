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
use ml_kem::kem::Params as KemParams;

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
type ByteArray<N> = Array<u8, N>;
/// value array -- array of polynomial values
type NttArray<P> = Array<Array<u16, ARR_LEN>, <P as EncodingSize>::K>;
struct Ntt;

impl Ntt {
    fn zero<P: EncodingSize>() -> NttArray<P> {
        Array::<Array<u16, ARR_LEN>, P::K>::from_fn(|_| Array::<u16, ARR_LEN>::from_fn(|_| 0u16))
    }
}

struct ByteArr;

impl ByteArr {
    fn zero<N: ArraySize>() -> ByteArray<N> {
        ByteArray::<N>::from_fn(|_| 0u8)
    }
}

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
#[rustfmt::skip]
pub trait EncodingSize {
    /// Number of bits used to represent field elements
    type USIZE: ArraySize;

    /// Number of field elements per equation.
    type K: ArraySize
        // allows:  (K * 384) + RHO_LEN
        + Mul<U384, Output: ArraySize + Add<RHO_LEN, Output: ArraySize>>
        // allows: K * Du
        + Mul< Self::DU, Output: ArraySize
            // Allows: K * Du * 32
            + Mul< U32, Output: ArraySize
                // Allows: (K * Du * 32) + RHO_LEN
                + Add<RHO_LEN, Output: ArraySize>
                // Allows: (K * Du * 32) + (Dv * 32)
                + Add<<Self::DV as Mul<U32>>::Output, Output: ArraySize>,
            >,
        >;

    /// The bit width of encoded integers in the `u` vector in a ciphertext
    type DU: ArraySize;
    /// The bit width of encoded integers in the `v` vector in a ciphertext
    type DV: ArraySize
        // Allows: Dv * 32
        + Mul<U32, Output: ArraySize>;

    /// Number of bytes for just `t_hat` values in a kemeleon encoded value
    ///
    /// Computed as: $\left\lceil (HIGH\\_ORDER\\_BIT -1)/8 \right\rceil$
    type T_HAT_LEN: ArraySize
        // Allows: t_hat_len + RHO_LEN
        + Add<RHO_LEN, Output: ArraySize>
        // Allows: t_hat_len + (Dv * 32)
        + Add<<Self::DV as Mul<U32>>::Output, Output: ArraySize>;

    /// Bitmask for the high order byte which will be less than a full byte of
    /// random bits when encoded.
    ///
    /// Computed as: $(HIGH\\_ORDER\\_BIT -1)\ mod\ 8$
    const MSB_BITMASK: u8;
    /// Bitmask for the high order byte which will be less than a full byte of
    /// random bits when encoded. Inversion of [`EncodingSize::MSB_BITMASK`].
    const MSB_BITMASK_INV: u8 = !Self::MSB_BITMASK;
}

// ========================================================================== //
//                          FIPS
// ========================================================================== //

/// Fips encoding size values
#[allow(non_camel_case_types)]
pub trait FipsEncodingSize: EncodingSize {
    /// Length of an NTT Vector encoded and compressed
    type FIPS_T_HAT_LEN: ArraySize + Add<RHO_LEN, Output: ArraySize>;

    /// Size of the compressed U element of an ML-KEM ciphertext. $Du * K * 256 / 8$
    type FIPS_ENCODED_USIZE: ArraySize + Add<Self::FIPS_ENCODED_VSIZE, Output: ArraySize>;
    /// Size of the compressed V element of an ML-KEM ciphertext. $Dv * 256 / 8$
    type FIPS_ENCODED_VSIZE: ArraySize;
}

impl<T: EncodingSize> FipsEncodingSize for T {
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

impl<T: EncodingSize + FipsEncodingSize> FipsByteArraySize for T {
    type ENCODED_EK_SIZE = Sum<T::FIPS_T_HAT_LEN, RHO_LEN>;
    type ENCODED_CT_SIZE = Sum<T::FIPS_ENCODED_USIZE, T::FIPS_ENCODED_VSIZE>;
}

// ========================================================================== //
//                          Kemeleon
// ========================================================================== //

/// Ciphertext U and V inner element sizes required for encoding and decoding.
#[allow(non_camel_case_types)]
pub trait KemeleonEncodingSize: EncodingSize {
    /// Size of the U value of the kemeleon encoded ciphertext. Matches `T_HAT_LEN`.
    type ENCODED_USIZE: ArraySize + Add<Self::ENCODED_VSIZE, Output: ArraySize>;

    #[allow(clippy::doc_markdown)]
    /// Size of the V value of the Kemeleon encoded ciphertext. N values of Dv Bit size.
    /// The number of bytes is computed as $ ENCODED_VSIZE = n * D_v / 8 \text{ --- for } n=256 $
    type ENCODED_VSIZE: ArraySize;
}

impl<T: EncodingSize> KemeleonEncodingSize for T {
    type ENCODED_USIZE = T::T_HAT_LEN;
    type ENCODED_VSIZE = Prod<Self::DV, U32>;
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

impl<T: KemeleonEncodingSize> KemeleonByteArraySize for T {
    type ENCODED_EK_SIZE = Sum<T::T_HAT_LEN, RHO_LEN>;
    type ENCODED_CT_SIZE = Sum<T::ENCODED_USIZE, T::ENCODED_VSIZE>;
}

// ========================================================================== //
//                          Implementation
// ========================================================================== //

pub use ml_kem::{MlKem1024Params, MlKem512Params, MlKem768Params};

impl EncodingSize for MlKem512Params {
    type USIZE = U12;
    type K = U2;
    type DU = U10;
    type DV = U4;

    type T_HAT_LEN = U749;
    const MSB_BITMASK: u8 = 0b1100_0000;
}

impl EncodingSize for MlKem768Params {
    type USIZE = U12;
    type K = U3;
    type DU = U10;
    type DV = U4;

    type T_HAT_LEN = U1124;
    const MSB_BITMASK: u8 = 0b1111_1100;
}

impl EncodingSize for MlKem1024Params {
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
pub type MlKem512 = mlkem::Kemx<ml_kem::MlKem512Params>;

/// ML-KEM with the parameter set for security category 3, corresponding to key search on a block cipher with a 192-bit key.
pub type MlKem768 = mlkem::Kemx<ml_kem::MlKem768Params>;

/// ML-KEM with the parameter set for security category 5, corresponding to key search on a block cipher with a 256-bit key.
pub type MlKem1024 = mlkem::Kemx<ml_kem::MlKem1024Params>;

impl<P> EncodingSize for mlkem::Kemx<P>
where
    P: KemParams + EncodingSize,
{
    type USIZE = P::USIZE;
    type K = <P as EncodingSize>::K;
    type DU = P::DU;
    type DV = P::DV;

    type T_HAT_LEN = P::T_HAT_LEN;
    const MSB_BITMASK: u8 = P::MSB_BITMASK;
}

use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;

/// Convert to and from byte representations.
pub trait Encode {
    /// Expected size of the output object
    type EncodedSize: ArraySize;
    /// Error returned should decode fail
    type Error: core::error::Error;
    /// Encode this object into its Kemeleon form
    fn as_bytes(&self) -> Array<u8, Self::EncodedSize>;
    /// Decode this object from its encoded form, return `Self::Error` if the provided value cannot
    /// be parsed as a ciphertext
    fn try_from_bytes<B: AsRef<[u8]>>(buf: B) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// A generic interface to an Obfuscated Key Encapsulation Method
pub trait OKemCore: Clone {
    /// Error type retuned by fallible fns
    type OkemError: core::error::Error;

    /// The shared key type generated by this KEM
    type SharedKey: Encode + Debug + PartialEq;

    /// The ciphertext type encapsulating a shared key
    type Ciphertext: Encode + Debug + PartialEq + Clone;

    /// A decapsulation key for this KEM
    type DecapsulationKey: Decapsulate<Self::Ciphertext, Self::SharedKey>
        + Encode
        + Debug
        + PartialEq;

    /// An encapsulation key for this KEM
    type EncapsulationKey: Encapsulate<Self::Ciphertext, Self::SharedKey>
        + Encode
        + Debug
        + PartialEq
        + Clone;

    /// Generate a new encodable (decapsulation, encapsulation) key pair
    fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey);

    /// Generate a new (decapsulation, encapsulation) key pair
    ///
    /// Returns an error if the first key generated is not encodable.
    fn try_generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::OkemError>;

    /// Gicen a Decapsulation key return the associated `EncapsulationKey`
    fn encapsulation_key(dk: &Self::DecapsulationKey) -> Self::EncapsulationKey;
}

impl<U: ArraySize> Encode for Array<u8, U> {
    type Error = EncodeError;
    type EncodedSize = U;

    fn as_bytes(&self) -> Array<u8, Self::EncodedSize> {
        self.clone()
    }

    fn try_from_bytes<B: AsRef<[u8]>>(buf: B) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let len = U::USIZE;
        let arr = buf.as_ref();

        if arr.len() < len {
            return Err(EncodeError::array_too_short(arr.len(), len));
        }
        Ok(Array::<u8, U>::from_fn(|i| arr[i]))
    }
}
