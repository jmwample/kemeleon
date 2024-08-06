//! Implementation of Kemeleon Encodings
//!
//! [Paper](https://eprint.iacr.org/2024/1086.pdf).
//!
//! ## Usage
//!
//! ```
//! use ml_kem::MlKem512;
//! let mut rng = rand::thread_rng();
//! let (dk, ek) = Kemx::<MlKem512>::generate(&mut rng).expect("keygen failed");
//!
//! // // Converting the Encapsulation key to bytes and back in order to be sent.
//! // let ek_encoded: Vec<u8> = ek.as_bytes().to_vec();
//!
//! let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
//!
//! // // Converting the ciphertext to bytes and back in order to be sent.
//! // let ct = Ciphertext::<MlKem512>::from_bytes(ct);
//!
//! let k_recv = dk.decapsulate(&ct).unwrap();
//! assert_eq!(k_send, k_recv);
//! ```
//!
//! ## Explanation
//!
//! #### Encapsulation Keys
//!
//! ```txt ignore
//! Kemeleon.Encode(a):
//!   1 𝑟 ← sum(𝑖=1, 𝑘·𝑛, 𝑞^(𝑖−1) · a[𝑖]
//!   2 if 𝑟 .bit( ⌈log2 (𝑞^(𝑛·𝑘) + 1) ⌉) = 1:
//!   3     return ⊥                        // if the most significant bit is 1 -> reject
//!   4 return 𝑟 .bit(0 : ⌈log2 (𝑞^(𝑛·𝑘) + 1) ⌉ − 1)
//! ```
//!
//! Once encoded in this way the high order byte will have the remainder randomized
//!
//! A key encoded in this way can then be decoded using the following algorithm
//!
//! ```txt ignore
//! Kemeleon.Decode(𝑟):
//!   1 𝑟 .bit( ⌈log2(𝑞^(𝑛·𝑘 + 1) ⌉) ← 0    // set most significant bit to 0
//!   2 for 𝑖 = 1 to 𝑘 · 𝑛:
//!   3     a[𝑖] ← ( 𝑟− sum(𝑗=1, 𝑖−1, 𝑝𝑘 [𝑗]) ) / ( 𝑞^(𝑖−1) ) mod 𝑞
//!   4 return a
//! ```
//!
//! #### Ciphertext
//!
//! ```txt ignore
//! Kemeleon.EncodeCtxt(c = (c1 || c2)):
//!
//! ```
//!
//! ```txt ignore
//! Kemeleon.DecodeCtxt(r):
//!
//! ```
#![feature(generic_const_exprs)]

use core::fmt::Debug;

mod fips;
pub mod kemeleon;
mod mlkem;

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

/// Convert between Kemeleon and `ml-kem` values.
pub trait Transcode {
    type Fips;

    fn as_fips(&self) -> &Self::Fips;

    fn to_fips(self) -> Self::Fips;

    fn from_fips(t: Self::Fips) -> Self;
}

// ========================================================================== //
// Encoding Sizes and Generics
// ========================================================================== //

pub trait EncodingSize {
    /// Number of bits used to represent field elements
    const USIZE: usize = 12;

    const VALUE_STEP: usize = 2;
    const BYTE_STEP: usize = 3;

    /// Number of field elements per equation.
    const K: usize;
    /// Number of bytes required to represent the object when not encoded
    const UNENCODED_SIZE: usize = RHO_LEN + ARR_LEN * Self::K;

    /// Bitwise Index of the high order bit when computing the kemeleon byte
    /// representation. Computed as $\left\lceil log_{2}(q^{n\cdot k}+1) \right\rceil$
    const HIGH_ORDER_BIT: u64;
    /// Size of the Kemeleon encoded string as bytes. $\left\lceil (HIGH\_ORDER\_BIT -1)/8 \right\rceil$
    const ENCODED_SIZE: usize;
    /// Bitmask for the high order byte which will be less than a full byte of
    /// random bits when encoded. $(HIGH\_ORDER\_BIT -1)\ mod\ 8$
    const MSB_BITMASK: u8;
    /// Bitmask for the high order byte which will be less than a full byte of
    /// random bits when encoded. Inversion of [`EncodingSize::MSB_BITMASK`].
    const MSB_BITMASK_INV: u8;

    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;
}

impl EncodingSize for ml_kem::MlKem512 {
    const K: usize = 2;

    const ENCODED_SIZE: usize = RHO_LEN + 749;
    const MSB_BITMASK: u8 = 0b00011111;
    const MSB_BITMASK_INV: u8 = 0b11100000;
    const HIGH_ORDER_BIT: u64 = 5991;

    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

impl EncodingSize for ml_kem::MlKem768 {
    const K: usize = 3;

    const ENCODED_SIZE: usize = RHO_LEN + 1124;
    const MSB_BITMASK: u8 = 0b00011111;
    const MSB_BITMASK_INV: u8 = 0b11100000;
    const HIGH_ORDER_BIT: u64 = 8987;

    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

impl EncodingSize for ml_kem::MlKem1024 {
    const K: usize = 4;

    const ENCODED_SIZE: usize = RHO_LEN + 1498;
    const MSB_BITMASK: u8 = 0b00011111;
    const MSB_BITMASK_INV: u8 = 0b11100000;
    const HIGH_ORDER_BIT: u64 = 11982;

    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
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
