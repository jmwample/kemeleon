use core::fmt::Debug;
use std::io::Error;

mod fips;
pub mod kemeleon;
pub mod mlkem;

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

impl FieldElement {
    pub const Q: u16 = 3329;
    pub const Q32: u32 = Self::Q as u32;
    pub const Q64: u64 = Self::Q as u64;
}

type ValueArray = [FieldElement; ARR_LEN];

pub trait Transcode {
    type Fips;

    fn to_fips(&self) -> Self::Fips;

    fn from_fips(t: &Self::Fips) -> Self;
}

pub trait ValueArrayEncoder {
    fn encode(p: &ValueArray) -> Vec<u8>;
}
pub trait ValueArrayDecoder {
    fn decode(c: impl AsRef<[u8]>) -> Result<ValueArray, Error>;
}

// ========================================================================== //
// Encoding Sizes and Generics
// ========================================================================== //

pub trait EncodingSize {
    const USIZE: usize = 12;
    const VALUE_STEP: usize = 2;
    const BYTE_STEP: usize = 3;

    const K: usize;

    const ENCODED_SIZE: usize;
    const MSB_BITMASK: u8;
    const MSB_BITMASK_INV: u8;
    const HIGH_ORDER_BIT: u64;

    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;
}

impl EncodingSize for ml_kem::MlKem512 {
    const K: usize = 2;

    const ENCODED_SIZE: usize = 749;
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

    const ENCODED_SIZE: usize = 1124;
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

    const ENCODED_SIZE: usize = 1498;
    const MSB_BITMASK: u8 = 0b00011111;
    const MSB_BITMASK_INV: u8 = 0b11100000;
    const HIGH_ORDER_BIT: u64 = 11982;

    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
}

// ========================================================================== //
// Tests
// ========================================================================== //

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{CryptoRng, RngCore};

    pub fn from_rand_rng<R: RngCore + CryptoRng>(mut rng: R) -> ValueArray {
        let mut b = [0u8; ARR_LEN * 2];
        rng.fill_bytes(&mut b);

        let mut c = [FieldElement(0u16); ARR_LEN];
        b.chunks_exact(2)
            .into_iter()
            .enumerate()
            .for_each(|(i, a)| {
                c[i] = FieldElement(u16::from_be_bytes([a[0], a[1]]) % FieldElement::Q)
            });

        c
    }

    #[test]
    fn create() {
        let mut rng = rand::thread_rng();
        let _ = from_rand_rng(&mut rng);
    }

    // #[test]
    // fn encode_decode() {
    //     let mut rng = rand::thread_rng();
    //     let k = from_rand_rng(&mut rng);

    //     let c = DeadSimple::encode(&k);
    //     let p = DeadSimple::decode(c).expect("failed decode");

    //     assert_eq!(k, p)
    // }
}

//
// // ========================================================================== //
// // DeadSimple
// // ========================================================================== //
//
// /// This is a basic encode / decode for ValueArra. It has many flaws wrt.
// /// the goals that we set out for an ideal encoding.
// ///
// /// - values always less than Q (where Q = 3329)
// /// - 0 bits since we 3329 < 4096 (12 bits) and we encode values using 16 bits
// /// - out of the 12 bits used per value, only 3329/4096 values are hit
// struct DeadSimple {}
//
// impl ValueArrayEncoder for DeadSimple {
//     fn encode(p: &ValueArray) -> Vec<u8> {
//         let mut c = vec![0u8; ARR_LEN * 2];
//         p.iter().enumerate().for_each(|(i, v)| {
//             let a = v.0.to_be_bytes();
//             c[2 * i] = a[0];
//             c[2 * i + 1] = a[1];
//         });
//         c
//     }
// }
//
// impl ValueArrayDecoder for DeadSimple {
//     fn decode(c: impl AsRef<[u8]>) -> Result<ValueArray, Error> {
//         if c.as_ref().len() < ARR_LEN * 2 {
//             return Err(Error::other("incorrect length"));
//         }
//
//         let mut p = [FieldElement(0u16); ARR_LEN];
//         c.as_ref()[..ARR_LEN * 2]
//             .chunks_exact(2)
//             .into_iter()
//             .enumerate()
//             .for_each(|(i, a)| {
//                 p[i] = FieldElement(u16::from_be_bytes([a[0], a[1]]) % FieldElement::Q)
//             });
//
//         Ok(p)
//     }
// }
//
// impl DeadSimple {
//     pub fn encode_value(v: &FieldElement) -> [u8; 2] {
//         v.0.to_be_bytes()
//     }
//
//     pub fn decode_value(v: [u8; 2]) -> FieldElement {
//         FieldElement(u16::from_be_bytes(v))
//     }
// }
