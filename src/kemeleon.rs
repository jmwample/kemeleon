use crate::{ARR_LEN, ValueArray, ValueArrayDecoder, ValueArrayEncoder, FieldElement};

use std::io::Error;

use num_bigint::BigUint;

/// Kemeleon encoding
pub(crate) struct Kemeleon {}

/// In this formulation a is 1 indexed (as oposed to being 0 indexed)
///
/// Kemeleon.Encode(a):
/// ```txt ignore
///     1 𝑟 ← sum(𝑖=1, 𝑘·𝑛, 𝑞^(𝑖−1) · a[𝑖]
///     2 if 𝑟 .bit( ⌈log2 (𝑞^(𝑛·𝑘) + 1) ⌉) = 1:
///     3     return ⊥ // most significant bit is 1
///     4 return 𝑟 .bit(0 : ⌈log2 (𝑞^(𝑛·𝑘) + 1) ⌉ − 1)
/// ```
///
/// The intuition here is to accumulate (sum) the integer coefficients,
/// resulting in a single larger integer whose intermediary bits are no longer
/// biased.
impl ValueArrayEncoder for Kemeleon {
    fn encode(p: &ValueArray) -> Vec<u8> {
        Self::encode_priv(p).0
    }
}

/// Kemeleon.Decode(𝑟):
/// ```txt ignore
///     1 𝑟 .bit( ⌈log2(𝑞^(𝑛·𝑘 + 1) ⌉) ← 0
///         // set most significant bit to 0
///
///     2 for 𝑖 = 1 to 𝑘 · 𝑛:
///     3     a[𝑖] ← ( 𝑟− sum(𝑗=1, 𝑖−1, 𝑝𝑘 [𝑗]) ) / ( 𝑞^(𝑖−1) ) mod 𝑞
///     4 return a
/// ```
impl ValueArrayDecoder for Kemeleon {
    fn decode(c: impl AsRef<[u8]>) -> Result<ValueArray, Error> {
        // if c.as_ref().len() < ValueArray::LENGTH * 2 {
        //     return Err(Error::other("incorrect length"));
        // }

        let base = BigUint::from(FieldElement::Q);
        let r = BigUint::from_bytes_le(c.as_ref());

        let mut out = [FieldElement(0u16); ARR_LEN];
        let mut scratch: BigUint;
        for i in 0..ARR_LEN {
            scratch = BigUint::ZERO;
            let pk_i = ((&r - &scratch) / base.pow(i as u32)) % FieldElement::Q;
            scratch += &pk_i;
            out[i] = FieldElement(pk_i.to_u32_digits()[0] as u16);
        }

        Ok(out)
    }
}

impl Kemeleon {
    fn encode_priv(p: &ValueArray) -> (Vec<u8>, bool) {
        let mut out = BigUint::ZERO;
        let base = BigUint::from(FieldElement::Q);

        for (i, x) in p.iter().enumerate() {
            let bigx = BigUint::from(x.0);
            out += bigx * base.pow(i as u32);
        }

        (out.to_bytes_le(), !out.bit(2996))
    }


    pub fn validate_encoding(p: &ValueArray) -> bool {
        Self::encode_priv(p).1
    }
}

// ========================================================================== //
// Tests
// ========================================================================== //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode() {
        let mut rng = rand::thread_rng();
        let k = crate::tests::from_rand_rng(&mut rng);

        let c = Kemeleon::encode(&k);
        // let out = hex::encode(&c);
        // dbg!(&out);
        let p = Kemeleon::decode(c).expect("failed decode");

        assert_eq!(k, p)
    }


    #[test]
    fn compute_constants() {
        let q = BigUint::from(FieldElement::Q);
        let expected_lengths = [2995, 5990, 8986, 11981];

        let n = 256;
        for k in [1, 2, 3, 4] {
            let v: BigUint = q.pow(n * k) + 1u32;

            let bits = v.bits()-1;
            assert_eq!(bits, expected_lengths[k as usize -1]);
            // println!("{} {}", bits, bits%8)
        }
    }
}
