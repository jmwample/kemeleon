use super::{vector_decode, vector_encode, EncapsulationKey, Encodable, Encode};
use crate::{fips, Barr8, EncodingSize, FipsEncodingSize, ARR_LEN, RHO_LEN};

use std::io::Error as IoError;

use ml_kem::{EncodedSizeUser, KemCore};

// ========================================================================== //
// Encapsulation Key
// ========================================================================== //

impl<P> Encode for EncapsulationKey<P>
where
    P: KemCore + EncodingSize + FipsEncodingSize,
    [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K]:,
{
    type ET = Barr8<{ <P as EncodingSize>::ENCODED_SIZE }>;
    type Error = IoError;

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
    fn as_bytes(&self) -> Self::ET {
        let mut dst = [0u8; <P as EncodingSize>::ENCODED_SIZE];
        // we know there will be no size error and we know the key will be encodable
        // so we do not need the result.
        let _ = self.encode_priv(&mut dst);
        dst
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
    fn try_from_bytes(c: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        EncapsulationKey::<P>::decode_priv(c.as_ref())
    }
}

impl<P> Encodable for EncapsulationKey<P>
where
    P: KemCore + EncodingSize + FipsEncodingSize,
    [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K]:,
{
    fn satisfies_sampling(&self) -> bool {
        let mut dst = [0u8; <P as EncodingSize>::ENCODED_SIZE];
        self.encode_priv(&mut dst).expect("should never fail")
    }
}

impl<P> EncapsulationKey<P>
where
    P: KemCore + EncodingSize + FipsEncodingSize,
    [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K]:,
{
    fn decode_priv(c: impl AsRef<[u8]>) -> Result<Self, IoError> {
        if c.as_ref().len() < P::ENCODED_SIZE {
            return Err(IoError::other("incorrect length"));
        }

        // Get the random mask byte from the high order bits
        let rand_byte = c.as_ref()[P::T_HAT_LEN - 1] & P::MSB_BITMASK;

        // extract the value of rho
        let mut rho = [0u8; RHO_LEN];
        rho[..].clone_from_slice(&c.as_ref()[P::T_HAT_LEN..]);

        // Remove the randomized the high order bits by setting every bit above
        // the HIGH_ORDER_BIT to 0.
        let mut bytes = c.as_ref()[..P::T_HAT_LEN].to_vec();
        bytes[P::T_HAT_LEN - 1] &= P::MSB_BITMASK_INV;

        // extract the values
        let mut vals = [[0u16; ARR_LEN]; P::K];
        vector_decode(&bytes, vals.as_flattened_mut())?;

        // Build the resulting key
        Ok(EncapsulationKey::<P>::from_parts(&vals, &rho, rand_byte))
    }

    fn encode_priv(&self, mut dst: impl AsMut<[u8]>) -> Result<bool, IoError> {
        let k = dst.as_mut();
        if k.len() < P::ENCODED_SIZE {
            return Err(IoError::other(format!(
                "invalid dst array size. {} < {}",
                k.len(),
                P::ENCODED_SIZE,
            )));
        }

        let vals_fips_encoded = self.key.as_bytes().to_vec();
        let (rho, vals) = fips::byte_decode::<P>(vals_fips_encoded);

        let sample_success = vector_encode(vals.as_flattened(), &mut k[..P::T_HAT_LEN])?;

        // Clear the high order bit (and any bits above it)
        k[P::T_HAT_LEN - 1] &= P::MSB_BITMASK_INV;

        // randomize the high order bits
        k[P::T_HAT_LEN - 1] |= self.byte & P::MSB_BITMASK;

        // append rho
        k[P::T_HAT_LEN..].copy_from_slice(&rho[..]);

        Ok(sample_success)
    }
}

// ========================================================================== //
// Tests
// ========================================================================== //

#[allow(clippy::integer_division_remainder_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mlkem::Kemx, FieldElement, FipsEncodingSize};
    use ml_kem::{Encoded, MlKem1024, MlKem512, MlKem768};
    use num_bigint::BigUint;

    fn entropy_check<P>()
    where
        P: KemCore + EncodingSize + FipsEncodingSize,
        [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
        [(); <P as EncodingSize>::ENCODED_SIZE]:,
        [(); <P as EncodingSize>::K]:,
    {
        let ek_kb = [0xff; P::ENCODED_SIZE];
        let ek = EncapsulationKey::<P>::try_from_bytes(ek_kb).expect("failed to parse key");
        // println!("{:02x}", ek.key.as_bytes()[P::FIPS_ENCODED_SIZE - RHO_LEN-1]);

        // all bits 1 => random mask byte will match the high bit mask
        assert_eq!(P::MSB_BITMASK, ek.byte);

        let ek_kb_1 = ek.as_bytes();
        assert_eq!(
            hex::encode(ek_kb),
            hex::encode(ek_kb_1),
            "failed K={}",
            P::K
        );
    }

    // Bit Frequency analysis test -- make sure that the high order byte
    // doesn't miss setting any bits, leaving non-randomized features.
    #[test]
    fn bit_entropy_check() {
        entropy_check::<MlKem512>();
        entropy_check::<MlKem768>();
        entropy_check::<MlKem1024>();
    }

    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_wrap)]
    fn sample_boundary_check<P>()
    where
        P: KemCore + EncodingSize + FipsEncodingSize,
        [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
        [(); <P as EncodingSize>::ENCODED_SIZE]:,
        [(); <P as EncodingSize>::K]:,
    {
        let ek_kb = [0xff_u8; P::ENCODED_SIZE];
        let max_ek_k = EncapsulationKey::decode_priv(ek_kb).unwrap();
        let ek_fips_b = max_ek_k.key.as_bytes();
        let (rho, max_ntt_vals) = fips::byte_decode(ek_fips_b);

        for k in -2_i16..3 {
            // Adjust the key such that the kemeleon encoded value is `k in [-2..3]` off
            // of max. When k >= 1 the value is no longer encodable as it pushes
            // over to requiring the HIGH_ORDER_BIT to be set.
            let mut t_hat = max_ntt_vals;
            t_hat[0][0] = (t_hat[0][0] as i16 + k) as u16;
            let ek_k = EncapsulationKey::from_parts(&t_hat, &rho, 0xff);

            let mut dst = [0u8; P::ENCODED_SIZE];
            let sample_success = ek_k.encode_priv(&mut dst).expect("encode failed");

            assert_eq!(sample_success, k <= 0, "{k} incorrect");
        }

        // Similarly incrementing the high order byte will be high enough to overflow
        // into the HIGH_ORDER_BIT - making it unencodable.
        let mut t_hat = [[0_u16; ARR_LEN]; P::K];
        t_hat[P::K - 1][ARR_LEN - 1] = max_ntt_vals[P::K - 1][ARR_LEN - 1] + 1;
        let ek_k = EncapsulationKey::from_parts(&t_hat, &rho, 0xff);

        let mut dst = [0u8; P::ENCODED_SIZE];
        let sample_success = ek_k.encode_priv(&mut dst).expect("encode failed");

        assert!(!sample_success, "increment high order byte incorrect");
    }

    // Explicitly test the boundary where we throw out samples for each variant
    #[test]
    fn sampling_boundary() {
        sample_boundary_check::<MlKem512>();
        sample_boundary_check::<MlKem768>();
        sample_boundary_check::<MlKem1024>();
    }

    fn consistency_check<P>()
    where
        P: KemCore + EncodingSize + FipsEncodingSize,
        [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
        [(); <P as EncodingSize>::ENCODED_SIZE]:,
        [(); <P as EncodingSize>::K]:,
    {
        let mut rng = rand::thread_rng();
        // This is the repeated-trial generate function and any key created
        // is guaranteed to be representable, otherwise it would have panicked
        let (_dk, ek) = Kemx::<P>::generate(&mut rng);
        let dst = ek.as_bytes();
        let mut re_encode = dst;

        for _ in 0..5 {
            // Encapsulation Key decoded from bytes sent over the wire.
            let recv_ek = EncapsulationKey::<P>::decode_priv(re_encode).expect("failed decode");
            re_encode = recv_ek.as_bytes();
            assert_eq!(hex::encode(re_encode), hex::encode(dst));
        }
    }

    // Consistent encoding test - decode then re-encode you should get the same bytes
    #[test]
    fn consistency() {
        consistency_check::<MlKem512>();
        consistency_check::<MlKem768>();
        consistency_check::<MlKem1024>();
    }

    fn value_check<P>(b: &[u8], v: &BigUint, description: &str)
    where
        P: KemCore + EncodingSize,
        [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
        [(); <P as EncodingSize>::ENCODED_SIZE]:,
        [(); <P as EncodingSize>::K]:,
    {
        let encoded = Encoded::<P::EncapsulationKey>::try_from(b).unwrap();
        let key = EncapsulationKey::<P> {
            key: P::EncapsulationKey::from_bytes(&encoded),
            byte: 0x00,
        };
        if key.satisfies_sampling() {
            let kv = BigUint::from_bytes_le(&key.as_bytes()[..P::T_HAT_LEN]);
            assert_eq!(&kv, v, "{description}");
        }
    }

    // make sure specific values map in the way we expect them to.
    fn specific_values_trial<P>()
    where
        P: KemCore + EncodingSize + FipsEncodingSize,
        [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
        [(); <P as EncodingSize>::ENCODED_SIZE]:,
        [(); <P as EncodingSize>::K]:,
    {
        let zero = [0u8; P::FIPS_ENCODED_SIZE];
        value_check(&zero, &BigUint::ZERO, "zero");

        // 01 00 -> 01
        let mut one = zero;
        one[0] = 0x01_u8;
        value_check(&one, &BigUint::from(1_u64), "one -> [0][0] = 1");

        // 01 0d -> 3329 -> 0
        let mut one = zero;
        one[0] = 0x01_u8;
        one[1] = 0x0d_u8;
        value_check(&one, &BigUint::ZERO, "one -> [0][0] = 1");

        // 00 10 00 -> 3329   (1<<12)le
        let mut x3329 = zero;
        x3329[1] = 0x10_u8;
        value_check(&x3329, &BigUint::from(3329_u64), "[0][1] = 1");

        // ff 0f 00 -> 0x0fff % 3329
        let mut x = zero;
        x[0] = 0xff_u8;
        x[1] = 0x0f_u8;
        value_check(&x, &BigUint::from(0x0fff % 3329_u64), "[0][1] = ff");

        // 00 f0 0f -> 0xff * 3329
        let mut x = zero;
        x[1] = 0xf0_u8;
        x[2] = 0x0f_u8;
        value_check(&x, &BigUint::from(3329_u64 * 0xff_u64), "[0][1] = ff");

        // 01 10 -> 3330
        let mut x = zero;
        x[0] = 0x01_u8;
        x[1] = 0x10_u8;
        value_check(&x, &BigUint::from(3330_u64), "01 10 => 3330");

        // 00000000... 00 00 10 00 ->  3329 ^(P::K * 256 - 1)
        let mut x = zero;
        x[P::FIPS_ENCODED_SIZE - RHO_LEN - 2] = 0x10_u8;
        value_check(
            &x,
            &BigUint::from(3329_u64).pow((P::K * ARR_LEN - 1) as u32),
            ".... 00 01 00 => 3329 ^(P::K * 256 - 1)",
        );

        // 00000000... 0000f00f ->  (0xff) * 3329 ^(P::K * 256 - 1)
        let mut x = zero;
        x[P::FIPS_ENCODED_SIZE - RHO_LEN - 1] = 0x0f_u8;
        x[P::FIPS_ENCODED_SIZE - RHO_LEN - 2] = 0xf0_u8;
        value_check(
            &x,
            &(BigUint::from(0x00ff_u64) * BigUint::from(3329_u64).pow((P::K * ARR_LEN - 1) as u32)),
            ".... 00 f0 0f => (0x0ff) * 3329 ^(P::K * 256 - 1)",
        );

        // 00000000... 00 00 00 00 | ff ->  0
        let mut x = zero;
        x[P::FIPS_ENCODED_SIZE - RHO_LEN] = 0xff_u8;
        value_check(&x, &BigUint::ZERO, ".... 00 00 00 | ff => 0");
    }

    #[test]
    fn specific_values() {
        specific_values_trial::<MlKem512>();
        specific_values_trial::<MlKem768>();
        specific_values_trial::<MlKem1024>();
    }

    fn encode_decode_trial<P>()
    where
        P: KemCore + EncodingSize + FipsEncodingSize,
        [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
        [(); <P as EncodingSize>::ENCODED_SIZE]:,
        [(); <P as EncodingSize>::K]:,
    {
        let mut rng = rand::thread_rng();
        // This is the repeated trial generate from random and any key created
        // is guaranteed to be representable, otherwise it would have panicked
        let (_dk, ek) = Kemx::<P>::generate(&mut rng);
        let orig = ek.key.as_bytes();
        let dst = ek.as_bytes();

        // Encapsulation Key decoded from bytes sent over the wire.
        let recv_ek = EncapsulationKey::<P>::decode_priv(dst).expect("failed decode");

        assert_eq!(
            hex::encode(&orig),
            hex::encode(recv_ek.key.as_bytes()),
            "b: 0x{:02x}",
            ek.byte
        );
    }

    #[test]
    fn encode_decode() {
        encode_decode_trial::<ml_kem::MlKem512>();
        encode_decode_trial::<ml_kem::MlKem768>();
        encode_decode_trial::<ml_kem::MlKem1024>();
    }

    fn test_encode_decode(encoded_key: &str, b: u8) {
        let ek_bytes = hex::decode(encoded_key).expect("failed to unhex");
        let ek_encoded =
            Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem512Params>>::try_from(
                &ek_bytes[..],
            )
            .expect("failed to build hybrid array");
        let ek_decoded_in =
            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem512Params>::from_bytes(&ek_encoded);
        let ek_in = EncapsulationKey::<MlKem512> {
            key: ek_decoded_in,
            byte: b,
        };

        // Encode encapsulation key using Kemeleon
        let mut dst = [0u8; MlKem512::ENCODED_SIZE];
        let encodable = ek_in.encode_priv(&mut dst).expect("failed kemeleon encode");
        assert!(
            encodable,
            "non-encodable key provided.\n {}",
            hex::encode(dst)
        );

        // Encapsulation Key decoded from bytes sent over the wire.
        let recv_ek = EncapsulationKey::<MlKem512>::decode_priv(dst).expect("failed decode");

        assert_eq!(
            hex::encode(ek_in.key.as_bytes()),
            hex::encode(recv_ek.key.as_bytes())
        );
    }

    // TODO: expand tests to include larger cipher sized
    #[test]
    fn encode_fixed_encap_key() {
        let mut zero = [0u8; 800];
        test_encode_decode(&hex::encode(zero), 0u8);

        zero[0] = 1u8;
        test_encode_decode(&hex::encode(zero), 0u8);

        zero[0] = 0u8;
        zero[1] = 1u8;
        test_encode_decode(&hex::encode(zero), 0u8);

        zero[0] = 1u8;
        zero[1] = 1u8;
        test_encode_decode(&hex::encode(zero), 0u8);

        zero[0] = 0xffu8;
        zero[1] = 0xffu8;
        test_encode_decode(&hex::encode(zero), 0u8);

        zero[0] = 0x00u8;
        zero[1] = 0x00u8;
        zero[767] = 0x33u8;
        test_encode_decode(&hex::encode(zero), 0u8);

        let encoded_key = "1d04f737d1811f950ccc2340bff7640bd95ac2350b92ee6a5dcb4ccd05799bd2a25ad5b04a7a90a064387f9f8b6e77c60309a09b0d3307de9c936a91b797906674134fc9fbb5f1b450d5daa7ddc74c26d43aa8b351b4673f6bc32d89f460666475a28765ce722b42e682941b04635371a5234f6b168142c3366ce6bbd24a52a644619856c4303b0292227e9ae16ccaf33fc4f1a9fb537294b0261f7b1ca6ea14fa02bb12871add605345e4b18d446d5d33951d563b606c4329648b1c92a54f307ab7722294a95c1c42b3734586fd5044e39553c81458e1f85e4dec0275c9248ebc56f623cd08824386c16918a993e3454d1581c8a9c3a032b79d18e21f84c08e033bae46c098f6d55f83c28bef252aa43335dde63c96465125e46101accca40437a0810f616584d73cac1c54071a05c32f21bde9d2ad90e809f61862db966671eb2ace541290502d90185d819a7d0e566fa5e454e3cc7da8c93187a3af32dc831421c9b7ea984ad7c45483a119bca58ba8a1fc2201598884ce93255e359e8f989224548ab7f91657a56f83d68a21656d854432362a71d0727f45ca0138605885ac4314d2a1c8f61522e8aa91813fd6ab0ac438c04c182e25e774ac2c3c967306eda695d15505182a788191a46b3252a9917b56e23c92a7a51fc09f43221b806178272c11de8598f6a049d5ca2b342c08c4f13ca8d79ab7447bc0871ed525653b19b78bdb1fef17a3a14a2607dbcb7952a043012642a782d22706c08487bbcb95a6494dff891f75a86ce15c77c73c880e516a41139df7f0adf4d393cc564b68896d419948dcbb74740b5f85115c65ba0e5602449d10b20783abbd56b1b1b2cf5c73768563056eb76e8338515da7af1b62b29a05a1ed531de0b84b4c3033e80c3d50866dd3c0a17b9387e97963165720b587785912bdab15c946893024579923f16a46bbac862aa823d81619c616af92a0575019af5732c4a80686c1c4f81ac743611e45453e820878aa6498c28984b17b073d38945a73c8f8e033c038a5a25504a3324679490285be911109c35dec1c7ffa48d62c3acaddb348150b9a0de15d140000000000000000000000000000000000000000000000000000000000000000";
        test_encode_decode(encoded_key, 0u8);
        test_encode_decode(encoded_key, 1u8);
        test_encode_decode(encoded_key, 0x3fu8);
        // test_encode_decode(encoded_key, 0xffu8); // unencodable

        let encoded_key = "6290c6bae865138cc97c47ad54c9a2253b6b29a5044ee9abd098321ac1b2a831184b8bbc681516954447d1728c93627e50e36256408582a1cb7285817270753f0b4ed7ca8f260ac9367bb5e45a8ee447c79b161134158a2afc6135c37199642847891a7cf73da9ba4c0b3a1363372ba6062224c9ca9fb46bbfb22fa1e66b6477b53bc7584772850d3c6e8a9739af3b01c9f8a3c281c5ecc23c6fab82351661b2f79a007bb070ac900af8c1e159a06d101f93ab7f81721e33e712bf915083b0193cf0b7c208bc77291d51e90d58d217b2c1853b728daa271a37c26e0d557a15b4195b272294188f1c4a76d308443e32a45ea3b714498fb86a3f7430a8ff9b218519bce2976927acc53e404877033f524410b01c79d15b0c4802a2cd47b6bee983df36c01bb3abff137b4217b1d2acbfe8652f890a03f4c12177490b38a345078a31783c1dd3413eaf7c4cbef32b0d5c165e0428d94aae1ea39f604c6d1515a08f758e5898461ae7c7dd3a0bc5993965f03961a7669cf252af4611b8b3a6e3c35bbea149123779dc41aebb9b5707d93b63b0c09475182a87501259a354d39e243c3c8b69a3ce42250a5024ecb9c658414a2ec051b7468a15763e9c768822ec769ab3ce7b8b1ad38ab9523cba17a778aa6b6bc583beb71c7502fa24f0a1c41dfa7a603654489c15c81a70fad674aab7a469654c46714deb8b6fd8d0686d022859b96dc9e415cc8aa073bb9b53812f0705ab4c2bae23db1ab5b1089e57aaadea299962c284a2bb7b70b23e9ab895d3be9a4416fac244586804ba7399438098fd56b61fc721fba6c10862acc677950b379007d1a12fb793dd15b250148b89956287d474ec44bb9d262c4c1b35ec338956c57f0547173d166cd5a7a17a08841d0845a15aa8b548bb95e9c3391c3cecda07c951b7c0d9235af98ef4178202fa5736ca4940a30be4979dbda4972c7001a06867419290080388b5388c02f57c3667090413bdc8369892e3c6b1048dc39c86de03ccae7c73ec4109ac404a766827d43024652b4412aac36a715321f7c286616c61b38e0965b8ec45733bfac3e44c9e1bab1d86bb4e2ba58b21622c93a8f533ffcaea8127a9656df0449d8d8225147e6a271d";
        test_encode_decode(encoded_key, 0x8eu8);
    }

    #[test]
    fn compute_constants() {
        let expected_lengths = [2995, 5990, 8986, 11981];

        let base = BigUint::from(FieldElement::Q64);
        for k in [1_usize, 2, 3, 4] {
            let mut v = BigUint::ZERO;
            let mut offset = BigUint::from(1_u64);
            for _ in 0..k {
                for _ in 0..ARR_LEN {
                    v += 3328_u16 * &offset;
                    offset *= &base;
                }
            }

            let bits = v.bits() as u32;
            let over = (BigUint::from(1_u64) << bits) - 1_u64;
            let under = (BigUint::from(1_u64) << (bits - 1)) - 1_u64;

            assert!(v < over);
            assert!(v > under);

            assert_eq!(bits - 1, expected_lengths[k - 1]);
            // println!("{k} {} {}", bits, bits % 8);
            // println!("{}", v);
        }

        let q = BigUint::from(FieldElement::Q64);
        let max_value = q.pow(ARR_LEN as u32 * 3_u32) - 1u32;
        let max_val_bits: u32 = max_value.bits() as u32;
        // println!("{} {}", max_val_bits, hex::encode(max_value.to_bytes_le()));

        let mut over = (BigUint::from(1_u64) << max_val_bits) - 1_u64;
        let under = (BigUint::from(1_u64) << (max_val_bits - 1)) - 1_u64;
        assert!(max_value < over);
        assert!(max_value > under);

        over.set_bit(u64::from(max_val_bits - 1), false);
        assert_eq!(over, under);

        // let lim_val = BigUint::from(2_u64).pow(max_val_bits);
        // let lim_val_bitcount = lim_val.bits();
        // let lim_val_bytes = lim_val.to_bytes_le();
        // println!("{} {} {}", lim_val_bitcount, lim_val_bytes.len(), hex::encode(lim_val_bytes));
    }
}
