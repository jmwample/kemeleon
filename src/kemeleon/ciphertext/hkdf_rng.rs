//! HKDF-based Random Number Generator
//!
//! This is used to create a predictable (i.e. deterministic by input) source
//! of random bytes that can be used when required in ciphertext encapsulation.
//!

use digest::{
    block_buffer::Eager,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    generic_array::typenum::{IsLess, Le, NonZero, U256},
    HashMarker, OutputSizeUser,
};
use generic_array::ArrayLength;
use hkdf::Hkdf;
use rand_core::{CryptoRng, Error, RngCore};

type OutputSize<D> = <<D as CoreProxy>::Core as OutputSizeUser>::OutputSize;
type BlockSize<D> = <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize;

/// max size that I could fill from hkdf<sha256>
const MAX_FILL: usize = 8192 - 32;

pub struct HkdfRng<D>
where
    D: CoreProxy + OutputSizeUser,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + OutputSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    Le<BlockSize<D>, U256>: NonZero,
    BlockSize<D>: ArrayLength + IsLess<U256>,
    OutputSize<D>: ArrayLength,
{
    private_buf: [u8; MAX_FILL],
    count: usize,
    _digest: core::marker::PhantomData<D>,
}

#[allow(dead_code)]
impl<D> HkdfRng<D>
where
    D: CoreProxy + OutputSizeUser,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + OutputSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    Le<BlockSize<D>, U256>: NonZero,

    BlockSize<D>: ArrayLength + IsLess<U256>,
    OutputSize<D>: ArrayLength,
{
    pub fn new(ikm: &[u8], salt: &[u8], info: &[u8]) -> Self {
        let hk = Hkdf::<D>::new(Some(salt), ikm);

        let mut buf = [0u8; MAX_FILL];
        hk.expand(info, &mut buf)
            .expect("failed to initialize hkdf rng");

        Self {
            private_buf: buf,
            count: 0,
            _digest: core::marker::PhantomData {},
        }
    }

    pub fn remaining(&self) -> usize {
        MAX_FILL - self.count
    }

    pub fn used(&self) -> usize {
        self.count
    }
}

impl<D> RngCore for HkdfRng<D>
where
    D: CoreProxy + OutputSizeUser,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + OutputSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    Le<BlockSize<D>, U256>: NonZero,

    BlockSize<D>: ArrayLength + IsLess<U256>,
    OutputSize<D>: ArrayLength,
{
    fn next_u32(&mut self) -> u32 {
        assert!(
            self.remaining() >= 4,
            "not enough randomness remains in hkdf rng: need 4, {} remain",
            self.remaining()
        );

        let mut b = [0u8; 4];
        b.copy_from_slice(&self.private_buf[self.count..self.count + 4]);
        self.count += 4;
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    fn next_u64(&mut self) -> u64 {
        assert!(
            self.remaining() >= 8,
            "not enough randomness remains in hkdf rng: need 8, {} remain",
            self.remaining()
        );

        let mut b = [0u8; 8];
        b.copy_from_slice(&self.private_buf[self.count..self.count + 8]);
        self.count += 8;
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(
            self.remaining() >= dest.len(),
            "not enough randomness remains in hkdf rng: need {}, {} remain",
            dest.len(),
            self.remaining()
        );

        let k = dest.len();
        if k == 0 {
            return;
        }

        dest.copy_from_slice(&self.private_buf[self.count..self.count + k]);
        self.count += k;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<D> CryptoRng for HkdfRng<D>
where
    D: CoreProxy + OutputSizeUser,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + OutputSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    Le<BlockSize<D>, U256>: NonZero,

    BlockSize<D>: ArrayLength + IsLess<U256>,
    OutputSize<D>: ArrayLength,
{
}

#[cfg(test)]
mod test {
    use sha2::Sha256;

    use super::*;

    #[test]
    fn fill_bytes() {
        let mut drbg = HkdfRng::<Sha256>::new(
            "initial key material".as_bytes(),
            "sodium chloride".as_bytes(),
            "name-spacing / differentiating material".as_bytes(),
        );

        let expected = "640364973888c2b4978544a45bd2639b862443333a1afe6005f81e546b02956ec04209286f249c5bd9458864e93527edfc28dc2e531b98af6fe22c5ec1dadb31d118a25d42fcc9df3375e2718860586c439a3ea8d4b7ce1a616ace301ee7f04190930440897caf25f57a33e19f7bca87684981d14f3c7cd006d49003cdb42e0b";

        let mut buf = [0u8; 128];
        drbg.fill_bytes(&mut buf);
        assert_eq!(expected, hex::encode(buf));
    }

    #[test]
    fn basic() {
        let mut drbg = HkdfRng::<Sha256>::new(
            "initial key material".as_bytes(),
            "sodium chloride".as_bytes(),
            "name-spacing / differentiating material".as_bytes(),
        );

        let expected = [
            "640364973888c2b4978544a45bd2639b862443333a1afe6005f81e546b02956e",
            "c04209286f249c5bd9458864e93527edfc28dc2e531b98af6fe22c5ec1dadb31",
            "d118a25d42fcc9df3375e2718860586c439a3ea8d4b7ce1a616ace301ee7f041",
            "90930440897caf25f57a33e19f7bca87684981d14f3c7cd006d49003cdb42e0b",
        ];

        let mut buf = [0u8; 32];
        for x_str in expected {
            drbg.fill_bytes(&mut buf);
            assert_eq!(hex::encode(buf), x_str);
        }
    }

    #[test]
    fn consistency() {
        let mut drbg = HkdfRng::<Sha256>::new(
            "totally random0123456789".as_bytes(),
            "secret nonce".as_bytes(),
            "my drbg".as_bytes(),
        );

        let mut buf = [0u8; 32];
        drbg.fill_bytes(&mut buf);

        let mut drbg = HkdfRng::<Sha256>::new(
            "totally random0123456789".as_bytes(),
            "secret nonce".as_bytes(),
            "my drbg".as_bytes(),
        );

        let mut buf1 = [0u8; 32];
        for i in 0..8 {
            let b = drbg.next_u32().to_be_bytes();
            buf1[i * 4..(i * 4) + 4].copy_from_slice(&b[0..4]);
        }
    }

    #[test]
    #[should_panic(expected = "not enough randomness remains in hkdf rng: need 8, 7 remain")]
    fn read_u64_too_far() {
        let mut rng = HkdfRng::<Sha256>::new(b"aaa", b"bbb", b"ccc");
        rng.count = MAX_FILL - 7;
        rng.next_u64();
    }

    #[test]
    #[should_panic(expected = "not enough randomness remains in hkdf rng: need 4, 3 remain")]
    fn read_u32_too_far() {
        let mut rng = HkdfRng::<Sha256>::new(b"aaa", b"bbb", b"ccc");
        rng.count = MAX_FILL - 3;
        rng.next_u32();
    }

    #[test]
    #[should_panic(expected = "not enough randomness remains in hkdf rng: need 2, 1 remain")]
    fn fill_bytes_too_far() {
        let mut rng = HkdfRng::<Sha256>::new(b"aaa", b"bbb", b"ccc");
        rng.count = MAX_FILL - 1;
        let mut buf = [0u8; 2];
        rng.try_fill_bytes(&mut buf).expect("cannot happen");
    }
}
