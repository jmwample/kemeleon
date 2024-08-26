//! This is a HMAC DRBG implementation adapted from `sorpaas/rust-hmac-drbg`.
//! The implementation is copied here so that it can be controlled, modified,
//! and maintained as needed internally. The `sorpaas` implementation has not
//! been updated in 4 years, so this seems like a better way to make sure this
//! stays up to date for use in this crate. The Apache2 license for the `sorpaas`
//! crate is included in `docs/licenses/`.
//!
//! # Modifications
//! - [x] Update dependencies
//! - [x] implement `RngCore` for `HmacDRBG`
//! - [ ] **TODO**: Make reading bytes consistent.
//!   - Right now a read creates a block and
//!     throws away any unused bytes. This means that if you constantly call `next_u32`
//!     you will get nea new block every time even though you are only using 4 bytes
//!     of the block, So the bytes you get would be a subset of the ones you get
//!     from just reading into a large [u8]. This could be fixed by keeping track
//!     of how many bytes are remaining in the current block before updating.
//!   - Does this contradict the HMAC DRBG RFC?

use core::cmp::min;

use digest::{
    block_buffer::Eager,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    generic_array::typenum::{IsLess, Le, NonZero, U256},
    HashMarker, OutputSizeUser,
};
use generic_array::{
    typenum::{U4, U8},
    ArrayLength, GenericArray,
};
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, Error, RngCore};

pub struct HmacDRBG<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + OutputSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    Le<BlockSize<D>, U256>: NonZero,

    BlockSize<D>: ArrayLength<u8> + IsLess<U256>,
    OutputSize<D>: ArrayLength<u8>,
{
    k: GenericArray<u8, OutputSize<D>>,
    v: GenericArray<u8, OutputSize<D>>,
    count: usize,
}

type OutputSize<D> = <<D as CoreProxy>::Core as OutputSizeUser>::OutputSize;
type BlockSize<D> = <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize;

#[allow(dead_code)]
impl<D> HmacDRBG<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + OutputSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    Le<BlockSize<D>, U256>: NonZero,

    BlockSize<D>: ArrayLength<u8> + IsLess<U256>,
    OutputSize<D>: ArrayLength<u8>,
{
    pub fn new(entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Self {
        let mut k = GenericArray::<u8, OutputSize<D>>::default();
        let mut v = GenericArray::<u8, OutputSize<D>>::default();

        for i in 0..k.as_slice().len() {
            k[i] = 0x0;
        }

        for i in 0..v.as_slice().len() {
            v[i] = 0x01;
        }

        let mut this = Self { k, v, count: 0 };

        this.update(Some(&[entropy, nonce, pers]));
        this.count = 1;

        this
    }

    pub fn count(&self) -> usize {
        self.count
    }

    fn hmac(&self) -> Hmac<D> {
        Hmac::new_from_slice(&self.k).expect("Smaller and larger key size are handled by default")
    }

    pub fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) {
        self.update(Some(&[entropy, add.unwrap_or(&[])]));
    }

    pub fn generate<N: ArrayLength<u8>>(&mut self, add: Option<&[u8]>) -> GenericArray<u8, N> {
        let mut result = GenericArray::default();
        self.generate_to_slice(result.as_mut_slice(), add);
        result
    }

    pub fn generate_to_slice(&mut self, result: &mut [u8], add: Option<&[u8]>) {
        if let Some(add) = add {
            self.update(Some(&[add]));
        }

        let mut i = 0;
        while i < result.len() {
            let mut vmac = self.hmac();
            vmac.update(&self.v);
            self.v = vmac.finalize().into_bytes();

            let cp_len = min(self.v.len(), result.len() - i);
            result[i..i + cp_len].copy_from_slice(&self.v[..cp_len]);

            i += cp_len;
        }

        match add {
            Some(add) => {
                self.update(Some(&[add]));
            }
            None => {
                self.update(None);
            }
        }
        self.count += 1;
    }

    fn update(&mut self, seeds: Option<&[&[u8]]>) {
        let mut kmac = self.hmac();
        kmac.update(&self.v);
        kmac.update(&[0x00]);
        if let Some(seeds) = seeds {
            for seed in seeds {
                kmac.update(seed);
            }
        }
        self.k = kmac.finalize().into_bytes();

        let mut vmac = self.hmac();
        vmac.update(&self.v);
        self.v = vmac.finalize().into_bytes();

        if seeds.is_none() {
            return;
        }

        let seeds = seeds.unwrap();

        let mut kmac = self.hmac();
        kmac.update(&self.v);
        kmac.update(&[0x01]);
        for seed in seeds {
            kmac.update(seed);
        }
        self.k = kmac.finalize().into_bytes();

        let mut vmac = self.hmac();
        vmac.update(&self.v);
        self.v = vmac.finalize().into_bytes();
    }
}

impl<D> RngCore for HmacDRBG<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + OutputSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    Le<BlockSize<D>, U256>: NonZero,

    BlockSize<D>: ArrayLength<u8> + IsLess<U256>,
    OutputSize<D>: ArrayLength<u8>,
{
    fn next_u32(&mut self) -> u32 {
        let b = self.generate::<U4>(None);
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    fn next_u64(&mut self) -> u64 {
        let b = self.generate::<U8>(None);
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.generate_to_slice(dest, None);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<D> CryptoRng for HmacDRBG<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + OutputSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    Le<BlockSize<D>, U256>: NonZero,

    BlockSize<D>: ArrayLength<u8> + IsLess<U256>,
    OutputSize<D>: ArrayLength<u8>,
{
}

#[cfg(test)]
mod test {
    use generic_array::typenum::U32;
    use hex::FromHex;
    use sha2::Sha256;

    use super::*;

    #[test]
    fn fill_bytes() {
        let mut drbg = HmacDRBG::<Sha256>::new(
            "totally random0123456789".as_bytes(),
            "secret nonce".as_bytes(),
            "my drbg".as_bytes(),
        );

        let expected = "018ec5f8e08c41e5ac974eb129ac297c5388ee1864324fa13d9b15cf98d9a15758e54bbc5c30b5e212e5d14376614d9a7fae84ab62352302a50f37581283b0b97fb723e3790e4364e03e2f9745157ac639ddf121c12b489a1e2a879ca434aa4f75555649de5e17c3c6e1fb866e9f7db463da1e03d0e962c1a9322f2eff4959aa";

        let mut buf = [0u8; 128];
        drbg.fill_bytes(&mut buf);
        assert_eq!(expected, hex::encode(buf));
    }

    #[test]
    fn basic() {
        let mut drbg = HmacDRBG::<Sha256>::new(
            "totally random0123456789".as_bytes(),
            "secret nonce".as_bytes(),
            "my drbg".as_bytes(),
        );

        let expected = [
            "018ec5f8e08c41e5ac974eb129ac297c5388ee1864324fa13d9b15cf98d9a157",
            "6b16576b47a9f4df549a25d82f1440ac07668b4dafbd8d54493ff20005118a20",
            "85431580e28508635e6e4f04a2e7395a4468b99ba8a2722bc70c4dce40d6f80e",
            "11052159bd36911cd075163ca91978b9a17f6e25f171649c78e25001ad203259",
        ];

        for x_str in expected {
            let x_bytes = unhex32(x_str);
            assert_eq!(drbg.generate::<U32>(None).as_slice(), x_bytes);
        }
    }

    fn unhex32(s: &str) -> [u8; 32] {
        <[u8; 32]>::from_hex(s).expect("provided string must unhex to 32 bytes")
    }

    #[test]
    fn consistency() {
        let mut drbg = HmacDRBG::<Sha256>::new(
            "totally random0123456789".as_bytes(),
            "secret nonce".as_bytes(),
            "my drbg".as_bytes(),
        );

        let mut buf = [0u8; 32];
        drbg.fill_bytes(&mut buf);

        let mut drbg = HmacDRBG::<Sha256>::new(
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
}
