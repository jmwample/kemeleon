//! This is a HMAC DRBG implementation adapted from `sorpaas/rust-hmac-drbg`.
//! The implementation is copied here so that it can be controlled, modified,
//! and maintained as needed internally. The `sorpaas` implementation has not
//! been updated in 4 years, so this seems like a better way to make sure this
//! stays up to date for use in this crate. The Apache2 license for the `sorpaas`
//! crate is included in `docs/licenses/`.

use core::cmp::min;

use digest::{
    block_buffer::Eager,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    generic_array::typenum::{IsLess, Le, NonZero, U256},
    HashMarker, OutputSizeUser,
};
use generic_array::{
    typenum::{U32, U4, U8},
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

            for j in 0..self.v.len() {
                result[i + j] = self.v[j];
            }
            i += self.v.len();
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
        let mut generated = 0_usize;
        while generated < dest.len() {
            let remaining = dest.len() - generated;
            let step = min(32, remaining);

            let b = self.generate::<U32>(None);
            dest[generated..generated + step].copy_from_slice(&b[..step]);

            generated += step;
        }
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

        let expected = "018ec5f8e08c41e5ac974eb129ac297c5388ee1864324fa13d9b15cf98d9a1576b16576b47a9f4df549a25d82f1440ac07668b4dafbd8d54493ff20005118a2085431580e28508635e6e4f04a2e7395a4468b99ba8a2722bc70c4dce40d6f80e11052159bd36911cd075163ca91978b9a17f6e25f171649c78e25001ad203259";

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
}
