//! This is a HMAC DRBG implementation adapted from `sorpaas/rust-hmac-drbg`.
//! The implementation is copied here so that it can be controlled, modified,
//! and maintained as needed internally. The `sorpaas` implementation has not
//! been updated in 4 years, so this seems like a better way to make sure this
//! stays up to date for use in this crate. The Apache2 license for the `sorpaas`
//! crate is included in `docs/licenses/`.

use digest::{
    block_buffer::Eager,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    generic_array::typenum::{IsLess, Le, NonZero, U256},
    HashMarker, OutputSizeUser,
};
use generic_array::{ArrayLength, GenericArray};
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
        0_u32
    }

    fn next_u64(&mut self) -> u64 {
        0_u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
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
