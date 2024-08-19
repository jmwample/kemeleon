use super::{vector_decode, vector_encode, Encode};
use crate::{Barr8, EncodingSize, ARR_LEN, RHO_LEN};

use core::marker::PhantomData;
use std::io::Error as IoError;

use ml_kem::KemCore;
use rand_core::CryptoRngCore;
use sha2::Sha256;

mod compress;
use compress::Compress;

mod hmac_drbg;
use hmac_drbg::HmacDRBG;

// ========================================================================== //
// CipherText
// ========================================================================== //

pub use crate::mlkem::KCiphertext as Ciphertext;

impl<P> Encode for Ciphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K * RHO_LEN]:,
{
    /// Encapsulation Key
    type EK = Self;

    /// Encoded Cuphertext Type
    type ET = Barr8<{ P::K * RHO_LEN }>;

    /// Error Type returned on failed decode
    type Error = IoError;

    fn as_bytes(&self) -> Self::ET {
        // TODO: I dislike having to use a non-provided rng here to convert to
        // bytes in a non-deterministic way.
        // let mut rng = rand::thread_rng();
        let mut drbg = HmacDRBG::<Sha256>::new(b"0000", b"0000", b"0000");
        let mut out = [0u8; P::K * RHO_LEN];
        self.encode(&mut drbg, &mut out).expect("shouldn't happen");
        out
    }

    fn try_from_bytes(b: impl AsRef<[u8]>) -> Result<Self, IoError> {
        if b.as_ref().is_empty() {
            return Err(IoError::other("bad bytestring provided"));
        }

        Ciphertext::decode(b)
    }
}

impl<P> Ciphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K * RHO_LEN]:,
{
    fn decode(c: impl AsRef<[u8]>) -> Result<Self, IoError> {
        let (c1, c2) = split_ct::<P>(c.as_ref());
        // let idx_r1 = P::DV * ARR_LEN;
        // let r1 = &c.as_ref()[..c.as_ref().len() - idx_r1];
        // let c2 = &c.as_ref()[idx_r1..];

        let mut values = [[0u16; ARR_LEN]; P::K];
        vector_decode::<P>(&c1, values.as_flattened_mut())
            .map_err(|e| IoError::other("error occured while decoding"))?;

        let c1 = values.as_flattened_mut();
        c1.iter_mut().compress::<P>();
        let mut ctxt = c1.to_vec();
        // ctxt.append(c2);

        // let fips = ml_kem::Ciphertext::try_from(fips_ct.as_ref())
        //     .map_err(|_| IoError::other("failed to parse as ciphertext"))?;

        // Ok(Self {
        //     bytes: b.as_ref().to_vec(),
        //     fips,
        //     _p: PhantomData,
        // })
        todo!("not yet implemented");
    }

    fn encode(
        &self,
        rng: &mut impl CryptoRngCore,
        _dst: impl AsMut<[u8]>,
    ) -> Result<bool, IoError> {
        // TODO: Length check

        // split the u and v elements
        let (mut c1, c2) = split_fips_ct::<P>(&self.bytes);
        let mut r1: Vec<u16> = c1
            .chunks_exact(2)
            .map(|a| u16::from_le_bytes([a[0], a[1]]))
            .collect();

        // re-add randomness to the u elements
        r1.iter_mut().decompress::<P>();
        for mut u_i in &mut r1 {
            *u_i = recover_rand::<{ P::DU }>(*u_i, rng);
        }

        // encode the u elements
        let mut dst = [0u8; P::ENCODED_SIZE];
        let c1_u16: Vec<u16> = c1
            .chunks_exact(2)
            .map(|a| u16::from_le_bytes([a[0], a[1]]))
            .collect();
        let success = vector_encode(c1_u16, &mut dst)?;

        // TODO: check c2 for 0s and rejection sample based on probability
        // c2.for_each(|v| success &= ??? );

        // todo!("not yet implemented");
        Ok(success)
    }
}

fn recover_rand<const D: usize>(i: u16, rng: &mut impl CryptoRngCore) -> u16 {
    // TODO: find values that do not modify u_i
    i
}

fn split_fips_ct<P>(b: &[u8]) -> (&[u8], &[u8])
where
    P: EncodingSize,
{
    (&(b[..P::ENCODED_SIZE]), &(b[P::ENCODED_SIZE..]))
}

// TODO: this is skeleton code
fn split_ct<P>(b: &[u8]) -> (&[u8], &[u8])
where
    P: EncodingSize,
{
    (&(b[..P::ENCODED_SIZE]), &(b[P::ENCODED_SIZE..]))
}

#[cfg(test)]
mod test {
    // #[test]
    // fn encode_decode() {
    //     todo!("test not implemented yet");
    // }
}
