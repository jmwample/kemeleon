use super::{vector_decode, vector_encode, Encode};
use crate::fips;
use crate::{Barr8, EncodingSize, FipsEncodingSize, ARR_LEN};

use std::io::Error as IoError;

use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use ml_kem::KemCore;
use rand::{CryptoRng, RngCore};
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
pub use crate::mlkem::KEncodedCiphertext as EncodedCiphertext;

impl<P> Encode for EncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::ENCODED_CT_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{
    /// Encoded Cuphertext Type
    type ET = Barr8<{ P::ENCODED_CT_SIZE }>;

    /// Error Type returned on failed decode
    type Error = IoError;

    fn as_bytes(&self) -> Self::ET {
        self.0
    }

    fn try_from_bytes(b: impl AsRef<[u8]>) -> Result<Self, IoError> {
        if b.as_ref().is_empty() {
            return Err(IoError::other("empty bytestring provided"));
        } else if b.as_ref().len() < P::ENCODED_CT_SIZE {
            return Err(IoError::other("bad bytestring provided"));
        }
        let mut arr = [0u8; P::ENCODED_CT_SIZE];
        arr.copy_from_slice(&b.as_ref()[..P::ENCODED_CT_SIZE]);

        Ok(EncodedCiphertext::<P>(arr))
    }
}

impl<P> Ciphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::ENCODED_CT_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{
}

impl<P> Ciphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::ENCODED_CT_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{
    pub(crate) fn new(
        fips_ct: &ml_kem::Ciphertext<P>,
        ss: &ml_kem::SharedKey<P>,
    ) -> Result<(bool, Self), IoError> {
        let mut kemeleon_ct = Self {
            encoded: false,
            bytes: vec![],
            fips: fips_ct.clone(),
        };

        // create the DRBG
        // TODO: initialize hmac_drbg using sharedkey and ml_kem ciphertext
        let mut drbg = HmacDRBG::<Sha256>::new(&ss[..], &fips_ct[..], b"");

        let encodable = kemeleon_ct.encode(&mut drbg)?;
        Ok((encodable, kemeleon_ct))
    }

    fn new_from_rng<R: RngCore + CryptoRng>(
        fips_ct: &ml_kem::Ciphertext<P>,
        rng: &mut R,
    ) -> Result<(bool, Self), IoError> {
        let mut kemeleon_ct = Self {
            encoded: false,
            bytes: vec![],
            fips: fips_ct.clone(),
        };

        let encodable = kemeleon_ct.encode(rng)?;
        Ok((encodable, kemeleon_ct))
    }

    fn encode<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<bool, IoError> {
        // split the u and v elements
        let (mut c1, c2) = split_fips_ct::<P>(&self.fips);
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
        let mut success = vector_encode(c1_u16, &mut dst)?;

        // TODO: check c2 for 0s and rejection sample based on probability
        // c2.for_each(|v| success &= ??? );
        success &= rejection_sample(c2, rng);

        self.bytes = concat_ct(&dst, c2).to_vec();

        Ok(success)
    }

    pub(crate) fn decode(c: impl AsRef<[u8]>) -> Result<Self, IoError>
    where
        [(); P::FIPS_ENCODED_USIZE]:,
        [(); P::FIPS_ENCODED_CT_SIZE]:,
    {
        let (c1, c2) = split_ct::<P>(c.as_ref());

        let mut values = [[0u16; ARR_LEN]; P::K];
        vector_decode::<P>(&c1, values.as_flattened_mut())
            .map_err(|e| IoError::other(format!("error occured while decoding {e}")))?;

        // re-compress the values
        let c1 = values.as_flattened_mut();
        c1.iter_mut().compress::<P>();

        // convert back to fips encoding of the U values
        let mut fips_ct = [0u8; P::FIPS_ENCODED_CT_SIZE];
        fips::byte_encode::<P, { P::DU }>(&values, &mut fips_ct[..P::FIPS_ENCODED_USIZE]);

        // ml_kem::Ciphertext = c1 || c2
        fips_ct[P::FIPS_ENCODED_USIZE..].copy_from_slice(c2);
        let fips = ml_kem::Ciphertext::<P>::try_from(&fips_ct[..])
            .map_err(|_| IoError::other("failed to parse as ciphertext"))?;

        Ok(Self {
            encoded: true,
            bytes: c.as_ref().to_vec(),
            fips,
        })
    }
}

fn u16_to_u8(x16: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(x16.len() * 2);
    x16.iter()
        .for_each(|&x| out.write_u16::<BigEndian>(x).unwrap());
    out
}

fn recover_rand<const D: usize>(i: u16, rng: &mut impl CryptoRngCore) -> u16 {
    // TODO: find values that do not modify u_i
    i
}

fn rejection_sample<R: CryptoRng + RngCore>(c2: &[u8], rng: &mut R) -> bool {
    // TODO: implement me
    true
}

fn split_fips_ct<P>(b: &[u8]) -> (&[u8], &[u8])
where
    P: EncodingSize,
{
    (
        &(b[..P::FIPS_ENCODED_USIZE]),
        &(b[P::FIPS_ENCODED_USIZE..P::FIPS_ENCODED_CT_SIZE]),
    )
}

// TODO: this is skeleton code
fn split_ct<P>(b: &[u8]) -> (&[u8], &[u8])
where
    P: EncodingSize,
{
    (
        &(b[..P::ENCODED_USIZE]),
        &(b[P::ENCODED_USIZE..P::ENCODED_CT_SIZE]),
    )
}

fn concat_ct<P>(u: &[u8], v: &[u8]) -> [u8; P::ENCODED_CT_SIZE]
where
    P: EncodingSize,
    [(); P::ENCODED_CT_SIZE]:,
{
    let mut out = [0u8; P::ENCODED_CT_SIZE];
    out[..P::ENCODED_USIZE].copy_from_slice(&u[..P::ENCODED_USIZE]);
    out[..P::ENCODED_VSIZE].copy_from_slice(&v[..P::ENCODED_VSIZE]);
    out
}

fn concat_fips_ct<P>(u: &[u8], v: &[u8]) -> [u8; P::FIPS_ENCODED_CT_SIZE]
where
    P: EncodingSize,
    [(); P::FIPS_ENCODED_CT_SIZE]:,
{
    let mut out = [0u8; P::FIPS_ENCODED_CT_SIZE];
    out[..P::FIPS_ENCODED_USIZE].copy_from_slice(&u[..P::FIPS_ENCODED_USIZE]);
    out[..P::FIPS_ENCODED_VSIZE].copy_from_slice(&v[..P::FIPS_ENCODED_VSIZE]);
    out
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mlkem::{KEncodedCiphertext, Kemx};

    use kem::{Decapsulate, Encapsulate};
    use ml_kem::{MlKem1024, MlKem512, MlKem768};

    fn encode_decode_trial<P>()
    where
        P: ml_kem::KemCore + EncodingSize,
        [(); P::K]:,
        [(); P::DU]:,
        [(); P::USIZE]:,
        [(); P::ENCODED_SIZE]:,
        [(); P::ENCODED_CT_SIZE]:,
        [(); P::FIPS_ENCODED_SIZE]:,
        [(); P::FIPS_ENCODED_USIZE]:,
        [(); P::FIPS_ENCODED_CT_SIZE]:,
    {
        let mut rng = rand::thread_rng();
        let (dk, ek) = Kemx::<P>::generate(&mut rng);

        // encapsulate a secret using the kemeleon Encapsulation key
        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();

        let ct_bytes = ct.as_bytes();
        let ct_bytes_recv = KEncodedCiphertext::try_from_bytes(ct_bytes)
            .expect("failed to parse KEncodedCiphertext");

        // and decapsulate using the kemeleon decapsulation key
        let k_recv = dk.decapsulate(&ct_bytes_recv).unwrap();
        // make sure the shared secret matches
        assert_eq!(k_send, k_recv);
        todo!("test not implemented yet");
    }

    #[test]
    fn encode_decode() {
        encode_decode_trial::<MlKem512>();
        encode_decode_trial::<MlKem768>();
        encode_decode_trial::<MlKem1024>();
    }
}
