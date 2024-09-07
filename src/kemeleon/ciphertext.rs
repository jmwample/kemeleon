use super::{vector_decode, vector_encode, Encode};
use crate::{fips, FieldElement};
use crate::{Barr8, EncodeError, EncodingSize, FipsEncodingSize, ARR_LEN};

use ml_kem::KemCore;
use rand::{CryptoRng, RngCore};
use rand_core::CryptoRngCore;
use sha2::Sha256;

mod compress;
use compress::{Compress, Du};
mod precomputed;
use precomputed::get_eq_set;
mod hkdf_rng;
use hkdf_rng::HkdfRng;

// ========================================================================== //
// CipherText
// ========================================================================== //

pub use crate::mlkem::KCiphertext as Ciphertext;
#[allow(clippy::module_name_repetitions)]
pub use crate::mlkem::KEncodedCiphertext as EncodedCiphertext;

impl<P> Encode for EncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
{
    /// Encoded Cuphertext Type
    type ET = Barr8<{ P::ENCODED_CT_SIZE }>;

    /// Error Type returned on failed decode
    type Error = EncodeError;

    fn as_bytes(&self) -> Self::ET {
        self.0
    }

    fn try_from_bytes(b: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        if b.as_ref().is_empty() {
            return Err(EncodeError::invalid_ctxt_len(0_usize));
        } else if b.as_ref().len() < P::ENCODED_CT_SIZE {
            return Err(EncodeError::invalid_ctxt_len(b.as_ref().len()));
        }
        let mut arr = [0u8; P::ENCODED_CT_SIZE];
        arr.copy_from_slice(&b.as_ref()[..P::ENCODED_CT_SIZE]);

        Ok(EncodedCiphertext::<P>(arr))
    }
}

const HKDF_INFO: [u8; 40] = *b"kemeleon ct hkdf random number generator";

impl<P> Ciphertext<P>
where
    P: KemCore + EncodingSize,
{
    pub(crate) fn new(
        fips_ct: &ml_kem::Ciphertext<P>,
        ss: &ml_kem::SharedKey<P>,
    ) -> Result<(bool, Self), EncodeError> {
        let mut kemeleon_ct = Self {
            encoded: false,
            bytes: [0u8; P::ENCODED_CT_SIZE],
            fips: fips_ct.clone(),
        };

        // create the DRBG using sharedkey and ml_kem ciphertext
        let mut rng = HkdfRng::<Sha256>::new(ss, fips_ct, &HKDF_INFO);

        let encodable = kemeleon_ct.encode(&mut rng)?;
        Ok((encodable, kemeleon_ct))
    }

    // TODO: find a good way to expose this
    #[allow(dead_code)]
    fn new_from_rng<R: RngCore + CryptoRng>(
        fips_ct: &ml_kem::Ciphertext<P>,
        rng: &mut R,
    ) -> Result<(bool, Self), EncodeError> {
        let mut kemeleon_ct = Self {
            encoded: false,
            bytes: [0u8; P::ENCODED_CT_SIZE],
            fips: fips_ct.clone(),
        };

        let encodable = kemeleon_ct.encode(rng)?;
        Ok((encodable, kemeleon_ct))
    }

    fn encode<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<bool, EncodeError> {
        // split the u and v elements
        let (c1, c2) = split_fips_ct::<P>(&self.fips);
        let mut r1: [[u16; ARR_LEN]; P::K] = fips::byte_decode::<P, { P::DU }>(&c1);

        // re-add randomness to the u elements
        r1.as_flattened_mut()
            .iter_mut()
            .decompress::<Du<{ P::DU }>>();
        for u_i in r1.as_flattened_mut().iter_mut() {
            *u_i = recover_rand::<{ P::DU }>(*u_i, rng);
        }

        // encode the u elements
        let mut dst = [0u8; P::ENCODED_CT_SIZE];
        let mut success = vector_encode(r1.as_flattened(), &mut dst)?;

        // Check c2 for 0s and rejection sample based on probability
        success &= rejection_sample(c2, rng, P::DV);

        self.bytes = concat_ct(&dst, c2);
        Ok(success)
    }

    pub(crate) fn decode(c: impl AsRef<[u8]>) -> Result<Self, EncodeError> {
        let mut ct_bytes = [0u8; P::ENCODED_CT_SIZE];
        ct_bytes[..].copy_from_slice(&c.as_ref()[..P::ENCODED_CT_SIZE]);
        let (c1, c2) = split_ct::<P>(&ct_bytes);

        let mut values = [[0u16; ARR_LEN]; P::K];
        vector_decode::<P>(&c1, values.as_flattened_mut())?;

        // re-compress the values
        let c1 = values.as_flattened_mut();
        c1.iter_mut().compress::<Du<{ P::DU }>>();

        // convert back to fips encoding of the U values
        let mut fips_ct = [0u8; P::FIPS_ENCODED_CT_SIZE];
        fips::byte_encode::<P, { P::DU }>(&values, &mut fips_ct[..P::FIPS_ENCODED_USIZE]);

        // ml_kem::Ciphertext = c1 || c2
        fips_ct[P::FIPS_ENCODED_USIZE..].copy_from_slice(c2);
        let fips =
            ml_kem::Ciphertext::<P>::try_from(&fips_ct[..]).map_err(EncodeError::MlKemError)?;

        Ok(Self {
            encoded: true,
            bytes: ct_bytes,
            fips,
        })
    }
}

#[allow(clippy::integer_division_remainder_used)]
fn recover_rand<const DU: usize>(i: u16, rng: &mut impl CryptoRngCore) -> u16 {
    let mut compressed_i = i;
    compressed_i.compress::<Du<DU>>();
    let eq_set = get_eq_set::<DU>(compressed_i);

    let mut b = [0u8; 2];
    rng.fill_bytes(&mut b);
    let idx = u16::from_be_bytes(b) % eq_set.len() as u16;

    eq_set[idx as usize]
}

#[allow(clippy::integer_division_remainder_used)]
fn rejection_sample<R: CryptoRng + RngCore>(c2: &[u8], rng: &mut R, dv: usize) -> bool {
    let lim = 2_u16.pow(dv as u32);
    let mut b = [0u8; 2];
    for val in fips::ct_vdecompress(dv, c2) {
        rng.fill_bytes(&mut b);
        let y = u16::from_be_bytes(b);
        if val == 0 && y % FieldElement::Q < lim {
            return false;
        }
    }
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
{
    let mut out = [0u8; P::ENCODED_CT_SIZE];
    out[..P::ENCODED_USIZE].copy_from_slice(&u[..P::ENCODED_USIZE]);
    out[P::ENCODED_USIZE..P::ENCODED_CT_SIZE].copy_from_slice(&v[..P::ENCODED_VSIZE]);
    out
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mlkem::{KCiphertext, KEncodedCiphertext, Kemx, MAX_RETRIES};

    use kem::{Decapsulate, Encapsulate};
    use ml_kem::{MlKem1024, MlKem512, MlKem768};

    fn encode_decode_trial<P>(desc: &str)
    where
        P: ml_kem::KemCore + EncodingSize,
    {
        let mut rng = rand::thread_rng();
        // use Kemx::generate so that we don't have to worry about the
        // encapsulation key being encodable.
        let (dk, ek) = Kemx::<P>::generate(&mut rng);

        // >>> Because we are doing a FIPS encapsulation and manually encoding we have to
        // >>> sample the rng ourselves in case we generate an unencodable ciphertext.

        // encapsulate a secret using the kemeleon Encapsulation key
        let (mut ct, mut k_send) = ek.key.encapsulate(&mut rng).unwrap();
        // attempt to encode the ciphertext to kemeleon representation
        let (mut encodable, mut kemeleon_ct) =
            KCiphertext::new_from_rng(&ct, &mut rng).expect("failed to make new ciphertext");

        let mut i = 0;
        while !encodable && i < MAX_RETRIES {
            // encapsulate a secret using the kemeleon Encapsulation key
            // if our previous ct was not encodable - pick a new one
            (ct, k_send) = ek.key.encapsulate(&mut rng).unwrap();

            // attempt to encode the ciphertext to kemeleon representation
            (encodable, kemeleon_ct) =
                KCiphertext::new_from_rng(&ct, &mut rng).expect("failed to make new ciphertext");

            i += 1;
        }
        assert!(
            i < MAX_RETRIES,
            "{desc}: failed to find an encodable ciphertext - not possible"
        );
        // <<<
        // <<<

        let ct_bytes = kemeleon_ct.bytes;
        let ct_bytes_recv = KEncodedCiphertext::try_from_bytes(ct_bytes)
            .unwrap_or_else(|e| panic!("{desc} failed to parse KEncodedCiphertext {e}"));

        let ct_recv = KCiphertext::decode(&ct_bytes_recv)
            .unwrap_or_else(|e| panic!("{desc}: failed decode {e}"));
        assert_eq!(ct_recv.fips, ct, "{desc}: fips ciphertexts don't match");

        // decapsulate using the kemeleon decapsulation key
        // make sure the shared secret matches
        let k_recv = dk.decapsulate(&ct_bytes_recv).unwrap();
        assert_eq!(
            k_send, k_recv,
            "{desc}: derived fips shared keys don't match"
        );
    }

    #[test]
    fn encode_decode_ct() {
        encode_decode_trial::<MlKem512>("MlKem512 Du:10, Dv:4");
        encode_decode_trial::<MlKem768>("MlKem768 Du:10, Dv:4");
        encode_decode_trial::<MlKem1024>("MlKem1024 Du:11, Dv:5");
    }
}
