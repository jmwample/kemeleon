use crate::{fips, kemeleon::Encodable, EncodingSize, FipsEncodingSize, Transcode, ARR_LEN};

use core::fmt::Debug;
use std::{io::Error as IoError, marker::PhantomData};

#[cfg(feature = "deterministic")]
use ml_kem::B32;
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, SharedKey, EncapsulateDeterministic};
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;

// ========================================================================== //
// Kem Equivalent object
// ========================================================================== //


/// Number of retries to generate a key pair that satisfies the Kemeleon criteria.
pub(crate) const MAX_RETRIES: usize = 64;

#[derive(Debug, PartialEq, PartialOrd)]
pub struct Kemx<P>
where
    P: ml_kem::KemCore,
{
    _p: PhantomData<P>,
}

impl<P> Kemx<P>
where
    P: ml_kem::KemCore + EncodingSize,
    [(); <P as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K]:,
    [(); P::USIZE]:,
{
    pub fn generate(rng: &mut impl CryptoRngCore) -> (KDecapsulationKey<P>, KEncapsulationKey<P>) {
        // random u8 for the most significant byte which will be less than 8 bits.
        let msb_rand = rng.next_u32() as u8;

        for _ in 0..MAX_RETRIES {
            let (dk, ek) = P::generate(rng);
            let encap_key = KEncapsulationKey::<P> {
                key: ek,
                byte: msb_rand,
            };
            if encap_key.satisfies_sampling() {
                let decap_key = KDecapsulationKey::<P>(dk);
                return (decap_key, encap_key);
            }

            continue;
        }
        panic!("failed to generate key - you have a bad random number generator")
    }
}

// ========================================================================== //
// Encapsulation Key
// ========================================================================== //

// TODO: store the local representation created by from_fips so that we don't
// have to compute it if we re-use the key for some reason (or call as_bytes
// more than once).
/// An `EncapsulationKey` provides the ability to encapsulate a shared key so that
/// it can only be decapsulated by the holder of the corresponding decapsulation key.
#[derive(Debug, PartialEq, PartialOrd)]
pub struct KEncapsulationKey<P>
where
    P: KemCore,
{
    pub(crate) key: P::EncapsulationKey,
    pub(crate) byte: u8,
}

impl<P> KEncapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); P::FIPS_ENCODED_SIZE]:,
    [(); P::USIZE]:,
{
    // TODO: must use for now -- not sure it this will stay
    #[must_use]
    pub fn from_parts(t_hat: &[[u16; ARR_LEN]; P::K], rho: &[u8; 32], mask_byte: u8) -> Self {
        let ek_fb = fips::ek_encode(rho, t_hat);
        Self::from_fips_bytes(ek_fb, mask_byte)
    }

    // TODO: should this be a Result since a key of improper length could panic?
    pub fn from_fips_bytes(ek_fb: impl AsRef<[u8]>, mask_byte: u8) -> Self {
        let ek_fb_e = Encoded::<<P as KemCore>::EncapsulationKey>::try_from(ek_fb.as_ref())
            .map_err(|e| IoError::other(format!("failed to convert to hybrid_array::Array: {e}")))
            .unwrap();
        let key = <P as KemCore>::EncapsulationKey::from_bytes(&ek_fb_e);
        Self {
            key,
            byte: mask_byte,
        }
    }
}

impl<P> Encapsulate<KEncodedCiphertext<P>, SharedKey<P>> for KEncapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::ENCODED_CT_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{
    type Error = IoError;

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KEncodedCiphertext<P>, SharedKey<P>), Self::Error> {
        let (ek, ss) = self
            .key
            .encapsulate(rng)
            .map_err(|_| IoError::other("failed encapsulation"))?;
        let (success, ct) = KCiphertext::<P>::new(&ek, &ss)?;

        if !success {
            Err(NotEncodable)
        }

        return Ok((KEncodedCiphertext(ct.bytes), ss));
    }
}

#[cfg(feature = "deterministic")]
impl<P> EncapsulateDeterministic<KEncodedCiphertext<P>, SharedKey<P>> for KEncapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::ENCODED_CT_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{
    type Error = IoError;

    // Required method
    fn encapsulate_deterministic(&self, m: &B32) -> Result<(KEncodedCiphertext<P>, SharedKey<P>), Self::Error> {
        for _ in 0..MAX_RETRIES {
            let (ek, ss) = self
                .key
                .encapsulate_deterministic(m)
                .map_err(|_| IoError::other("failed encapsulation"))?;
            let (success, ct) = KCiphertext::<P>::new(&ek, &ss)?;

            if !success {
                continue;
            }

            return Ok((KEncodedCiphertext(ct.bytes), ss));
        }
        panic!("failed to generate shared secret and encapsulate - you have a bad random number generator")
    }
}

impl<P> Transcode for KEncapsulationKey<P>
where
    P: KemCore + EncodingSize,
{
    type Fips = <P as KemCore>::EncapsulationKey;

    fn as_fips(&self) -> &Self::Fips {
        &self.key
    }

    fn to_fips(self) -> Self::Fips {
        self.key
    }

    fn from_fips(t: Self::Fips) -> Self {
        Self {
            key: t,
            byte: 0x00u8,
        }
    }
}

// ========================================================================== //
// Ciphertext encoding
// ========================================================================== //

/// A ciphertext produced by the KEM `K`
#[derive(Debug, PartialEq, PartialOrd)]
pub struct KCiphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::ENCODED_CT_SIZE]:,
{
    pub(crate) encoded: bool,
    pub(crate) bytes: [u8; P::ENCODED_CT_SIZE],
    pub(crate) fips: Ciphertext<P>,
}

pub struct KEncodedCiphertext<P>(pub(crate) [u8; P::ENCODED_CT_SIZE])
where
    P: KemCore + EncodingSize,
    [(); P::ENCODED_CT_SIZE]:;

impl<P> AsRef<[u8]> for KEncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::ENCODED_CT_SIZE]:,
{
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ========================================================================== //
// Decapsulation Key
// ========================================================================== //

/// A `DecapsulationKey` provides the ability to generate a new key pair, and decapsulate an encapsulated shared key.
#[derive(Debug, PartialEq, PartialOrd)]
pub struct KDecapsulationKey<P>(P::DecapsulationKey)
where
    P: KemCore;

impl<P> Decapsulate<KEncodedCiphertext<P>, SharedKey<P>> for KDecapsulationKey<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::ENCODED_CT_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
    [(); P::FIPS_ENCODED_USIZE]:,
    [(); P::FIPS_ENCODED_CT_SIZE]:,
{
    type Error = IoError; //<P::DecapsulationKey as Decapsulate<ml_kem::Ciphertext<P>, SharedKey<P>>>::Error;

    fn decapsulate(&self, ciphertext: &KEncodedCiphertext<P>) -> Result<SharedKey<P>, Self::Error> {
        let ct = KCiphertext::decode(ciphertext)?;
        let k_send = ct.fips;
        self.0
            .decapsulate(&k_send)
            .map_err(|e| IoError::other(format!("failed to decapsulate: {e:?}")))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768};

    fn generate_trial<P>()
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

        // To Fips Encoding and back
        let ek_encoded: Vec<u8> = ek.key.as_bytes().to_vec();
        let ek_bytes = Encoded::<<P as KemCore>::EncapsulationKey>::try_from(&ek_encoded[..])
            .expect("failed to create hybrid_array::Array");
        let ek_decoded = <P as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
        // make sure recovered key matches the original
        assert_eq!(&ek_decoded, ek.as_fips());

        // encapsulate a secret using the kemeleon Encapsulation key
        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
        // and decapsulate using the kemeleon decapsulation key
        let k_recv = dk.decapsulate(&ct).unwrap();
        // make sure the shared secret matches
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn generate_keys_sampled() {
        generate_trial::<MlKem512>();
        generate_trial::<MlKem768>();
        generate_trial::<MlKem1024>();
    }
}
