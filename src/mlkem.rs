use core::fmt::Debug;
use std::{io::Error as IoError, marker::PhantomData};

use crate::{kemeleon::Encodable, EncodingSize, Transcode};

use kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, KemCore, SharedKey};
use rand_core::CryptoRngCore;

// ========================================================================== //
// Kem Equivalent object
// ========================================================================== //

/// Number of retries to generate a key pair that satisfies the Kemeleon criteria.
const MAX_RETRIES: usize = 64;

pub struct Kemx<P>
where
    P: ml_kem::KemCore,
{
    _p: PhantomData<P>,
}

impl<P> Kemx<P>
where
    P: ml_kem::KemCore + EncodingSize,
    [(); <P as EncodingSize>::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K]:,
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

#[derive(Debug, PartialEq, PartialOrd)]
pub struct KEncapsulationKey<P>
where
    P: KemCore,
{
    pub(crate) key: P::EncapsulationKey,
    pub(crate) byte: u8,
}

impl<P> KEncapsulationKey<P> where P: KemCore + EncodingSize {}

impl<P> Encapsulate<EncodedCiphertext<P>, SharedKey<P>> for KEncapsulationKey<P>
where
    P: KemCore,
{
    type Error = IoError;

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(EncodedCiphertext<P>, SharedKey<P>), Self::Error> {
        let (ek, ss) = self
            .key
            .encapsulate(rng)
            .map_err(|_| IoError::other("failed encapsulation"))?;
        Ok((EncodedCiphertext::<P>::from_fips(ek), ss))
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
// Decapsulation Key
// ========================================================================== //

#[derive(Debug, PartialEq, PartialOrd)]
pub struct KDecapsulationKey<P>(P::DecapsulationKey)
where
    P: KemCore;

impl<P> Decapsulate<EncodedCiphertext<P>, SharedKey<P>> for KDecapsulationKey<P>
where
    P: KemCore,
{
    type Error = <P::DecapsulationKey as Decapsulate<ml_kem::Ciphertext<P>, SharedKey<P>>>::Error;

    fn decapsulate(
        &self,
        encapsulated_key: &EncodedCiphertext<P>,
    ) -> Result<SharedKey<P>, Self::Error> {
        let ek = encapsulated_key.as_fips();
        self.0.decapsulate(ek)
    }
}

// ========================================================================== //
// Ciphertext encoding
// ========================================================================== //

#[derive(Debug, PartialEq, PartialOrd)]
pub struct EncodedCiphertext<P>
where
    P: KemCore,
{
    pub(crate) bytes: Vec<u8>,
    pub(crate) _p: PhantomData<P>,
}

// TODO this is likely incorrect / incomplete i just made it this way so it would
// compile so I could get tests compiling first.
impl<P> Transcode for EncodedCiphertext<P>
where
    P: KemCore,
{
    type Fips = ml_kem::Ciphertext<P>;

    fn as_fips(&self) -> &Self::Fips {
        #[allow(deprecated)]
        Self::Fips::from_slice(&self.bytes)
    }

    fn to_fips(self) -> Self::Fips {
        #[allow(deprecated)]
        Ciphertext::<P>::clone_from_slice(&self.bytes)
    }

    fn from_fips(t: Self::Fips) -> Self {
        Self {
            bytes: t.to_vec(),
            _p: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768};

    fn generate_trial<P>()
    where
        P: ml_kem::KemCore + EncodingSize,
        [(); <P as EncodingSize>::FIPS_ENCODED_SIZE]:,
        [(); <P as EncodingSize>::ENCODED_SIZE]:,
        [(); <P as EncodingSize>::K]:,
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
