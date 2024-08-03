use core::fmt::Debug;
use std::{io::Error as IoError, marker::PhantomData};

use crate::{
    kemeleon::KemeleonEk,
    EncodingSize,
    Transcode,
    // ValueArrayEncoder, ValueArray, ValueArrayDecoder,
};

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
    [(); <P as EncodingSize>::ENCODED_SIZE ]:,
{
    pub fn generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KDecapsulationKey<P>, KEncapsulationKey<P>), IoError> {
        // random u8 for the most significant byte which will be less than 8 bits.
        let msb_rand = rng.next_u32() as u8;

        for _ in 0..MAX_RETRIES {
            let (dk, ek) = P::generate(rng);
            let kek = KEncapsulationKey::<P> {
                key: ek,
                byte: msb_rand,
            };
            if kek.satisfies_sampling() {
                let kdk = KDecapsulationKey::<P>(dk);
                return Ok((kdk, kek));
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
    use crate::kemeleon::Encode;

    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem512};

    // #[test]
    // fn generate_keys_sampled() {
    //     let mut rng = rand::thread_rng();
    //     let (dk, ek) = generate_sampled::<MlKem512>(&mut rng).expect("key generation failed");

    //     let ek_encoded: Vec<u8> = ek.encode();
    //     let ek_decoded = <MlKem512 as KemCore>::EncapsulationKey::decode(&ek_encoded);

    //     assert_eq!(ek_decoded, ek);
    //     let (ct, k_send) = ek_decoded.encapsulate(&mut rng).unwrap();

    //     let k_recv = dk.decapsulate(&ct).unwrap();
    //     assert_eq!(k_send, k_recv);
    // }

    #[test]
    fn generate_normal() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = crate::MlKem512::generate(&mut rng).expect("keygen failed");

        let ek_encoded: Vec<u8> = ek.as_bytes().to_vec();

        #[allow(deprecated)]
        let ek_bytes =
            Encoded::<<MlKem512 as ml_kem::KemCore>::EncapsulationKey>::from_slice(&ek_encoded);
        let ek_decoded = <MlKem512 as KemCore>::EncapsulationKey::from_bytes(ek_bytes);

        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
        assert_eq!(ek_decoded, ek.to_fips());

        // let ct = Ciphertext::<MlKem512>::from_bytes(ct);
        let k_recv = dk.decapsulate(&ct).unwrap();
        assert_eq!(k_send, k_recv);
    }
}
