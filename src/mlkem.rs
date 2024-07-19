use core::fmt::Debug;
use std::{io::Error as IoError, marker::PhantomData};

use crate::{
    fips, kemeleon::Kemeleon, EncodingSize, Transcode, ValueArray, ValueArrayDecoder,
    ValueArrayEncoder,
};

use kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, SharedKey};
use rand_core::CryptoRngCore;

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
    P: ml_kem::KemCore,
{
    pub fn generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KDecapsulationKey<P>, KEncapsulationKey<P>), IoError> {
        // random u8 for the most significant byte which will be less than 8 bits.
        let msb_rand = rng.next_u32() as u8;

        for _ in 0..MAX_RETRIES {
            let (dk, ek) = P::generate(rng);
            if can_encode::<P>(&ek) {
                let kek = KEncapsulationKey::<P> {
                    key: ek,
                    byte: msb_rand,
                };
                let kdk = KDecapsulationKey::<P>(dk);
                return Ok((kdk, kek));
            }

            continue;
        }
        panic!("failed to generate key - you have a bad random number generator")
    }

    /// Live, Laugh Lobotomy. The ValueArray needs to be made generic somehow.
    pub fn encode_ek<A: ValueArrayEncoder>(p: &ValueArray) -> Vec<u8> {
        A::encode(p)
    }

    /// Live, Laugh Lobotomy. The ValueArray needs to be made generic somehow.
    pub fn decode_ek<A: ValueArrayDecoder>(c: impl AsRef<[u8]>) -> Result<ValueArray, IoError> {
        A::decode(c)
    }

    /// Encode an ML-Kem CipherText into a wire format byte array using specific
    /// algorithm `A`.
    pub fn encode_ct<A>(p: Vec<u8>) -> Vec<u8> {
        p
    }

    /// Decode an ML-Kem CipherText from a wire format byte array using specific
    /// algorithm `A`.
    pub fn decode_ct<A: ValueArrayDecoder>(c: impl AsRef<[u8]>) -> Result<ValueArray, IoError> {
        A::decode(c)
    }
}

fn can_encode<P>(ek: &P::EncapsulationKey) -> bool
where
    P: KemCore,
{
    true
}

trait KemeleonEk {
    type EK;
    type Error;

    fn can_encode(&self) -> bool;

    fn encode(&self) -> Vec<u8>;

    fn decode(c: impl AsRef<[u8]>) -> Result<Self::EK, Self::Error>;
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct KEncapsulationKey<P>
where
    P: KemCore,
{
    key: P::EncapsulationKey,
    byte: u8,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct KDecapsulationKey<P>(P::DecapsulationKey)
where
    P: KemCore;

#[derive(Debug, PartialEq, PartialOrd)]
pub struct EncodedCiphertext<P>
where
    P: KemCore,
{
    bytes: Vec<u8>,
    _p: PhantomData<P>,
}

impl<P> EncodedCiphertext<P>
where
    P: KemCore,
{
    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn from_bytes(b: impl AsRef<[u8]>) -> Result<Self, IoError> {
        if b.as_ref().is_empty() {
            return Err(IoError::other("bad bytestring provided"));
        }
        Ok(Self {
            bytes: b.as_ref().to_vec(),
            _p: PhantomData,
        })
    }
}

impl<P> KEncapsulationKey<P>
where
    P: KemCore + EncodingSize,
{
    pub fn as_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    pub fn from_bytes(b: impl AsRef<[u8]>) -> Result<Self, IoError> {
        if b.as_ref().is_empty() {
            return Err(IoError::other("bad bytestring provided"));
        }

        // try decode as kemeleon
        let kek = Kemeleon::decode(b)?;

        // re-encode as fips
        let fips = fips::byte_encode::<P>(&kek);

        // parse as an ml-kem::EncapsulationKey
        #[allow(deprecated)]
        let ek_bytes = Encoded::<<P as KemCore>::EncapsulationKey>::from_slice(&fips);
        let key = <P as KemCore>::EncapsulationKey::from_bytes(ek_bytes);

        Ok(Self { key, byte: 0x00 })
    }
}

impl<P> KemeleonEk for KEncapsulationKey<P>
where
    P: KemCore,
{
    type EK = Self;
    type Error = IoError;

    fn encode(&self) -> Vec<u8> {
        vec![]
    }

    fn decode(c: impl AsRef<[u8]>) -> Result<Self::EK, Self::Error> {
        #[allow(deprecated)] // I don't understand what they want for the TryFrom format.
        let ek_bytes = Encoded::<<P as KemCore>::EncapsulationKey>::from_slice(c.as_ref());
        let key = <P as KemCore>::EncapsulationKey::from_bytes(ek_bytes);

        Ok(KEncapsulationKey { key, byte: 0x00 })
    }

    fn can_encode(&self) -> bool {
        true
    }
}

impl<P> Encapsulate<EncodedCiphertext<P>, SharedKey<P>> for KEncapsulationKey<P>
where
    P: KemCore,
{
    type Error = IoError;

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(EncodedCiphertext<P>, SharedKey<P>), Self::Error> {
        EncodedCiphertext::<P>::from_fips(self.key.encapsulate(rng))
    }
}

impl<P> Decapsulate<EncodedCiphertext<P>, SharedKey<P>> for KDecapsulationKey<P>
where
    P: KemCore,
{
    type Error = <P::DecapsulationKey as Decapsulate<ml_kem::Ciphertext<P>, SharedKey<P>>>::Error;

    fn decapsulate(
        &self,
        encapsulated_key: &EncodedCiphertext<P>,
    ) -> Result<SharedKey<P>, Self::Error> {
        let ek = encapsulated_key.to_fips();
        self.0.decapsulate(ek)
    }
}

impl<P> Transcode for KEncapsulationKey<P>
where
    P: KemCore + EncodingSize,
{
    type Fips = <P as KemCore>::EncapsulationKey;
    fn to_fips(&self) -> Self::Fips {}

    fn from_fips(t: &Self::Fips) -> Self {}
}

impl<P> Transcode for EncodedCiphertext<P>
where
    P: KemCore,
    <P as KemCore>::CiphertextSize: EncodedSizeUser,
{
    type Fips = ml_kem::Ciphertext<P>;

    fn to_fips(&self) -> Self::Fips {
        
    }

    fn from_fips(t: &Self::Fips) -> Self {
        
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
        let (dk, ek) = Kemx::<MlKem512>::generate(&mut rng).expect("keygen failed");

        let ek_encoded: Vec<u8> = ek.as_bytes().to_vec();

        #[allow(deprecated)]
        let ek_bytes =
            Encoded::<<MlKem512 as ml_kem::KemCore>::EncapsulationKey>::from_slice(&ek_encoded);
        let ek_decoded = <MlKem512 as KemCore>::EncapsulationKey::from_bytes(ek_bytes);

        assert_eq!(ek_decoded, ek.to_fips());
        let (ct, k_send) = ek_decoded.encapsulate(&mut rng).unwrap();

        let k_recv = dk.decapsulate(&ct.to_fips()).unwrap();
        assert_eq!(k_send, k_recv);
    }
}

// impl<EK, P> KemeleonEk<EK> for P::EncapsulationKey
// where
//     P: KemCore,
//     EK: Encapsulate<Ciphertext<P>, SharedKey<P>> + EncodedSizeUser + Debug + PartialEq,
//     EK: Encapsulate<Array<u8, <P as KemCore>::CiphertextSize>, Array<u8, U32>>,
// {
//     fn can_encode(&self) -> bool {
//         true
//     }
//
//     fn encode(&self) -> Vec<u8> {
//         self.as_bytes().to_vec()
//     }
//
//     fn decode(c: impl AsRef<[u8]>) -> Self {
//         #[allow(deprecated)] // I don't understand what they want for the TryFrom format.
//         let ek_bytes = Encoded::<P::EncapsulationKey>::from_slice(c.as_ref());
//         <P as KemCore>::EncapsulationKey::from_bytes(ek_bytes)
//     }
// }

// #[cfg(not(feature = "deterministic"))]
// impl<P> ml_kem::KemCore for Kemx<P>
// where
//     P: KemCore,
//     <P as KemCore>::DecapsulationKey:
//         Decapsulate<Ciphertext<P>, SharedKey<P>> + EncodedSizeUser + Debug + PartialEq,
//     <P as KemCore>::DecapsulationKey:
//         Decapsulate<Array<u8, <P as KemCore>::CiphertextSize>, Array<u8, U32>>,
//     <P as KemCore>::EncapsulationKey:
//         Encapsulate<Ciphertext<P>, SharedKey<P>> + EncodedSizeUser + Debug + PartialEq,
//     <P as KemCore>::EncapsulationKey:
//         Encapsulate<Array<u8, <P as KemCore>::CiphertextSize>, Array<u8, U32>>,
// {
//     type SharedKeySize = U32;
//     type CiphertextSize = P::CiphertextSize;
//     type DecapsulationKey = P::DecapsulationKey;
//     type EncapsulationKey = P::EncapsulationKey;
//
//     /// Generate a new (decapsulation, encapsulation) key pair
//     fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         // let most_sign_byte_rand = rng.next_u32() as u8;
//
//         for _ in 0..MAX_RETRIES {
//             let (dk, ek) = P::generate(rng);
//             if can_encode::<P>(&ek) {
//                 return (dk, ek);
//             }
//
//             continue;
//         }
//         panic!("failed to generate key - you have a bad random number generator")
//     }
// }
//
// #[cfg(feature = "deterministic")]
// impl<P> ml_kem::KemCore for Kemx<P>
// where
//     P: KemCore + EncodingSize + ParameterSet,
//     <P as KemCore>::DecapsulationKey:
//         Decapsulate<Ciphertext<P>, SharedKey<P>> + EncodedSizeUser + Debug + PartialEq,
//     <P as KemCore>::EncapsulationKey: Encapsulate<Ciphertext<P>, SharedKey<P>>
//         + EncapsulateDeterministic<Ciphertext<P>, SharedKey<P>>
//         + EncodedSizeUser
//         + Debug
//         + PartialEq,
// {
//     type SharedKeySize = U32;
//     type CiphertextSize = P::CiphertextSize;
//     type DecapsulationKey = P::DecapsulationKey;
//     type EncapsulationKey = P::EncapsulationKey;
//
//     /// Generate a new (decapsulation, encapsulation) key pair
//     fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         let (dk, ek) = P::generate(rng);
//         (dk, ek)
//     }
//
//     #[cfg(feature = "deterministic")]
//     fn generate_deterministic(
//         d: &B32,
//         z: &B32,
//     ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         let dk = P::generate_deterministic(d, z);
//         let ek = dk.encapsulation_key().clone();
//         (dk, ek)
//     }
// }
