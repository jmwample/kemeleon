use core::fmt::Debug;
use std::io::Error as IoError;

use crate::Kemx;

use hybrid_array::{typenum::U32, Array};
use kem::{Decapsulate, Encapsulate};
#[cfg(feature = "deterministic")]
use ml_kem::EncapsulateDeterministic;
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, SharedKey};
use rand_core::CryptoRngCore;

/// Number of retries to generate a key pair that satisfies the Kemeleon criteria.
const MAX_RETRIES: usize = 64;

#[cfg(not(feature = "deterministic"))]
impl<P> ml_kem::KemCore for Kemx<P>
where
    P: KemCore,
    <P as KemCore>::DecapsulationKey:
        Decapsulate<Ciphertext<P>, SharedKey<P>> + EncodedSizeUser + Debug + PartialEq,
    <P as KemCore>::DecapsulationKey:
        Decapsulate<Array<u8, <P as KemCore>::CiphertextSize>, Array<u8, U32>>,
    <P as KemCore>::EncapsulationKey:
        Encapsulate<Ciphertext<P>, SharedKey<P>> + EncodedSizeUser + Debug + PartialEq,
    <P as KemCore>::EncapsulationKey:
        Encapsulate<Array<u8, <P as KemCore>::CiphertextSize>, Array<u8, U32>>,
{
    type SharedKeySize = U32;
    type CiphertextSize = P::CiphertextSize;
    type DecapsulationKey = P::DecapsulationKey;
    type EncapsulationKey = P::EncapsulationKey;

    /// Generate a new (decapsulation, encapsulation) key pair
    fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        // let most_sign_byte_rand = rng.next_u32() as u8;

        for _ in 0..MAX_RETRIES {
            let (dk, ek) = P::generate(rng);
            if can_encode::<P>(&ek) {
                return (dk, ek);
            }

            continue;
        }
        panic!("failed to generate key - you have a bad random number generator")
    }
}

fn can_encode<P>(ek: &P::EncapsulationKey) -> bool
where
    P: KemCore,
{
    true

}

#[cfg(feature = "deterministic")]
impl<P> ml_kem::KemCore for Kemx<P>
where
    P: KemCore + EncodingSize + ParameterSet,
    <P as KemCore>::DecapsulationKey:
        Decapsulate<Ciphertext<P>, SharedKey<P>> + EncodedSizeUser + Debug + PartialEq,
    <P as KemCore>::EncapsulationKey: Encapsulate<Ciphertext<P>, SharedKey<P>>
        + EncapsulateDeterministic<Ciphertext<P>, SharedKey<P>>
        + EncodedSizeUser
        + Debug
        + PartialEq,
{
    type SharedKeySize = U32;
    type CiphertextSize = P::CiphertextSize;
    type DecapsulationKey = P::DecapsulationKey;
    type EncapsulationKey = P::EncapsulationKey;

    /// Generate a new (decapsulation, encapsulation) key pair
    fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (dk, ek) = P::generate(rng);
        (dk, ek)
    }

    #[cfg(feature = "deterministic")]
    fn generate_deterministic(
        d: &B32,
        z: &B32,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = P::generate_deterministic(d, z);
        let ek = dk.encapsulation_key().clone();
        (dk, ek)
    }
}

trait KemeleonEk {
    type EK;
    type Error;

    fn can_encode(&self) -> bool;

    fn encode(&self) -> Vec<u8>;

    fn decode(c: impl AsRef<[u8]>) -> Result<Self::EK, Self::Error>;
}

struct KEncapsulationKey<P>
where
    P: KemCore,
{
    key: P::EncapsulationKey,
    byte: u8,
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


impl<P, SS> ::kem::Encapsulate<Self, SS> for KEncapsulationKey<P>
where
    P: KemCore,
{
    type Error = IoError;

    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(Self, SS), Self::Error> {
        Err(IoError::other("not implemented"))
    }
}

// fn generate_sampled<P>(
//     rng: &mut impl CryptoRngCore,
// ) -> Result<(P::DecapsulationKey, P::EncapsulationKey), IoError>
// where
//     P: KemCore,
// {
//     let most_sign_byte_rand = rng.next_u32() as u8;
//
//     for i in 0..MAX_RETRIES {
//         let (dk, ek) = P::generate(rng);
//         if ek.can_encode() {
//             return Ok((dk, ek));
//         }
//
//         continue
//     }
//     Err(IoError::other("oops not implemented yet"))
// }

#[cfg(test)]
mod test {
    use crate::Kemx;
    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem512};
    use kem::{Encapsulate, Decapsulate};

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
        let (dk, ek) = Kemx::<MlKem512>::generate(&mut rng);

        let ek_encoded: Vec<u8> = ek.as_bytes().to_vec();

        #[allow(deprecated)]
        let ek_bytes =
            Encoded::<<MlKem512 as ml_kem::KemCore>::EncapsulationKey>::from_slice(&ek_encoded);
        let ek_decoded = <MlKem512 as KemCore>::EncapsulationKey::from_bytes(ek_bytes);

        assert_eq!(ek_decoded, ek);
        let (ct, k_send) = ek_decoded.encapsulate(&mut rng).unwrap();

        let k_recv = dk.decapsulate(&ct).unwrap();
        assert_eq!(k_send, k_recv);
    }
}
