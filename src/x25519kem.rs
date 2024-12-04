//! Obfuscated X25519 KEM using Elligator2
//!
//! Implements the `kem::{Encapsulate, Decapsulate}` traits.
//!

use crate::OKemCore;

use dhkem::{DhKem, X25519Kem};

mod x25519_elligator2;
use x25519_elligator2::ReusableSecret;

impl OKemCore for X25519Kem {
    type OkemError = ();
    type SharedKey = <Self as DhKem>::SharedSecret;
    type Ciphertext = <Self as DhKem>::EncapsulatedKey;
    type DecapsulationKey = <Self as DhKem>::DecapsulatingKey;
    type EncapsulationKey = <Self as DhKem>::EncapsulatedKey;

    fn generate(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        todo!("coming soon _tm_");
    }

    fn try_generate(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::OkemError> {
        todo!("its too late");
    }

    fn encapsulation_key(dk: &Self::DecapsulationKey) -> Self::EncapsulationKey {
        todo!("howdy partner");
    }
}


