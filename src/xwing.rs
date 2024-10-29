//! Obfuscated X-Wing using Kemeleon and Elligator2
//!
//! Implements the `kem::{Encapsulate, Decapsulate}` traits.
//!
//! Kemeleon for ML-KEM encoding and Elligator2 for X25519 Encoding.
//!

use rand_core::CryptoRngCore;

// Re-export traits from the `kem` crate
pub use ::kem::{Decapsulate, Encapsulate};

/// Size in bytes of the Ciphertext.
pub const CIPHERTEXT_SIZE: usize = 1284;
/// Size in bytes of the DecapsulationKey.
pub const DECAPSULATION_KEY_SIZE: usize = 32;
/// Size in bytes of the EncapsulationKey.
pub const ENCAPSULATION_KEY_SIZE: usize = 1188;

/// Shared secret value
pub type SharedSecret = [u8; 32];

/// Public key used to encapsulate a shared secret value in a KEM scheme.
#[derive(Clone, PartialEq)]
pub struct EncapsulationKey {}

impl Encapsulate<Ciphertext, SharedSecret> for EncapsulationKey {
    type Error = ();
    fn encapsulate(
        &self,
        _: &mut impl CryptoRngCore,
    ) -> Result<(Ciphertext, SharedSecret), Self::Error> {
        todo!()
    }
}

impl EncapsulationKey {
    /// Convert the key to the following format:
    /// Kemeleon encoded ML-KEM-768 public key(1156 bytes) | Elligator2 encoded X25519 public key(32 bytes).
    pub fn as_bytes(&self) -> [u8; ENCAPSULATION_KEY_SIZE] {
        [0u8; ENCAPSULATION_KEY_SIZE]
    }

    /// Attempt to parse an Encapsulation Key from a bytes like object. The value must be formatted as:
    /// Kemeleon encoded ML-KEM-768 public key(1156 bytes) | Elligator2 encoded X25519 public key(32 bytes).
    pub fn try_from_bytes(buf: impl AsRef<[u8]>) -> Result<Self, ()> {
        Ok(Self {})
    }
}

impl TryFrom<&[u8; ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    type Error = ();
    fn try_from(value: &[u8; ENCAPSULATION_KEY_SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(value)
    }
}

impl TryFrom<x_wing::EncapsulationKey> for EncapsulationKey {
    type Error = ();
    fn try_from(value: x_wing::EncapsulationKey) -> Result<Self, Self::Error> {
        todo!("soon (tm)");
    }
}

impl Into<x_wing::EncapsulationKey> for EncapsulationKey {
    fn into(self) -> x_wing::EncapsulationKey {
        todo!("I swear it shall be done");
    }
}

/// Priuvate key used to decapsulate an encapsulated shared secret value in a KEM scheme.
#[derive(Clone)]
pub struct DecapsulationKey {}

impl Decapsulate<Ciphertext, SharedSecret> for DecapsulationKey {
    type Error = ();
    fn decapsulate(&self, _: &Ciphertext) -> Result<[u8; 32], Self::Error> {
        todo!()
    }
}

impl TryFrom<[u8; DECAPSULATION_KEY_SIZE]> for DecapsulationKey {
    type Error = ();
    /// Attempts to parse the provided value as an Decapsulation key.
    ///
    /// Returns an error if the associated encapsulation key is non-encodable.
    fn try_from(value: [u8; DECAPSULATION_KEY_SIZE]) -> Result<Self, Self::Error> {
        todo!();
    }
}

impl TryFrom<x_wing::DecapsulationKey> for DecapsulationKey {
    type Error = ();
    fn try_from(value: x_wing::DecapsulationKey) -> Result<Self, Self::Error> {
        todo!("soon (tm)");
    }
}

impl Into<x_wing::DecapsulationKey> for DecapsulationKey {
    fn into(self) -> x_wing::DecapsulationKey {
        todo!("I swear it shall be done");
    }
}

impl DecapsulationKey {
    /// Generate a new DecapsulationKey using OsRng.
    #[cfg(feature = "getrandom")]
    pub fn generate_from_os_rng() -> Self {
        DecapsulationKey {}
    }

    /// Generate a new DecapsulationKey using the provided RNG.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        DecapsulationKey {}
    }

    /// Provide the matching EncapsulationKey.
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        EncapsulationKey {}
    }

    /// Private key as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &[0u8; 32]
    }
}

/// Encapsulated shared secret key value created when using the x-wing KEM.
///
/// When used this Ciphertext value will always encode to, and attempt to decode from an
/// obfuscated encoding. Similarly the encapsulate method used to generate this value will
/// always be generated such that the value is alwyas encodable (see the kemeleon documentation).
#[derive(Clone, PartialEq)]
pub struct Ciphertext {}

impl Ciphertext {
    /// Convert the key to the following format:
    /// Kemeleon encoded ML-KEM-768 ciphertext(1252 bytes) | X25519 ciphertext(32 bytes).
    pub fn as_bytes(&self) -> [u8; CIPHERTEXT_SIZE] {
        [0u8; CIPHERTEXT_SIZE]
    }

    /// Attempt to parse a Ciphertext from a bytes like object. The value must be formatted as:
    /// Kemeleon encoded ML-KEM-768 ciphertext(1252 bytes) | Elligator2 encoded X25519 ciphertext(32 bytes).
    pub fn try_from_bytes(buf: impl AsRef<[u8]>) -> Result<Self, ()> {
        Ok(Self {})
    }
}

impl TryFrom<&[u8; CIPHERTEXT_SIZE]> for Ciphertext {
    type Error = ();
    fn try_from(value: &[u8; CIPHERTEXT_SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(value)
    }
}

impl TryFrom<x_wing::Ciphertext> for Ciphertext {
    type Error = ();
    fn try_from(value: x_wing::Ciphertext) -> Result<Self, Self::Error> {
        todo!("soon (tm)");
    }
}

impl Into<x_wing::Ciphertext> for Ciphertext {
    fn into(self) -> x_wing::Ciphertext {
        todo!("I swear it shall be done");
    }
}

/// Generate a X-Wing key pair using the provided rng.
pub fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (DecapsulationKey, EncapsulationKey) {
    (DecapsulationKey {}, EncapsulationKey {})
}

#[cfg(feature = "getrandom")]
/// Generate a X-Wing key pair using `OsRng`.
pub fn generate_key_pair_from_os_rng() -> (DecapsulationKey, EncapsulationKey) {
    (DecapsulationKey {}, EncapsulationKey {})
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_kem_flow() {
        let mut rng = rand::thread_rng();

        let (dk, ek) = generate_key_pair(&mut rng);

        let ek_bytes = ek.as_bytes();

        let ek = EncapsulationKey::try_from(&ek_bytes).expect("should be guaranteed to parse");

        let (ct, ss_sender) = ek.encapsulate(&mut rng).unwrap();
        let ct_bytes = ct.as_bytes();

        let ct = Ciphertext::try_from(&ct_bytes).expect("should be guaranteed to parse");
        let ss_receiver = dk.decapsulate(&ct).unwrap();

        assert_eq!(ss_sender, ss_receiver);
    }
}
