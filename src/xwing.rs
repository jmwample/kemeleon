//! Obfuscated X-Wing using Kemeleon and Elligator2
//!
//! Implements the `kem::{Encapsulate, Decapsulate}` traits.
//!
//! Kemeleon for ML-KEM encoding and Elligator2 for X25519 Encoding.
//!

use rand_core::CryptoRngCore;

use crate::{Ciphertext as KCiphertext, EncapsulationKey as KEncapsulationKey, Encode, Transcode};
use ml_kem::MlKem768;

mod x25519_elligator2;

type MlkemEk = KEncapsulationKey<MlKem768>;

type MlkemCt = KCiphertext<MlKem768>;

// Re-export traits from the `kem` crate
pub use ::kem::{Decapsulate, Encapsulate};

/// Size in bytes of the DecapsulationKey.
pub const DECAPSULATION_KEY_SIZE: usize = 32;

const ML_EK_LENGTH: usize = 1184;
const ML_KEM_EK_LENGTH: usize = 1156;
const X25519_EK_LENGTH: usize = 32;
/// Size in bytes of the EncapsulationKey.
pub const ENCAPSULATION_KEY_SIZE: usize = ML_KEM_EK_LENGTH + X25519_EK_LENGTH;

const ML_CT_LENGTH: usize = 1088;
const ML_KEM_CT_LENGTH: usize = 1252;
const X25519_CT_LENGTH: usize = 32;
/// Size in bytes of the Ciphertext.
pub const CIPHERTEXT_SIZE: usize = ML_KEM_CT_LENGTH + X25519_CT_LENGTH;

/// Shared secret value
pub type SharedSecret = [u8; 32];

/// Public key used to encapsulate a shared secret value in a KEM scheme.
#[derive(Clone, PartialEq)]
pub struct EncapsulationKey {
    inner: x_wing::EncapsulationKey,
    ek_m: MlkemEk,
}

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
        let ek_m = MlkemEk::try_from_bytes(buf).map_err(|_| ())?;

        let mut inner_bytes = [0u8; x_wing::ENCAPSULATION_KEY_SIZE];
        inner_bytes[..ML_EK_LENGTH].copy_from_slice(ek_m.as_fips_bytes());
        let inner = x_wing::EncapsulationKey::from(&inner_bytes);

        Ok(Self {
            inner,
            ek_m,
        })
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
pub struct DecapsulationKey {
    inner: x_wing::DecapsulationKey
}

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
        generate_key_pair(rng).0
    }

    /// Provide the matching EncapsulationKey.
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        EncapsulationKey{ inner: self.inner.encapsulation_key() }
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
pub struct Ciphertext {
    ct_m: MlkemCt,
    ct_x: [u8;32],
}

impl Ciphertext {
    /// Convert the key to the following format:
    /// Kemeleon encoded ML-KEM-768 ciphertext(1252 bytes) | X25519 ciphertext(32 bytes).
    pub fn as_bytes(&self) -> [u8; CIPHERTEXT_SIZE] {
        let mut out = [0u8; CIPHERTEXT_SIZE];
        let encoded_ct = self.ct_m.as_bytes();

        out[..ML_KEM_CT_LENGTH].copy_from_slice(&encoded_ct.as_ref());
        out[ML_KEM_CT_LENGTH..].copy_from_slice(&self.ct_x);
        out
    }

    /// Attempt to parse a Ciphertext from a bytes like object. The value must be formatted as:
    /// Kemeleon encoded ML-KEM-768 ciphertext(1252 bytes) | Elligator2 encoded X25519 ciphertext(32 bytes).
    pub fn try_from_bytes(buf: impl AsRef<[u8]>) -> Result<Self, ()> {
        let b = buf.as_ref();
        if b.len() < CIPHERTEXT_SIZE {
            return Err(())
        }

        let mut ct_x = [0u8; X25519_CT_LENGTH];
        ct_x. copy_from_slice(&b[ML_KEM_CT_LENGTH..ML_KEM_CT_LENGTH+X25519_CT_LENGTH]);

        let ct_m = MlkemCt::try_from(&b[..ML_KEM_CT_LENGTH]).map_err(|_| ())?;

        Ok(Self {
            ct_m,
            ct_x,
        })
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
    // TODO: do in loop until we get a valid kemeleon key
    let (dk, ek) = x_wing::generate_key_pair(rng);
    (DecapsulationKey {inner: dk}, EncapsulationKey{ inner: ek})
}

#[cfg(feature = "getrandom")]
/// Generate a X-Wing key pair using `OsRng`.
pub fn generate_key_pair_from_os_rng() -> (DecapsulationKey, EncapsulationKey) {
    let (dk, ek) = x_wing::generate_key_pair_from_os_rng();
    (DecapsulationKey {inner: dk}, EncapsulationKey {inner: ek})
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
