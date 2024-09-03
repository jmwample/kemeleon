use crate::{fips, kemeleon::Encodable, EncodingSize, FipsEncodingSize, Transcode, ARR_LEN};
use crate::{Encode, EncodeError};

use core::fmt::Debug;
use std::marker::PhantomData;

use kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, SharedKey};
#[cfg(feature = "deterministic")]
use ml_kem::{EncapsulateDeterministic, B32};
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
    /// Construct a local object representing an Encapsulation key from the FIPS byte
    /// representations of the individual parts of the key.
    pub fn from_parts(t_hat: &[[u16; ARR_LEN]; P::K], rho: &[u8; 32], mask_byte: u8) -> Self {
        let ek_fb = fips::ek_encode(rho, t_hat);
        Self::from_fips_bytes(ek_fb, mask_byte)
    }

    // TODO: should this be a Result since a key of improper length could panic?
    /// Provides an interface for creating a Kemeleon version of an object from the
    /// FIPS byte encoded version.
    ///
    /// Differs from `EncapsulationKey::<P>::from_bytes()` in that this parses only from
    /// FIPS representation, while `from_bytes` parses only from the Kemeleon representation.
    ///
    /// Panics if the provided FIPS encapsulation key is not the proper size. this
    /// is only used internally so this should never be provided an improperly
    /// formatted encapsulation key.
    fn from_fips_bytes(ek_fb: impl AsRef<[u8]>, mask_byte: u8) -> Self {
        let ek_fb_e = Encoded::<<P as KemCore>::EncapsulationKey>::try_from(ek_fb.as_ref())
            .map_err(EncodeError::MlKemError)
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
    type Error = EncodeError;

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KEncodedCiphertext<P>, SharedKey<P>), Self::Error> {
        for _ in 0..MAX_RETRIES {
            let (ek, ss) = self.key.encapsulate(rng).map_err(|_| {
                EncodeError::EncapsulationError("ML-KEM encapsulation error".into())
            })?;
            let (success, ct) = KCiphertext::<P>::new(&ek, &ss)?;

            if !success {
                continue;
            }

            return Ok((KEncodedCiphertext(ct.bytes), ss));
        }
        Err(EncodeError::NotEncodable)
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
    type Error = EncodeError;

    fn encapsulate_deterministic(
        &self,
        m: &B32,
    ) -> Result<(KEncodedCiphertext<P>, SharedKey<P>), Self::Error> {
        let (ek, ss) = self
            .key
            .encapsulate_deterministic(m)
            .map_err(|_| EncodeError::EncapsulationError("failed encapsulation".into()))?;
        let (success, ct) = KCiphertext::<P>::new(&ek, &ss)?;

        if !success {
            return Err(EncodeError::NotEncodable);
        }

        return Ok((KEncodedCiphertext(ct.bytes), ss));
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

// impl<P> EncodedSizeUser for KEncapsulationKey<P>
// where
//     P: KemCore + EncodingSize,
// {
//     type EncodedSize = typenum::U749;
//
//     fn as_bytes(&self) -> Encoded<Self> {
//
//     }
//
//     fn from_bytes(enc: &Encoded<Self>) -> Self {
//
//     }
// }

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

impl<P> From<[u8; P::ENCODED_CT_SIZE]> for KEncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::ENCODED_CT_SIZE]:,
{
    fn from(value: [u8; P::ENCODED_CT_SIZE]) -> Self {
        KEncodedCiphertext(value)
    }
}

impl<P> From<[u8; P::ENCODED_CT_SIZE]> for KCiphertext<P>
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
    fn from(value: [u8; P::ENCODED_CT_SIZE]) -> Self {
        KCiphertext::decode(value).unwrap()
    }
}

impl<P> TryFrom<&[u8]> for KEncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::DU]:,
    [(); P::ENCODED_SIZE]:,
    [(); P::ENCODED_CT_SIZE]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{
    type Error = EncodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        KEncodedCiphertext::try_from_bytes(value)
    }
}

impl<P> TryFrom<&[u8]> for KCiphertext<P>
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
    type Error = EncodeError;
    fn try_from(buf: &[u8]) -> Result<Self, EncodeError> {
        KCiphertext::decode(buf)
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
    type Error = EncodeError;

    fn decapsulate(&self, ciphertext: &KEncodedCiphertext<P>) -> Result<SharedKey<P>, Self::Error> {
        let ct = KCiphertext::decode(ciphertext)?;
        let k_send = ct.fips;
        self.0
            .decapsulate(&k_send)
            .map_err(|e| EncodeError::DecapsulationError(format!("failed to decapsulate: {e:?}")))
    }
}

impl<P> Decapsulate<KCiphertext<P>, SharedKey<P>> for KDecapsulationKey<P>
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
    type Error = EncodeError;

    fn decapsulate(&self, ciphertext: &KCiphertext<P>) -> Result<SharedKey<P>, Self::Error> {
        self.0
            .decapsulate(&ciphertext.fips)
            .map_err(|e| EncodeError::DecapsulationError(format!("failed to decapsulate: {e:?}")))
    }
}

impl<P> Decapsulate<Ciphertext<P>, SharedKey<P>> for KDecapsulationKey<P>
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
    type Error = EncodeError;

    fn decapsulate(&self, ciphertext: &Ciphertext<P>) -> Result<SharedKey<P>, Self::Error> {
        self.0
            .decapsulate(ciphertext)
            .map_err(|e| EncodeError::DecapsulationError(format!("failed to decapsulate: {e:?}")))
    }
}

impl<P: KemCore + EncodingSize + FipsEncodingSize> KDecapsulationKey<P> {
    /// Provides an interface for creating a Kemeleon version of a decapsulation key from
    /// the FIPS byte encoded version.
    pub fn from_fips_bytes(value: impl AsRef<[u8]>) -> Result<Self, EncodeError> {
        let b = value.as_ref();
        if b.len() != P::FIPS_ENCODED_SIZE {
            return Err(EncodeError::ParseError(
                "incorrect Decapsulation key length".into(),
            ));
        }

        let fips_key_encoded =
            Encoded::<P::DecapsulationKey>::try_from(b).map_err(Into::<EncodeError>::into)?;
        let fips_key = P::DecapsulationKey::from_bytes(&fips_key_encoded);

        Ok(KDecapsulationKey(fips_key))
    }
}

impl<P> EncodedSizeUser for KDecapsulationKey<P>
where
    P: KemCore + EncodingSize,
{
    type EncodedSize = <<P as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize;

    fn as_bytes(&self) -> Encoded<Self> {
        self.0.as_bytes()
    }

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let dk = P::DecapsulationKey::from_bytes(enc);
        Self(dk)
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

    fn coverage_trial<P>()
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

        // DecapsulationKey as_bytes
        // DecapsulationKey from_bytes
        let dkb = dk.as_bytes();
        let dk_parsed = KDecapsulationKey::<P>::from_bytes(&dkb);
        assert_eq!(dk.0, dk_parsed.0);

        // DecapsulationKey from_fips_bytes
        let dk_fips_b = dk.0.as_bytes();
        let dk_fips_parsed =
            KDecapsulationKey::<P>::from_fips_bytes(&dk_fips_b).expect("failed fips parse");
        assert_eq!(dk.0, dk_fips_parsed.0);

        // EncapsulationKey encapsulate -> (SharedKey<P>, bool)
        let (ct, sk) = ek.encapsulate(&mut rng).expect("failed encapsulate");

        // KDecapsulationKey decapsulate(KCiphertext)
        let ciphertext = KCiphertext::decode(&ct).expect("failed ciphertext decode");
        let k_recv = dk.decapsulate(&ciphertext).expect("failed to decapsulate");
        assert_eq!(sk, k_recv);

        // KDecapsulationKey decapsulate(mk-kem::Ciphertext)
        let ct_fips = ciphertext.fips;
        let k_recv = dk.decapsulate(&ct_fips).expect("failed to decapsulate");
        assert_eq!(sk, k_recv);

        let mut ct_arr = [0u8; P::ENCODED_CT_SIZE];
        ct_arr.copy_from_slice(&ct.as_bytes());

        // KCiphertext try_from &[u8]
        let _ct = KCiphertext::<P>::try_from(&ct_arr[..]).expect("failed parse");
        // KCiphertext from [u8; ENCODED_CT_SIZE]
        let _ct = KCiphertext::<P>::from(ct_arr);
        // KEncodedCiphertext try_from &[u8]
        let _ct = KEncodedCiphertext::<P>::try_from(&ct_arr[..]).expect("failed parse");
        // KEncodedCiphertext from [u8; ENCODED_CT_SIZE]
        let _ct = KCiphertext::<P>::from(ct_arr);

        // KEncapsulationKey to_fips
        let fips = ek.to_fips();
        // KEncapsulationKey from_fips
        let ek = KEncapsulationKey::<P>::from_fips(fips);

        // KEncapsulationKey encapsulate_deterministic
        #[cfg(feature = "deterministic")]
        let (ct, sk) = ek
            .encapsulate_deterministic((&[0u8; 32]).into())
            .expect("failed encapsulate_deterministic");

        let k_recv = dk
            .decapsulate(&ct)
            .expect("failed to decapsulate after deterministic encapsulation");
        assert_eq!(k_recv, sk);
    }

    #[test]
    fn coverage() {
        coverage_trial::<MlKem512>();
        coverage_trial::<MlKem768>();
        coverage_trial::<MlKem1024>();
    }
}
