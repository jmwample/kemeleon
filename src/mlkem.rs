use crate::{
    fips, kemeleon::Encodable, Encode, EncodeError, EncodingSize, FipsByteArraySize,
    FipsEncodingSize, KemeleonByteArraySize, NttArray, OKemCore, Transcode,
};

use core::{fmt::Debug, marker::PhantomData};

use hybrid_array::Array;
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

#[derive(Clone)]
pub struct Kemx<P>
where
    P: ml_kem::KemCore,
{
    _p: PhantomData<P>,
}

impl<P> Kemx<P>
where
    P: ml_kem::KemCore + FipsByteArraySize + KemeleonByteArraySize,
{
    fn generate_priv(rng: &mut impl CryptoRngCore) -> (KDecapsulationKey<P>, KEncapsulationKey<P>) {
        // random u8 for the most significant byte which will be less than 8 bits.
        let msb_rand = rng.next_u32() as u8;

        for _ in 0..MAX_RETRIES {
            let (dk, ek) = P::generate(rng);
            let encap_key = KEncapsulationKey::<P> {
                key: ek,
                byte: msb_rand,
            };
            if encap_key.is_encodable() {
                let decap_key = KDecapsulationKey::<P>(dk);
                return (decap_key, encap_key);
            }

            continue;
        }
        panic!("failed to generate key - you have a bad random number generator")
    }

    fn try_generate_priv(
        rng: &mut impl CryptoRngCore,
    ) -> (
        (KDecapsulationKey<P>, KEncapsulationKey<P>),
        Result<(), EncodeError>,
    ) {
        let msb_rand = rng.next_u32() as u8;

        let (dk, ek) = P::generate(rng);
        let encap_key = KEncapsulationKey::<P> {
            key: ek,
            byte: msb_rand,
        };

        let decap_key = KDecapsulationKey::<P>(dk);
        if encap_key.is_encodable() {
            ((decap_key, encap_key), Ok(()))
        } else {
            ((decap_key, encap_key), Err(EncodeError::NotEncodable))
        }
    }
}

impl<P> OKemCore for Kemx<P>
where
    P: KemCore + FipsByteArraySize + KemeleonByteArraySize,
{
    type OkemError = EncodeError;

    type SharedKeySize = <P as KemCore>::SharedKeySize;
    type SharedKey = SharedKey<P>;

    type Ciphertext = KEncodedCiphertext<P>;
    type CiphertextSize = <Self as KemeleonByteArraySize>::ENCODED_CT_SIZE;

    type DecapsulationKey = KDecapsulationKey<P>;

    type EncapsulationKey = KEncapsulationKey<P>;

    fn generate(rng: &mut impl CryptoRngCore) -> (KDecapsulationKey<P>, KEncapsulationKey<P>) {
        Self::generate_priv(rng)
    }

    fn try_generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KDecapsulationKey<P>, KEncapsulationKey<P>), EncodeError> {
        match Self::try_generate_priv(rng) {
            (ekdk, Ok(())) => Ok(ekdk),
            (_, Err(e)) => Err(e),
        }
    }

    #[cfg(feature = "deterministic")]
    fn generate_deterministic(d: &B32, z: &B32) -> (KDecapsulationKey<P>, KEncapsulationKey<P>) {
        let (dk, ek) = <P as KemCore>::generate_deterministic(d, z);
        (KDecapsulationKey(dk), KEncapsulationKey::from_fips(ek))
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
#[derive(Debug, PartialOrd)]
pub struct KEncapsulationKey<P>
where
    P: KemCore + FipsByteArraySize,
{
    pub(crate) key: P::EncapsulationKey,
    pub(crate) byte: u8,
}

impl<P> Clone for KEncapsulationKey<P>
where
    P: KemCore + FipsByteArraySize,
{
    fn clone(&self) -> Self {
        let k = P::EncapsulationKey::from_bytes(&self.key.as_bytes());

        KEncapsulationKey {
            byte: self.byte,
            key: k,
        }
    }
}

impl<P> PartialEq for KEncapsulationKey<P>
where
    P: KemCore + FipsByteArraySize,
{
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.byte == other.byte
    }
}

impl<P> KEncapsulationKey<P>
where
    P: KemCore + EncodingSize + FipsByteArraySize,
{
    // TODO: must use for now -- not sure it this will stay
    #[must_use]
    /// Construct a local object representing an Encapsulation key from the FIPS byte
    /// representations of the individual parts of the key.
    pub fn from_parts(ntt: &NttArray<P>, rho: &[u8; 32], mask_byte: u8) -> Self {
        let ek_fb = fips::ek_encode::<P>(rho, ntt);
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
    P: KemCore + FipsByteArraySize + KemeleonByteArraySize,
{
    type Error = EncodeError;

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KEncodedCiphertext<P>, SharedKey<P>), Self::Error> {
        for _ in 0..MAX_RETRIES {
            let (ek, ss) = self
                .key
                .encapsulate(rng)
                .map_err(|_| EncodeError::EncapsulationError)?;
            let (success, ct) = KCiphertext::<P>::new(&ek, &ss)?;

            if !success {
                continue;
            }

            return Ok((KEncodedCiphertext(ct.bytes), ss));
        }
        Err(EncodeError::BadRngSource)
    }
}

#[cfg(feature = "deterministic")]
impl<P> EncapsulateDeterministic<KEncodedCiphertext<P>, SharedKey<P>> for KEncapsulationKey<P>
where
    P: KemCore + FipsByteArraySize + KemeleonByteArraySize,
{
    type Error = EncodeError;

    fn encapsulate_deterministic(
        &self,
        m: &B32,
    ) -> Result<(KEncodedCiphertext<P>, SharedKey<P>), Self::Error> {
        let (ek, ss) = self
            .key
            .encapsulate_deterministic(m)
            .map_err(|_| EncodeError::EncapsulationError)?;
        let (_, ct) = KCiphertext::<P>::new(&ek, &ss)?;

        Ok((KEncodedCiphertext(ct.bytes), ss))
    }
}

impl<P> Transcode for KEncapsulationKey<P>
where
    P: KemCore + FipsByteArraySize,
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
pub struct KCiphertext<P>
where
    P: KemCore + KemeleonByteArraySize,
{
    pub(crate) bytes: Array<u8, P::ENCODED_CT_SIZE>,
    pub(crate) fips: Ciphertext<P>,
}

impl<P> core::fmt::Debug for KCiphertext<P>
where
    P: KemCore + KemeleonByteArraySize,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ciphertext")
            .field("fips", &hex::encode(&self.fips))
            .field("kmln", &hex::encode(&self.bytes))
            .finish()
    }
}

pub struct KEncodedCiphertext<P>(pub(crate) Array<u8, P::ENCODED_CT_SIZE>)
where
    P: KemCore + KemeleonByteArraySize;

impl<P> AsRef<[u8]> for KEncodedCiphertext<P>
where
    P: KemCore + KemeleonByteArraySize,
{
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P> PartialEq for KEncodedCiphertext<P>
where
    P: KemCore + KemeleonByteArraySize,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<P> core::fmt::Debug for KEncodedCiphertext<P>
where
    P: KemCore + KemeleonByteArraySize,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl<P> From<&Array<u8, P::ENCODED_CT_SIZE>> for KEncodedCiphertext<P>
where
    P: KemCore + KemeleonByteArraySize,
{
    fn from(value: &Array<u8, P::ENCODED_CT_SIZE>) -> Self {
        KEncodedCiphertext(value.clone())
    }
}

impl<P> From<Array<u8, P::ENCODED_CT_SIZE>> for KEncodedCiphertext<P>
where
    P: KemCore + KemeleonByteArraySize,
{
    fn from(value: Array<u8, P::ENCODED_CT_SIZE>) -> Self {
        KEncodedCiphertext(value)
    }
}

impl<P> From<Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>> for KCiphertext<P>
where
    P: KemCore + FipsByteArraySize + KemeleonByteArraySize,
{
    fn from(value: Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>) -> Self {
        KCiphertext::decode(value).unwrap()
    }
}

impl<P> From<&Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>> for KCiphertext<P>
where
    P: KemCore + FipsByteArraySize + KemeleonByteArraySize,
{
    fn from(value: &Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>) -> Self {
        KCiphertext::decode(value).unwrap()
    }
}

impl<P> TryFrom<&[u8]> for KEncodedCiphertext<P>
where
    P: KemCore + FipsByteArraySize + KemeleonByteArraySize,
{
    type Error = EncodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        KEncodedCiphertext::try_from_bytes(value)
    }
}

impl<P> TryFrom<&[u8]> for KCiphertext<P>
where
    P: KemCore + FipsByteArraySize + KemeleonByteArraySize,
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
    P: KemCore + FipsByteArraySize + KemeleonByteArraySize,
{
    type Error = EncodeError;

    fn decapsulate(&self, ciphertext: &KEncodedCiphertext<P>) -> Result<SharedKey<P>, Self::Error> {
        let ct = KCiphertext::<P>::decode(ciphertext)?;
        let k_send = ct.fips;
        self.0
            .decapsulate(&k_send)
            .map_err(|_| EncodeError::DecapsulationError)
    }
}

impl<P> Decapsulate<KCiphertext<P>, SharedKey<P>> for KDecapsulationKey<P>
where
    P: KemCore + KemeleonByteArraySize,
{
    type Error = EncodeError;

    fn decapsulate(&self, ciphertext: &KCiphertext<P>) -> Result<SharedKey<P>, Self::Error> {
        self.0
            .decapsulate(&ciphertext.fips)
            .map_err(|_| EncodeError::DecapsulationError)
    }
}

impl<P> Decapsulate<Ciphertext<P>, SharedKey<P>> for KDecapsulationKey<P>
where
    P: KemCore + EncodingSize,
{
    type Error = EncodeError;

    fn decapsulate(&self, ciphertext: &Ciphertext<P>) -> Result<SharedKey<P>, Self::Error> {
        self.0
            .decapsulate(ciphertext)
            .map_err(|_| EncodeError::DecapsulationError)
    }
}

impl<P: KemCore + EncodingSize + FipsEncodingSize> KDecapsulationKey<P> {
    /// Provides an interface for creating a Kemeleon version of a decapsulation key from
    /// the FIPS byte encoded version.
    pub fn from_fips_bytes(value: impl AsRef<[u8]>) -> Result<Self, EncodeError> {
        let b = value.as_ref();
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
    use crate::{ByteArr, KemeleonByteArraySize};

    use super::*;

    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768};

    fn generate_trial<P>()
    where
        P: ml_kem::KemCore + FipsByteArraySize + KemeleonByteArraySize,
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
        P: ml_kem::KemCore + FipsByteArraySize + KemeleonByteArraySize,
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

        let mut ct_arr = ByteArr::zero::<<P as KemeleonByteArraySize>::ENCODED_CT_SIZE>();
        ct_arr.copy_from_slice(&ct.as_bytes());

        // KCiphertext try_from &[u8]
        let _ct = KCiphertext::<P>::try_from(&ct_arr[..]).expect("failed parse");
        // KCiphertext from Array<u8, ENCODED_CT_SIZE>
        let _ct = KCiphertext::<P>::from(ct_arr.clone());
        // KCiphertext from &Array<u8, ENCODED_CT_SIZE>
        let _ct = KCiphertext::<P>::from(&ct_arr);
        // KEncodedCiphertext try_from &[u8]
        let _ct = KEncodedCiphertext::<P>::try_from(&ct_arr[..]).expect("failed parse");
        // KEncodedCiphertext from [u8; ENCODED_CT_SIZE]
        let _ct = KCiphertext::<P>::from(ct_arr);

        // KEncapsulationKey to_fips
        let fips = ek.to_fips();
        // KEncapsulationKey from_fips
        let __ek = KEncapsulationKey::<P>::from_fips(fips);

        // KEncapsulationKey encapsulate_deterministic
        #[cfg(feature = "deterministic")]
        let (ct, sk) = __ek
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
