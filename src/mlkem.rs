use crate::{
    fips, kemeleon::Encodable, ByteArray, Encode, EncodeError, EncodingSize, FipsByteArraySize,
    FipsEncodingSize, KemeleonByteArraySize, NttArray, OKemCore, Transcode,
};

use core::{fmt::Debug, marker::PhantomData};

use hkdf::Hkdf;
use hybrid_array::{typenum::Unsigned, Array};
use kem::{Decapsulate, Encapsulate};
use ml_kem::{
    kem::{DecapsulationKey, EncapsulationKey, Kem, Params as KemParams},
    Ciphertext, Encoded, EncodedSizeUser, KemCore, SharedKey,
};
use rand_core::CryptoRngCore;
use sha2::Sha256;

// ========================================================================== //
// Kem Equivalent object
// ========================================================================== //

/// Number of retries to generate a key pair that satisfies the Kemeleon criteria.
pub(crate) const MAX_RETRIES: usize = 64;

#[derive(Clone)]
pub struct Kemx<P>
where
    P: KemParams,
{
    _p: PhantomData<P>,
}

impl<P> Kemx<P>
where
    P: KemParams + FipsByteArraySize + KemeleonByteArraySize,
{
    fn generate_priv(rng: &mut impl CryptoRngCore) -> (KDecapsulationKey<P>, KEncapsulationKey<P>) {
        // random u8 for the most significant byte which will be less than 8 bits.
        for _ in 0..MAX_RETRIES {
            let ((dk, ek), res) = Self::try_generate_priv(rng);
            match res {
                Err(EncodeError::NotEncodable) => continue,
                Err(e) => panic!("encountered an unexpected error while generating keys: {e}"),
                Ok(()) => return (dk, ek),
            }
        }
        panic!("failed to generate key - you have a bad random number generator")
    }

    fn try_generate_priv(
        rng: &mut impl CryptoRngCore,
    ) -> (
        (KDecapsulationKey<P>, KEncapsulationKey<P>),
        Result<(), EncodeError>,
    ) {
        let (dk, ek) = Kem::<P>::generate(rng);

        let decap_key = KDecapsulationKey::<P>::new(dk);
        let encap_key = KEncapsulationKey::<P> {
            key: ek,
            byte: decap_key.byte,
        };

        if encap_key.is_encodable() {
            ((decap_key, encap_key), Ok(()))
        } else {
            ((decap_key, encap_key), Err(EncodeError::NotEncodable))
        }
    }
}

impl<P> OKemCore for Kemx<P>
where
    P: KemParams + FipsByteArraySize + KemeleonByteArraySize,
{
    type OkemError = EncodeError;

    type SharedKey = SharedKey<Kem<P>>;

    type Ciphertext = KCiphertext<P>;

    type DecapsulationKey = KDecapsulationKey<P>;

    type EncapsulationKey = KEncapsulationKey<P>;

    fn generate(rng: &mut impl CryptoRngCore) -> (KDecapsulationKey<P>, KEncapsulationKey<P>) {
        Self::generate_priv(rng)
    }

    fn try_generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), EncodeError> {
        match Self::try_generate_priv(rng) {
            (ekdk, Ok(())) => Ok(ekdk),
            (_, Err(e)) => Err(e),
        }
    }

    fn encapsulation_key(dk: &Self::DecapsulationKey) -> Self::EncapsulationKey {
        dk.encapsulation_key()
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
#[derive(Clone, Debug, PartialEq)]
pub struct KEncapsulationKey<P: KemParams> {
    pub(crate) key: EncapsulationKey<P>,
    pub(crate) byte: u8,
}

impl<P> KEncapsulationKey<P>
where
    P: KemParams + EncodingSize + FipsByteArraySize,
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
        let ek_fb_e = Encoded::<EncapsulationKey<P>>::try_from(ek_fb.as_ref())
            .map_err(EncodeError::MlKemError)
            .unwrap();
        let key = EncapsulationKey::<P>::from_bytes(&ek_fb_e);
        Self {
            key,
            byte: mask_byte,
        }
    }
}

impl<P> Encapsulate<KCiphertext<P>, SharedKey<Kem<P>>> for KEncapsulationKey<P>
where
    P: KemParams + FipsByteArraySize + KemeleonByteArraySize,
    EncapsulationKey<P>: Encapsulate<Ciphertext<Kem<P>>, SharedKey<Kem<P>>>,
{
    type Error = EncodeError;

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KCiphertext<P>, SharedKey<Kem<P>>), Self::Error> {
        for _ in 0..MAX_RETRIES {
            let (ek, ss) = self
                .key
                .encapsulate(rng)
                .map_err(|_| EncodeError::EncapsulationError)?;
            let (success, ct) = KCiphertext::<P>::new(&ek, &ss)?;

            if !success {
                continue;
            }

            return Ok((ct, ss));
        }
        Err(EncodeError::BadRngSource)
    }
}

impl<P> Transcode for KEncapsulationKey<P>
where
    P: KemParams + FipsByteArraySize,
{
    type Fips = EncapsulationKey<P>;

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
#[derive(Clone)]
pub struct KCiphertext<P>
where
    P: KemParams + KemeleonByteArraySize,
{
    pub(crate) bytes: Array<u8, P::ENCODED_CT_SIZE>,
    pub(crate) fips: Ciphertext<Kem<P>>,
}

impl<P> core::fmt::Debug for KCiphertext<P>
where
    P: KemParams + KemeleonByteArraySize,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ciphertext")
            .field("fips", &hex::encode(&self.fips))
            .field("kmln", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P> core::cmp::PartialEq for KCiphertext<P>
where
    P: KemParams + KemeleonByteArraySize,
{
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P> AsRef<[u8]> for KCiphertext<P>
where
    P: KemParams + KemeleonByteArraySize,
{
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P> From<Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>> for KCiphertext<P>
where
    P: KemParams + KemeleonByteArraySize,
{
    fn from(value: Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>) -> Self {
        KCiphertext::decode(value).unwrap()
    }
}

impl<P> From<&Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>> for KCiphertext<P>
where
    P: KemParams + FipsByteArraySize + KemeleonByteArraySize,
{
    fn from(value: &Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>) -> Self {
        KCiphertext::decode(value).unwrap()
    }
}

impl<P> TryFrom<&[u8]> for KCiphertext<P>
where
    P: KemParams + KemeleonByteArraySize,
{
    type Error = EncodeError;
    fn try_from(buf: &[u8]) -> Result<Self, EncodeError> {
        KCiphertext::decode(buf)
    }
}

// ========================================================================== //
// Decapsulation Key
// ========================================================================== //

/// A `DecapsulationKey` is the secret portion of a key pair that allows the holder to reveal a value encapsulated using
/// the associated encapsulation key.
///
/// Generally Kemeleon should ONLY be used for **ephemeral** key pairs, as the kemeleon encoded encapsulation key can
/// vary if serialized and deserialized. The encapsulation keys will function identically, but the high order bits may
/// be different.
///
/// ## Serializing and Deserializing
///
/// If parsing a [`DecapsulationKey`] from a FIPS formatted representation, the value of the high order bits will be
/// taken from random. This means that serializing the decapsulation key to FIPS format and then re-parsing as a
/// kemeleon key, the kemeleon representation of the associated encapsulation key has a 3/4 chance of differing in the
/// high order two bits (for 512, 6 bits for 768, 3 for 1024) when compared to the original encapsulation key.
///
/// NOTE: A best effort is made to ensure that the ensure that the high order bits of the encapsulation key are
/// randomized rather than being zeroed. If you have serialized the decapsulation key or parsed from a FIPS format
/// decapsulation key, the value of the high order bits will be taken from random.
pub struct KDecapsulationKey<P: KemParams> {
    key: DecapsulationKey<P>,
    byte: u8,
}

impl<P: KemParams> PartialEq for KDecapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.byte == other.byte
    }
}

impl<P: KemParams> Debug for KDecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("key", &self.key)
            .field("byte", &self.byte)
            .finish()
    }
}

pub type EncodedCt<P> = Array<u8, <P as KemeleonByteArraySize>::ENCODED_CT_SIZE>;

impl<P> Decapsulate<EncodedCt<P>, SharedKey<Kem<P>>> for KDecapsulationKey<P>
where
    P: KemParams + FipsByteArraySize + KemeleonByteArraySize,
    DecapsulationKey<P>: Decapsulate<Ciphertext<Kem<P>>, SharedKey<Kem<P>>>,
{
    type Error = EncodeError;

    fn decapsulate(&self, ciphertext: &EncodedCt<P>) -> Result<SharedKey<Kem<P>>, Self::Error> {
        let ct = KCiphertext::<P>::decode(ciphertext)?;
        let k_send = ct.fips;
        self.key
            .decapsulate(&k_send)
            .map_err(|_| EncodeError::DecapsulationError)
    }
}

impl<P> Decapsulate<KCiphertext<P>, SharedKey<Kem<P>>> for KDecapsulationKey<P>
where
    P: KemParams + KemeleonByteArraySize,
    DecapsulationKey<P>: Decapsulate<Ciphertext<Kem<P>>, SharedKey<Kem<P>>>,
{
    type Error = EncodeError;

    fn decapsulate(&self, ciphertext: &KCiphertext<P>) -> Result<SharedKey<Kem<P>>, Self::Error> {
        self.key
            .decapsulate(&ciphertext.fips)
            .map_err(|_| EncodeError::DecapsulationError)
    }
}

impl<P> KDecapsulationKey<P>
where
    P: KemParams + EncodingSize + FipsEncodingSize,
{
    const HIGH_ORDER_BITS_IKM: &[u8; 34] = b"kemeleon:decapsulation_key_msb_mac";

    /// Returns a decapsulation key built from a ['ml_kem::kem::DecapsulationKey`].
    pub fn new(key: DecapsulationKey<P>) -> Self {
        Self {
            byte: Self::get_high_order_bits(&key),
            key,
        }
    }

    /// Returns the Decapsulation Key as bytes in the FIPS representation for serializing
    /// and deserializing.
    pub fn to_fips_bytes(
        &self,
    ) -> ByteArray<<DecapsulationKey<P> as ml_kem::EncodedSizeUser>::EncodedSize> {
        self.key.as_bytes()
    }

    /// Returns the encapsulation key associated with this decapsulation key
    pub fn encapsulation_key(&self) -> KEncapsulationKey<P> {
        KEncapsulationKey {
            key: self.key.encapsulation_key().clone(),
            byte: self.byte,
        }
    }

    fn get_high_order_bits(key: &DecapsulationKey<P>) -> u8 {
        // SAFETY - this should never panic as the output vec is a valid size
        let hk = Hkdf::<Sha256>::new(None, Self::HIGH_ORDER_BITS_IKM);
        let mut okm = [0u8; 16];
        let info = key.as_bytes();
        hk.expand(&info[..], &mut okm)
            .expect("16 is a valid length for Sha256 to output");
        okm[0]
    }
}

impl<P> Encode for KDecapsulationKey<P>
where
    P: KemParams + EncodingSize,
{
    type Error = EncodeError;
    type EncodedSize = <DecapsulationKey<P> as EncodedSizeUser>::EncodedSize;

    /// Returns the Decapsulation Key as bytes.
    fn as_bytes(&self) -> Array<u8, Self::EncodedSize> {
        self.key.as_bytes()
    }

    /// Creates a Kemeleon decapsulation key from bytes.
    fn try_from_bytes<B: AsRef<[u8]>>(buf: B) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let dk_size = <DecapsulationKey<P> as EncodedSizeUser>::EncodedSize::USIZE;
        let b = buf.as_ref();

        if b.len() < dk_size {
            return Err(EncodeError::parse_error(
                "provided decapsulation key too short",
            ));
        }
        let encoded_dk = Encoded::<DecapsulationKey<P>>::from_fn(|i| b[i]);
        let dk = DecapsulationKey::from_bytes(&encoded_dk);

        Ok(Self::new(dk))
    }
}

#[cfg(test)]
mod test {
    use crate::{KemeleonByteArraySize, MlKem1024Params, MlKem512Params, MlKem768Params};

    use super::*;

    use ml_kem::{Encoded, EncodedSizeUser};

    fn generate_trial<P>()
    where
        P: KemParams + FipsByteArraySize + KemeleonByteArraySize,
    {
        let mut rng = rand::thread_rng();
        let (dk, ek) = Kemx::<P>::generate(&mut rng);

        // To Fips Encoding and back
        let ek_encoded: Vec<u8> = ek.key.as_bytes().to_vec();
        let ek_bytes = Encoded::<EncapsulationKey<P>>::try_from(&ek_encoded[..])
            .expect("failed to create hybrid_array::Array");
        let ek_decoded = EncapsulationKey::<P>::from_bytes(&ek_bytes);
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
        generate_trial::<MlKem512Params>();
        generate_trial::<MlKem768Params>();
        generate_trial::<MlKem1024Params>();
    }

    fn coverage_trial<P>()
    where
        P: KemParams + FipsByteArraySize + KemeleonByteArraySize,
    {
        let mut rng = rand::thread_rng();
        let (dk, ek) = Kemx::<P>::generate(&mut rng);

        // DecapsulationKey as_bytes
        // DecapsulationKey from_bytes
        let dkb = KDecapsulationKey::<P>::as_bytes(&dk);
        let dk_parsed = KDecapsulationKey::<P>::try_from_bytes(&dkb)
            .expect("failed to parse decapsulation key");
        assert_eq!(dk.key, dk_parsed.key);

        // DecapsulationKey from_fips_bytes
        let dk_fips_b = dk.key.as_bytes();
        let dk_fips_parsed =
            KDecapsulationKey::<P>::try_from_bytes(&dk_fips_b).expect("failed to parse dk");
        assert_eq!(dk.key, dk_fips_parsed.key);

        // EncapsulationKey encapsulate -> (SharedKey<P>, bool)
        let (ct, sk) = ek.encapsulate(&mut rng).expect("failed encapsulate");

        // KDecapsulationKey decapsulate(KCiphertext)
        let ciphertext = KCiphertext::decode(&ct).expect("failed ciphertext decode");
        let k_recv = dk.decapsulate(&ciphertext).expect("failed to decapsulate");
        assert_eq!(sk, k_recv);

        let bytes = &KCiphertext::<P>::as_bytes(&ct);
        let ct_arr = EncodedCt::<P>::from_fn(|i| bytes[i]);

        // KCiphertext try_from &[u8]
        let _ct = KCiphertext::<P>::try_from(&ct_arr[..]).expect("failed parse");
        // KCiphertext from Array<u8, ENCODED_CT_SIZE>
        let _ct = KCiphertext::<P>::from(ct_arr.clone());
        // KCiphertext from &Array<u8, ENCODED_CT_SIZE>
        let _ct = KCiphertext::<P>::from(&ct_arr);
        // KCiphertext try_from_bytes &[u8]
        let _ct = KCiphertext::<P>::try_from_bytes(&ct_arr[..]).expect("failed parse");
        // KCiphertext from [u8; ENCODED_CT_SIZE]
        let _ct = KCiphertext::<P>::from(ct_arr);

        // KEncapsulationKey to_fips
        let fips = ek.to_fips();
        // KEncapsulationKey from_fips
        let __ek = KEncapsulationKey::<P>::from_fips(fips);

        let k_recv = dk
            .decapsulate(&ct)
            .expect("failed to decapsulate after deterministic encapsulation");
        assert_eq!(k_recv, sk);
    }

    #[test]
    fn coverage() {
        coverage_trial::<MlKem512Params>();
        coverage_trial::<MlKem768Params>();
        coverage_trial::<MlKem1024Params>();
    }

    #[test]
    fn serialize_decap() {
        let mut rng = rand::thread_rng();
        let (dk, _) = Kemx::<MlKem768Params>::generate_priv(&mut rng);

        let dk_bytes = <KDecapsulationKey<MlKem768Params> as Encode>::as_bytes(&dk);
        let dk_parsed = KDecapsulationKey::<MlKem768Params>::try_from_bytes(dk_bytes)
            .expect("failed to parse decapsulation key");
        assert_eq!(dk.key, dk_parsed.key);
        assert_eq!(dk.byte, dk_parsed.byte);
    }
}
