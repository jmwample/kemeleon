//! Rust ML-KEM encodings following the [FIPS 203 Initial Public Draft](https://csrc.nist.gov/pubs/fips/203/ipd)
//!
//! This code was drawn almost directly from the [`ml-kem`](https://docs.rs/ml-kem) crate.
//!
//! This module implements the `byte_encode(f)` and `byte_decode(f)` fips encoding
//! functions. This can be used to interface with '`ml_kem`' crate by using it's
//! `Encode` trait then parsing to my own local format before re-encoding to
//! kemeleon format. The reverse can be done to convert back to '`ml_kem`'.
//!
//! This should work for any ML KEM library that implements the FIPS encoding
//! properly.
//!

use crate::{Barr8, EncodingSize, FieldElement, FipsEncodingSize, NttArray, ARR_LEN, RHO_LEN};

/// This is a helper function for computing a conversion of number of values to
/// number of bytes when encoding values using `d` bits each.
///
/// Returns a tuple indicating 1) number of values and 2) number of bytes
#[allow(clippy::integer_division_remainder_used)]
fn get_relative_steps(d: usize) -> (usize, usize) {
    match d {
        12 => (2, 3),
        5 => (8, 5),
        4 => (2, 1),
        _ => {
            let y = (d * 8) / gcd(d, 8);
            (y / d, y / 8)
        }
    }
}

#[allow(clippy::integer_division_remainder_used)]
fn gcd(x: usize, y: usize) -> usize {
    let mut x = x;
    let mut y = y;
    while y != 0 {
        let t = y;
        y = x % y;
        x = t;
    }
    x
}

// Algorithm 4 ByteEncode_d(F)
//
// Note: This algorithm performs compression as well as encoding.
pub(crate) fn byte_encode<D, const USIZE: usize>(
    ntt_vals: &NttArray<{ D::K }>,
    mut dst: impl AsMut<[u8]>,
) where
    D: EncodingSize,
{
    let bytes = dst.as_mut();
    let idx = USIZE * D::K * 32; // (32 = 256 / 8)

    // TODO should I remove this length check or convert it to a result?
    assert_eq!(
        bytes.len(),
        idx,
        "incorrect dst len {} != {idx}  K:{}",
        bytes.len(),
        D::K
    );

    let (val_step, byte_step) = get_relative_steps(USIZE);

    let vc = ntt_vals.as_flattened().chunks(val_step);
    let bc = bytes[..idx].chunks_mut(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut x = 0u128;
        for (j, vj) in v.iter().enumerate() {
            x |= u128::from(*vj) << (USIZE * j);
        }

        let xb = x.to_le_bytes();
        b.copy_from_slice(&xb[..byte_step]);
    }
}

// Algorithm 5 ByteDecode_d(F)
//
// Note: This function performs decompression as well as decoding.
pub(crate) fn byte_decode<D: EncodingSize, const USIZE: usize>(
    bytes: impl AsRef<[u8]>,
) -> NttArray<{ D::K }> {
    let (val_step, byte_step) = get_relative_steps(USIZE);
    let mask = (1 << USIZE) - 1;

    let mut vals = [[0u16; ARR_LEN]; D::K];

    let vc = vals.as_flattened_mut().chunks_mut(val_step);
    let bc = bytes.as_ref().chunks(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut xb = [0u8; 16];
        xb[..byte_step].copy_from_slice(b);

        let x = u128::from_le_bytes(xb);
        for (j, v_out) in v.iter_mut().enumerate() {
            // TODO: is the truncate implementation really necessary?
            let val: u16 = (x >> (USIZE * j)).truncate();
            *v_out = val & mask;

            if USIZE == 12 {
                *v_out %= FieldElement::Q;
            }
        }
    }
    vals
}

/// Safely truncate an unsigned integer value to shorter representation
pub trait Truncate<T> {
    fn truncate(self) -> T;
}

macro_rules! define_truncate {
    ($from:ident, $to:ident) => {
        impl Truncate<$to> for $from {
            fn truncate(self) -> $to {
                // This line is marked unsafe because the `unwrap_unchecked` call is UB when its
                // `self` argument is `Err`.  It never will be, because we explicitly zeroize the
                // high-order bits before converting.  We could have used `unwrap()`, but chose to
                // avoid the possibility of panic.
                unsafe { (self & $from::from($to::MAX)).try_into().unwrap_unchecked() }
            }
        }
    };
}

define_truncate!(u32, u16);
define_truncate!(u64, u32);
define_truncate!(usize, u8);
define_truncate!(u128, u16);
define_truncate!(u128, u8);

// ========================================================================== //
// FIPs spec EncapsulationKey Encoding
// ========================================================================== //

pub(crate) fn ek_encode<D>(
    rho: &[u8; 32],
    ntt_vals: &NttArray<{ D::K }>,
) -> Barr8<{ D::FIPS_ENCODED_SIZE }>
where
    D: EncodingSize,
    [(); D::USIZE]:,
{
    let mut bytes = [0u8; D::FIPS_ENCODED_SIZE];
    let idx = D::FIPS_ENCODED_SIZE - RHO_LEN;

    byte_encode::<D, { D::USIZE }>(ntt_vals, &mut bytes[..idx]);
    bytes[idx..].copy_from_slice(&rho[..]);

    bytes
}

pub(crate) fn ek_decode<D>(bytes: impl AsRef<[u8]>) -> ([u8; 32], NttArray<{ D::K }>)
where
    D: EncodingSize,
    [(); D::USIZE]:,
{
    //TODO: Lenth check on input for safety?
    assert!(
        bytes.as_ref().len() > (D::FIPS_ENCODED_SIZE - RHO_LEN),
        "incorrect src len for K:{}",
        D::K
    );

    let idx = bytes.as_ref().len() - RHO_LEN;
    let vals = byte_decode::<D, { D::USIZE }>(&bytes.as_ref()[..idx]);

    let mut rho = [0u8; RHO_LEN];
    rho.copy_from_slice(&bytes.as_ref()[idx..]);

    (rho, vals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncodingSize, FipsEncodingSize, RHO_LEN};
    use hex_literal::hex;

    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768};

    fn fips_encode_trial<D>()
    where
        D: KemCore + EncodingSize,
        [(); D::USIZE]:,
        [(); <D as EncodingSize>::K]:,
        [(); <D as FipsEncodingSize>::FIPS_ENCODED_SIZE]:,
    {
        let mut rng = rand::thread_rng();
        let (_, ek) = D::generate(&mut rng);

        let bytes_in = ek.as_bytes().to_vec();
        assert!(!bytes_in.is_empty());
        let (rho, ntt) = ek_decode::<D>(&bytes_in);

        let bytes_out = ek_encode::<D>(&rho, &ntt);
        // check that the byte representation of rho matches.
        assert_eq!(
            hex::encode(&bytes_in[..RHO_LEN]),
            hex::encode(&bytes_out[..RHO_LEN]),
            "rho values do not match"
        );
        // check that the byte representation of the polynomials matches.
        assert_eq!(
            hex::encode(&bytes_in[RHO_LEN..]),
            hex::encode(&bytes_out[RHO_LEN..]),
            "polynomials do not match"
        );

        let tmp = Encoded::<<D as KemCore>::EncapsulationKey>::try_from(&bytes_out[..])
            .expect("failed to build hybrid_array::Array from bytes");
        let reconst_ek = <D as KemCore>::EncapsulationKey::from_bytes(&tmp);
        assert_eq!(ek, reconst_ek);
    }

    #[test]
    fn custom_fips() {
        fips_encode_trial::<MlKem512>();
        fips_encode_trial::<MlKem768>();
        fips_encode_trial::<MlKem1024>();
    }

    #[test]
    fn fixed_encap_key() {
        let ek_bytes = hex!("1d04f737d1811f950ccc2340bff7640bd95ac2350b92ee6a5dcb4ccd05799bd2a25ad5b04a7a90a064387f9f8b6e77c60309a09b0d3307de9c936a91b797906674134fc9fbb5f1b450d5daa7ddc74c26d43aa8b351b4673f6bc32d89f460666475a28765ce722b42e682941b04635371a5234f6b168142c3366ce6bbd24a52a644619856c4303b0292227e9ae16ccaf33fc4f1a9fb537294b0261f7b1ca6ea14fa02bb12871add605345e4b18d446d5d33951d563b606c4329648b1c92a54f307ab7722294a95c1c42b3734586fd5044e39553c81458e1f85e4dec0275c9248ebc56f623cd08824386c16918a993e3454d1581c8a9c3a032b79d18e21f84c08e033bae46c098f6d55f83c28bef252aa43335dde63c96465125e46101accca40437a0810f616584d73cac1c54071a05c32f21bde9d2ad90e809f61862db966671eb2ace541290502d90185d819a7d0e566fa5e454e3cc7da8c93187a3af32dc831421c9b7ea984ad7c45483a119bca58ba8a1fc2201598884ce93255e359e8f989224548ab7f91657a56f83d68a21656d854432362a71d0727f45ca0138605885ac4314d2a1c8f61522e8aa91813fd6ab0ac438c04c182e25e774ac2c3c967306eda695d15505182a788191a46b3252a9917b56e23c92a7a51fc09f43221b806178272c11de8598f6a049d5ca2b342c08c4f13ca8d79ab7447bc0871ed525653b19b78bdb1fef17a3a14a2607dbcb7952a043012642a782d22706c08487bbcb95a6494dff891f75a86ce15c77c73c880e516a41139df7f0adf4d393cc564b68896d419948dcbb74740b5f85115c65ba0e5602449d10b20783abbd56b1b1b2cf5c73768563056eb76e8338515da7af1b62b29a05a1ed531de0b84b4c3033e80c3d50866dd3c0a17b9387e97963165720b587785912bdab15c946893024579923f16a46bbac862aa823d81619c616af92a0575019af5732c4a80686c1c4f81ac743611e45453e820878aa6498c28984b17b073d38945a73c8f8e033c038a5a25504a3324679490285be911109c35dec1c7ffa48d62c3acaddb348150b9a0de15d140000000000000000000000000000000000000000000000000000000000000000");

        let ek_encoded =
            Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem512Params>>::try_from(
                &ek_bytes[..],
            )
            .expect("failed to build hybrid array");
        let ek_decoded_in =
            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem512Params>::from_bytes(&ek_encoded);

        let (rho, ntt) = ek_decode::<MlKem512>(&ek_bytes);

        let bytes_out = ek_encode::<MlKem512>(&rho, &ntt);

        let ek_encoded =
            Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem512Params>>::try_from(
                &bytes_out[..],
            )
            .expect("failed to build hybrid array");
        let ek_decoded_out =
            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem512Params>::from_bytes(&ek_encoded);

        assert_eq!(ek_decoded_in, ek_decoded_out);
    }

    #[test]
    fn fixed_ciphertext() {
        let ct_512 = hex!("3cfb6267465190608ceb2f761536926f62c45fc590b5e08defbf308aced1057c75c7a1766df5c643d91aeeb206fa8e2dff19fdcc81719f15a9931685886431a58df6e85191b0efb5563d179347df8c64ea7107a53b2469d7bc029839e1eae1d1002b2657d235e2294fb54a1afe4921474af681b0cbda579a27a26aa76b946971625fb5e17776acd526f3c32439ee7bd507e4e140d28921db1f9aec34e66b832bb8e64c16e045b698b2466740d7d9d91c646d07f4f6520a8001554180bfa2f4c5aa7468e230be182164f16586f65756871dc3fe1167a158cf2560873c814ad15537434e46d579e5a6868f4821caef03696d90c1df03db08e5cf581c49a4b98fafac58334615c14165c95f8f7024c03dbb4f6c9e3bf57b75ac2e1626dc5f27eadfb32264f4c06455ad70969d9ce95fa47c52e0307889a92defa776ea849cdd97a8f0213c4f853a827a2a19cfb1d6d07d69df595540e443fe89bae0fe45cfb2c673b3c5eb88d739c50ec0e0de9afa19eed78b15e37c0eca4ca10d855e51f487e581eea83e5b0bfa8f65f2765d1c97f1d39957ccbd05b045a542eb25ce11e438b21d7d72835717f267aaf94d64e478f56c25314e4428b26a1996bf31b0c198c4cf4e0a3e6c56b8f093e6033f17d8eb2f6c73205cf850e063a4402b1ac3c4905f58286a20250897109ed5cc2b144566e5517b980e57c7283efa19096988ef0b1bcf50fc7dba740e4e731591937733ab015921f40a2297c29b240abde69008004ce7e45608a8d275c8bf8b2167532240bf2560d4e2cb961838d46d8c0a04ad45fdc5a5a33c5e0591f8de58bbb0a8e095140bffd983f2c4cf6d31000c9068b4743bcaa5a71c2177b4384c4b8a1c77653c5aa07cb3453c2d19c2e1b1cfa6785f7f6a86eef31fed1b7ac553e5a778b9ece3a25e9910110ae20647485cfe5cd969d069e9715f9303e6cd4a01b5dab9b0399a0fd7ec10a021f5f6573e61c40f64e45e201bb8392fdcc2252d688c9c968e30f77d1240150739c6011993ea27a6052a921d9ec24325306376c45a141bbd1b9ca265102e4b12d336d8b6f5b6d9b2f3711ed319d5");
        assert_eq!(768, ct_512.len());

        let ct_768 = hex!("2befc4e5a203ed15d9f3784e12d0dbdec25e856fa0bbee8d287da007a0717a81a5bc04a5b2e0a3feaa6ca879c1936c9e168bbe5d2a3ed4b4156b2536aa92303668d438d0bf828e73b28b2ec67975596665c65556ee1e4673ec27423724e0f9352bab375069c79ea74544886f5b965251288e97735ac4daedcb34592c6e0d56842177ed61c2af1af816734c8faa6235097add723928498d98546ac6de3a82930f7e2f3a88717e478c6e4e0337468d818644dae90c259d5bea576c4aa2cc0d3ad1b6276de9057433f8a75db4767f0ef5734121aa703d01fb40c9c86c470d3eb8e2ddba8a2113e7eaac16a304b119ec373f7dd5cbe85cc332a87a5fbd0fda63c1dc4c680747779c415a32667a5209d566e1374230212520b3298f12c2bbe4b8f98fbca494a84efaa2049191589e3a8e54042e0a97a1acd32639f989e0f7543e906b291ebc73d4f89a0fec6757a20852bb6e82b970d6faf257638b3cbc95159ba7ac0ddde481254a5c11f143d8d73f0f9d78c7155afa5e9370e612fdb38be3b25c7c2d3fdfafa66bd199ffb2d1a364884952d5ea887c32f78a953ef17ffa6ce41109bb611c1436fee3a4b36918a01242b3051d8af8764c45197096c8de1fb84ff44f3c3ed968083e4375ebfc3c275c70d0103efbd6a777bfa94ca28183e9a88f0466d987dda64a6a276bdc3c429c428f28c3829995f4b0da3d8bb9c9635e00fee9f1583077d4468d7653500ac0a200b18768e896ec00e0f9d6343acbd041e0591160f958d766b90bc655e2d0c80b69515c500158b41f67d9b778f1d1015f7e5d99c14ac99073d0810f36e91eef393b49e808273bf3f9e121d03f11055d6e44b5d5c5a63636659a4970add9e14b81fb85a2a372ad04fdd5341f715eced98d6820eaad46346b3d27bc6084d6d5404cde665f5b5cf4ee0e9633d670c3a322adb500ba8a953a2b5c2878d5cb9a348805d5e12a608227889cdb4efba56b9a1dea79651ee1fc14f2e810cdf99810bc88bbe8924f686dc24f7aca8089df299f9cf096a5926f047e0077f95e4aaf466777e4a1cb50a7cc32fb992595144988446b8752462706bb54d0d380d1b326f87f307706deb71c9357d15cd3002887f493ffc498db55ec99a2ed2bf72031d733d86a5281239072028e286a0911407bfce39db7dfb1177a9a01d29e28981fd8ff0c8d0776d306ed720b8f71161cb0cda9abb1a9c09ed275bcb53d807df10e5c2ce68c456edd06094b0616ada5c3b9775113e44069bb7a5a2d24418a0e51866f033479e9f0c4a77ddcdc93058d557b44208c314ed6298099258dc9861d03f750ea65aa97a9fcca6e76c83f39ebc5f6d3b2afdef7adb7bf427f46ef30162036f1d336764f5ad3a1de105e754d24a50435197076b772321d17b133402e8b3dc8831d191b92c6b60d2bcfe894d71c571410b2d6429116bcb6484267a2155beddbb734821a7489353c4cdf624d457272df18dbabaafd0d324aaf4fbb0186cceb7fcee4f5e136ac2e13b702ae846fd7940b540d015329a4677d9a");
        assert_eq!(1088, ct_768.len());

        let ct_1024 = hex!("fc9c673f51012ae9dcb35099ccaf1427be775a5a5f1316376c4c30f830e4720c46164f20fb7fcd6c4160c7e62aeea1705081c37d798feeae7de9ff45a7dbc05f438ef554920cf06920d2119a3fdd6cd0cfeef2917e2e118a5e06e8c9e6beb7893d00425d8e2689ff2e9079053e30ccb5e891efb01a3376dbb4deca7838f0b94501bcb1934e9192a0461a96e20a91b54e2c46e50cddc78f7c7b6227ba545b999f432b3b2ec361bc06f93ba827c70e2992a5d301e8341563671287ab8c23203910399dfc5366a5f3c88129db6fec9d6aafb3dfd8b73d45a9bd398f73f440a3c9c1eac77c8b127e739a9f8c1c4687ae7f642fc1328747fd8019e67c02ee4b859383beb01ce581233d4d001de893b00ac1141df3674774c7dae51f550339d5e603143412a33ce2fd0e7aa7100d2f8c985d46cc1207b9fa46eeccd98152dd3482383a11d8e47341aed00a1a65b636e0b9e95b97e22c39b8a8253db0e518fc992a9bf4fb40e816152007b270bb4378f139d4becd7d58051467e38b3e4202c187140b77198fce4530be7434ff3f6a95801e99aa387fae5e2d3b35a8c03aaea42632327da2ae53a78d0ea1e46c8f9bba4ec0ccf726102efe8f1462a8146a49cb2f8f472b503a954bae4e0e9623e2422517444073e41bb2e84956d3541e10bc5f74e453624b92ac743a4cb4ebcf2746013d3a2bbf303bc2b9d9cf85b1fc9b12d478ea81ec9cedb37456d6ac03cdfb972eef277940560d84849bf349d82908cb0b47d45adf4def30740f50b86a4a664971032d76920f939be461f8c1da078ca0dd136f16bdd1c3b958c796951ff3fe45e68bed2714e5e31514fcfc937a53cd905f80787e4ef65f22a8382976b350248569993d40f6885ad3697658ff29e65b854ef1f4311589afb70d438c599c79ed6a8452a3ee10343a61c12481d6dacd6bf0f3731c6b02d10fef9425848fff381f359b1d615a92ffa41a36d1200defef54c813581ab00be6b0bb865b56735f5f6a717e626ce90e50b7ef1ab6552bfdaf28d4d1de46d13821312b599d3ae579bced2db8aa5b405bb3e083734b9a3bfb593aa6028cbfba8732d46915d990d22cc8e9eb420a0a81d4546e388910ee5387a7f233dc905f8efcd5c603ba36c80c22755867a5017a606939d77cedf1240f3bcff4e336b3e181dde1d4faa10fcf122a28b655e55da4a675f40e84ab6d8274545e5c66268445f9ba6155ebedb8fba1713c2076ce7c6873d73720057249a6ee14fa55ffb74a2cbe632c1bd63baf21c69a7aae4b3100e73c8a3314217594772a286241c7a7929fa606507da8b90167f3d0fc6941de41353c1d88bc07c173f83c19e6271cc9b7a8bed1e69f7033c2db609625d64d4cb037436e936911253eda508b2c3eb5c8480838564a2fdab8c920ff1f6034c87e7b74e4c2016400b4f650e2a3ea5335963ebb0c596f148f23e8d605e04efc9b6572a89b382d04eb93d4d2333b3b54242272eed2c0eec40a3af93320749ea9429f1b69ac580f4dbf4cb077f786c2ddb9c250e5e3f8f40855037d34aa19e866e7c83aeec77f35c2697831994f72b563f184c2be6e7d7ce2d39d6600034f3992dda35cd519b4475f7d9f12abe1161920ea1c593233489153124a0e4a0be521a402be2761a7471315ec6847072f333ea9a931392262c9af9103e8b09b75294aec13aafb115a852e998ad406cca3813104c08755239e547deb8e60d7bd07d6170cad7ac46b317302fc0acb63cead36c25028dae897ea35f108cb47cf1eaa864db78ca5d99a41af3990cc54655434b5caf6dbac421017e057ec5a7cec1e1c9dd317a7d5645d4a48546ccc982cbc7eb66d3066fc4f1b4dc3cacd98f03dcf9e1adc8f42f82d98a06b74f122bb130108599dc9da3dbaa6c53c1191c33ee51f2497100b3e900f402d73236295dc5b7f41eb019c5cd332958529e13f63fb25d69767175dcb1641717858d923caeea526a6edb5dbaf268bcd61a8909eccdb403b5caac6c280200cc51470a7e2419eac0ad5b5260deeee198dd2a71162dabd967ebd1107ad9fa33f73221944415749434d73d6c7fcb3bb0009ebf6ec34b3d0c1457d0bf19a88b5c7bbf32c43de0def9ab4962aaf958e8f9abac073c77c5d8a59e0f00e0bf63e55d794f56427bd82a4c3cff49f7c93ac3a77a0401e58f5174bfa9b25f845fdccb9c67919d5679960b07a45ce56645a036fe83111c6");
        assert_eq!(1568, ct_1024.len());
    }
}
