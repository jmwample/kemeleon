
use crate::{EncodingSize, Barr8, ARR_LEN, RHO_LEN};
use super::{Encode, vector_decode};

use core::marker::PhantomData;
use std::io::Error as IoError;

use ml_kem::{Ciphertext, KemCore};

// ========================================================================== //
// CipherText
// ========================================================================== //

pub use crate::mlkem::EncodedCiphertext;

impl<P> Encode for EncodedCiphertext<P>
where
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::FIPS_ENCODED_SIZE]:,
    [(); <P as EncodingSize>::K * RHO_LEN]:,
{
    /// Encapsulation Key
    type EK = Self;

    /// Encoded Cuphertext Type
    type ET = Barr8<{ P::K * RHO_LEN }>;

    /// Error Type returned on failed decode
    type Error = IoError;

    fn as_bytes(&self) -> Self::ET {
        // self.bytes.clone()
        let mut out = [0u8; P::K * RHO_LEN];
        self.encode(&mut out).expect("shouldn't happen");
        out
    }

    fn try_from_bytes(b: impl AsRef<[u8]>) -> Result<Self, IoError> {
        if b.as_ref().is_empty() {
            return Err(IoError::other("bad bytestring provided"));
        }

        let fips = Ciphertext::<P>::try_from(&b.as_ref()[..])
            .map_err(|_| IoError::other("failed to parse as ciphertext"))?;

        Ok(Self {
            bytes: b.as_ref().to_vec(),
            fips,
            _p: PhantomData,
        })
    }
}

impl<P> EncodedCiphertext<P>
where 
    P: KemCore + EncodingSize,
    [(); P::K]:,
    [(); P::FIPS_ENCODED_SIZE]:,
{

    fn decode(c: impl AsRef<[u8]>) -> Result<Self, IoError> {
        let idx_r1 = P::DV * ARR_LEN;
        let r1 = &c.as_ref()[..c.as_ref().len() - idx_r1];
        let c2 = &c.as_ref()[idx_r1..];

        let mut values = [[0u16; ARR_LEN]; P::K];
        vector_decode::<P>(r1, values.as_flattened_mut())
            .map_err(|e| IoError::other("error occured while decoding"))?;

        let c1 = compress(values.as_flattened(), P::DU);
        let mut ctxt = c1.to_vec();
        // ctxt.append(c2);

        // match Ciphertext::<P>::try_from(&ctxt[..]) {
        //     Err(e) => Err(IoError::other("error occured while decoding")),
        //     Ok(pt) => Ok(Self{ bytes: pt.to_vec(), _p: PhantomData{} }),
        // }
        todo!("not yet implemented");
    }

    fn encode(&self, mut dst: impl AsMut<[u8]>) -> Result<(), IoError> {
        todo!("not yet implemented");
    }
}

const QFD: f64 = 4096.0 / 3329.0;
const DFQ: f64 = 3329.0 / 4096.0;

/// x −→ ⌈((2^d)/q)· x⌋
fn compress(u: impl AsRef<[u16]>, _du: usize) -> Vec<u16> {
    u.as_ref().iter().map(|v| (*v as f64 * QFD + 0.5) as u16).collect()
}

/// y −→ ⌈(q/(2^d))· y⌋

fn decompress(c: impl AsRef<[u16]>, _du: usize) -> Vec<u16> {
    c.as_ref().iter().map(|v| (*v as f64 * DFQ + 0.5) as u16).collect()
}


#[cfg(test)]
mod test {
    // #[test]
    // fn encode_decode() {
    //     todo!("test not implemented yet");
    // }
}
