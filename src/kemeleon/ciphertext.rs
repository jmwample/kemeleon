
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
        todo!("Ciphertext encoding not implemented yet")
    }

    fn try_from_bytes(b: impl AsRef<[u8]>) -> Result<Self, IoError> {
        if b.as_ref().is_empty() {
            return Err(IoError::other("bad bytestring provided"));
        }
        Ok(Self {
            bytes: b.as_ref().to_vec(),
            _p: PhantomData,
        })
    }
}

impl<P> EncodedCiphertext<P>
where 
    P: KemCore + EncodingSize,
{

    // fn decode( c: impl AsRef<[u8]>, mut dst: impl AsMut<[u8]>) -> Result<Self, IoError> {
    //     let idx_r1 = P::DV * ARR_LEN;
    //     let r1 = &c.as_ref()[..c.as_ref().len() - idx_r1];
    //     let r2 = &c.as_ref()[idx_r1..];

    //     let u = decode_priv::<P>(r2).map_err(|e| IoError::other("error occured while decoding"))?;
    //     let c1 = compress(Into::<[u16; ARR_LEN]>::into(u), P::DU);
    //     let ctxt: Vec<u16> = c1.iter().zip(r2).map(|(v1, v2)| v1 | v2).collect();

    //     match Ciphertext::<P>::try_from(&ctxt[..]) {
    //         Err(e) => Err(IoError::other("error occured while decoding")),
    //         Ok(pt) => Ok(Self{ bytes: pt.to_vec(), _p: PhantomData{} }),
    //     }
    //     // todo!("not yet implemented");
    // }

    fn encode(mut dst: impl AsMut<[u8]>) -> Result<(), IoError> {
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
    #[test]
    fn encode_decode() {
        todo!("test not implemented yet");
    }
}
