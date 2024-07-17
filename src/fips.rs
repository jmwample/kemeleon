
use std::io::Error;
use crate::{ValueArray, EncodingSize, FieldElement, ARR_LEN};


// Algorithm 4 ByteEncode_d(F)
//
// Note: This algorithm performs compression as well as encoding.
fn byte_encode<D: EncodingSize>(vals: &ValueArray) -> Vec<u8> {
    let val_step = D::VALUE_STEP;
    let byte_step = D::BYTE_STEP;

    let mut bytes = Vec::with_capacity(D::ENCODED_SIZE);

    let vc = vals.chunks(val_step);
    let bc = bytes.chunks_mut(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut x = 0u128;
        for (j, vj) in v.iter().enumerate() {
            x |= u128::from(vj.0) << (D::USIZE * j);
        }

        let xb = x.to_le_bytes();
        b.copy_from_slice(&xb[..byte_step]);
    }

    bytes
}

// Algorithm 5 ByteDecode_d(F)
//
// Note: This function performs decompression as well as decoding.
fn byte_decode<D: EncodingSize>(bytes: impl AsRef<[u8]>)  -> Result<ValueArray, Error> {
    let val_step = D::VALUE_STEP;
    let byte_step = D::BYTE_STEP;
    let mask = (1 << D::USIZE) - 1;

    let mut vals = [FieldElement(0u16); ARR_LEN];

    let vc = vals.chunks_mut(val_step);
    let bc = bytes.as_ref().chunks(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut xb = [0u8; 16];
        xb[..byte_step].copy_from_slice(b);

        let x = u128::from_le_bytes(xb);
        for j in 0..v.len() {
            let val: u16 = (x >> (D::USIZE * j)) as u16;
            let mut vj = val & mask;

            if D::USIZE == 12 {
                vj %= FieldElement::Q;
            }
            v[j] = FieldElement(vj);
        }
    }

    Ok(vals)
}
