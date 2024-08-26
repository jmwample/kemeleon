//! This implementation of the compress functionality was drawn from the `RustCrypto`
//! implementation of ML KEM as compress / decompress functionality is required
//! for this crate, but is not exposed publicly from `RustCrypto/ml-kem`.
//! Both the Apache2 and MIT licenses for the `RustCrypto` crate are included in
//! `docs/licenses/`.

use crate::{fips::Truncate, FieldElement};

use core::slice::IterMut;

pub(crate) struct Du<const USIZE: usize> {}

pub(crate) trait CompressionFactor {
    const USIZE: usize;
    const POW2_HALF: u32;
    const MASK: u16;
    const DIV_SHIFT: usize;
    const DIV_MUL: u64;
    const Q_HALF: u64 = (FieldElement::Q64 + 1) >> 1;
}

impl<const USIZE: usize> CompressionFactor for Du<{ USIZE }> {
    const USIZE: usize = USIZE;
    const POW2_HALF: u32 = 1 << (Self::USIZE - 1);
    const MASK: u16 = ((1_u16) << Self::USIZE) - 1;
    const DIV_SHIFT: usize = 34;
    #[allow(clippy::integer_division_remainder_used)]
    const DIV_MUL: u64 = (1 << Self::DIV_SHIFT) / FieldElement::Q64;
}

// Traits for objects that allow compression / decompression
pub(crate) trait Compress {
    fn compress<D: CompressionFactor>(&mut self) -> &Self;
    fn decompress<D: CompressionFactor>(&mut self) -> &Self;
}

impl Compress for u16 {
    // Equation 4.5: Compress_d(x) = round((2^d / q) x)
    //
    // Here and in decompression, we leverage the following facts:
    //
    //   round(a / b) = floor((a + b/2) / b)
    //   a / q ~= (a * x) >> s where x >> s ~= 1/q
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        let x = u64::from(*self);
        let y = ((((x << D::USIZE) + D::Q_HALF) * D::DIV_MUL) >> D::DIV_SHIFT).truncate();
        *self = y.truncate() & D::MASK;
        self
    }

    // Equation 4.6: Decompress_d(x) = round((q / 2^d) x)
    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        let x = u32::from(*self);
        let y = ((x * FieldElement::Q32) + D::POW2_HALF) >> D::USIZE;
        *self = y.truncate();
        self
    }
}

impl Compress for FieldElement {
    // Equation 4.5: Compress_d(x) = round((2^d / q) x)
    //
    // Here and in decompression, we leverage the following facts:
    //
    //   round(a / b) = floor((a + b/2) / b)
    //   a / q ~= (a * x) >> s where x >> s ~= 1/q
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        let x = u64::from(self.0);
        let y = ((((x << D::USIZE) + D::Q_HALF) * D::DIV_MUL) >> D::DIV_SHIFT).truncate();
        self.0 = y.truncate() & D::MASK;
        self
    }

    // Equation 4.6: Decompress_d(x) = round((q / 2^d) x)
    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        let x = u32::from(self.0);
        let y = ((x * FieldElement::Q32) + D::POW2_HALF) >> D::USIZE;
        self.0 = y.truncate();
        self
    }
}

impl<'a> Compress for IterMut<'a, u16> {
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        self.for_each(|fe| {
            fe.compress::<D>();
        });
        self
    }

    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        self.for_each(|fe| {
            fe.decompress::<D>();
        });
        self
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use num_rational::Ratio;

    fn rational_compress<D: CompressionFactor>(input: u16) -> u16 {
        let fraction = Ratio::new(u32::from(input) * (1 << D::USIZE), FieldElement::Q32);
        (fraction.round().to_integer() as u16) & D::MASK
    }

    fn rational_decompress<D: CompressionFactor>(input: u16) -> u16 {
        let fraction = Ratio::new(u32::from(input) * FieldElement::Q32, 1 << D::USIZE);
        fraction.round().to_integer() as u16
    }

    // Verify against inequality 4.7
    #[allow(clippy::integer_division_remainder_used)]
    fn compression_decompression_inequality<D: CompressionFactor>() {
        const QI32: i32 = FieldElement::Q as i32;
        let error_threshold = i32::from(Ratio::new(FieldElement::Q, 1 << D::USIZE).to_integer());

        for x in 0..FieldElement::Q {
            let mut y = FieldElement(x);
            y.compress::<D>();
            y.decompress::<D>();

            let mut error = i32::from(y.0) - i32::from(x) + QI32;
            if error > (QI32 - 1) / 2 {
                error -= QI32;
            }

            assert!(
                error.abs() <= error_threshold,
                "Inequality failed for x = {x}: error = {}, error_threshold = {error_threshold}, D = {:?}",
                error.abs(),
                D::USIZE
            );
        }
    }

    fn decompression_compression_equality<D: CompressionFactor>() {
        for x in 0..(1 << D::USIZE) {
            let mut y = FieldElement(x);
            y.decompress::<D>();
            y.compress::<D>();

            assert_eq!(y.0, x, "failed for x: {}, D: {}", x, D::USIZE);
        }
    }

    fn decompress_KAT<D: CompressionFactor>() {
        for y in 0..(1 << D::USIZE) {
            let x_expected = rational_decompress::<D>(y);
            let mut x_actual = FieldElement(y);
            x_actual.decompress::<D>();

            assert_eq!(x_expected, x_actual.0);
        }
    }

    fn compress_KAT<D: CompressionFactor>() {
        for x in 0..FieldElement::Q {
            let y_expected = rational_compress::<D>(x);
            let mut y_actual = FieldElement(x);
            y_actual.compress::<D>();

            assert_eq!(y_expected, y_actual.0, "for x: {}, D: {}", x, D::USIZE);
        }
    }

    fn compress_decompress_properties<D: CompressionFactor>() {
        compression_decompression_inequality::<D>();
        decompression_compression_equality::<D>();
    }

    fn compress_decompress_KATs<D: CompressionFactor>() {
        decompress_KAT::<D>();
        compress_KAT::<D>();
    }

    #[test]
    fn decompress_compress() {
        compress_decompress_properties::<Du<1>>();
        compress_decompress_properties::<Du<4>>();
        compress_decompress_properties::<Du<5>>();
        compress_decompress_properties::<Du<6>>();
        compress_decompress_properties::<Du<10>>();
        compress_decompress_properties::<Du<11>>();
        // preservation under decompression first only holds for d < 12
        compression_decompression_inequality::<Du<12>>();

        compress_decompress_KATs::<Du<1>>();
        compress_decompress_KATs::<Du<4>>();
        compress_decompress_KATs::<Du<5>>();
        compress_decompress_KATs::<Du<6>>();
        compress_decompress_KATs::<Du<10>>();
        compress_decompress_KATs::<Du<11>>();
        compress_decompress_KATs::<Du<12>>();
    }
}
