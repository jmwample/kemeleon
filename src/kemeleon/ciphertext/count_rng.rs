use rand::{CryptoRng, Error, RngCore};

pub struct CountingRng<R: CryptoRng + RngCore> {
    bytes_used: usize,
    rng: R,
}

impl<R: RngCore + CryptoRng> CountingRng<R> {
    fn new(rng: R) -> Self {
        Self { bytes_used: 0, rng }
    }

    fn bytes_used(&self) -> usize {
        self.bytes_used
    }
}

impl<R: RngCore + CryptoRng> RngCore for CountingRng<R> {
    fn next_u32(&mut self) -> u32 {
        self.bytes_used += 4;
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.bytes_used += 8;
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.bytes_used += dest.len();
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        if let Err(e) = self.rng.try_fill_bytes(dest) {
            Err(e)
        } else {
            self.bytes_used += dest.len();
            Ok(())
        }
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for CountingRng<R> {}

#[cfg(test)]
mod test {
    use rand::RngCore;

    use super::CountingRng;

    #[test]
    fn it_works() {
        let mut rng = CountingRng {
            bytes_used: 0,
            rng: rand::thread_rng(),
        };
        let _ = rng.next_u32();
        assert_eq!(4, rng.bytes_used);

        let _ = rng.next_u64();
        assert_eq!(12, rng.bytes_used);

        let mut buf = [0u8; 1];
        rng.fill_bytes(&mut buf);
        assert_eq!(13, rng.bytes_used);

        let mut buf = [0u8; 512];
        rng.fill_bytes(&mut buf);
        assert_eq!(525, rng.bytes_used);

        let b: &mut [u8] = &mut [];
        rng.try_fill_bytes(b).expect("errored");
        assert_eq!(525, rng.bytes_used);

        let mut buf = [0u8; 512];
        rng.try_fill_bytes(&mut buf).expect("shouldn't fail");
        assert_eq!(1037, rng.bytes_used);
    }
}
