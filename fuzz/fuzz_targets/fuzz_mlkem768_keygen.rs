#![no_main]
use libfuzzer_sys::fuzz_target;
use ml_kem::{KemCore, MlKem768};
use rand_core::{CryptoRng, RngCore};

/// Deterministic RNG backed by fuzzer-supplied bytes.
/// Returns 0x00 once the input is exhausted.
struct SliceRng<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceRng<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl RngCore for SliceRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.pos < self.data.len() {
                *byte = self.data[self.pos];
                self.pos += 1;
            } else {
                *byte = 0;
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SliceRng<'_> {}

// ML-KEM-768 keygen needs 64 bytes of randomness (d=32 + z=32).
// Feed arbitrary fuzzer bytes as the RNG source.
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut rng = SliceRng::new(data);
    let _ = MlKem768::generate(&mut rng);
});
