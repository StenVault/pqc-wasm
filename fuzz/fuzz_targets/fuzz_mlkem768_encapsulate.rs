#![no_main]
use libfuzzer_sys::fuzz_target;
use ml_kem::kem::Encapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::{CryptoRng, RngCore};

type EK = <MlKem768 as KemCore>::EncapsulationKey;

/// Deterministic RNG backed by fuzzer-supplied bytes.
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

fuzz_target!(|data: &[u8]| {
    if data.len() < 1184 {
        return;
    }
    let ek_bytes = &data[..1184];
    let ek_enc = ml_kem::Encoded::<EK>::from_fn(|i| ek_bytes[i]);
    let ek = EK::from_bytes(&ek_enc);

    let mut rng = SliceRng::new(&data[1184..]);
    let _ = ek.encapsulate(&mut rng);
});
