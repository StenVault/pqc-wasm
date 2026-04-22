#![no_main]
use libfuzzer_sys::fuzz_target;
use ml_kem::kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

type DK = <MlKem768 as KemCore>::DecapsulationKey;
type CT = ml_kem::Ciphertext<MlKem768>;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2400 + 1088 {
        return;
    }
    let dk_bytes = &data[..2400];
    let ct_bytes = &data[2400..2400 + 1088];

    let dk_enc = ml_kem::Encoded::<DK>::from_fn(|i| dk_bytes[i]);
    let dk = DK::from_bytes(&dk_enc);

    let ct = CT::from_fn(|i| ct_bytes[i]);

    let _ = dk.decapsulate(&ct);
});
