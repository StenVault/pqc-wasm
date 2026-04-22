#![no_main]
use libfuzzer_sys::fuzz_target;
use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1952 + 3309 {
        return;
    }
    let vk_bytes = &data[..1952];
    let sig_bytes = &data[1952..1952 + 3309];
    let message = &data[1952 + 3309..];

    let vk_enc = match EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);

    let sig = match Signature::<MlDsa65>::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = vk.verify(message, &sig);
});
