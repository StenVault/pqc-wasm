#![no_main]
use libfuzzer_sys::fuzz_target;
use ml_dsa::signature::Signer;
use ml_dsa::{B32, ExpandedSigningKey, MlDsa65};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let seed_arr: [u8; 32] = data[..32].try_into().unwrap();
    let seed = B32::from(seed_arr);
    let message = &data[32..];

    let sk = ExpandedSigningKey::<MlDsa65>::from_seed(&seed);
    let _ = sk.try_sign(message);
});
