#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── ML-KEM-768 (FIPS 203) ──────────────────────────────────────────────────

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKem768KeyPair {
    encapsulation_key: Vec<u8>,
    #[zeroize]
    decapsulation_key: Vec<u8>,
}

#[wasm_bindgen]
impl MlKem768KeyPair {
    #[wasm_bindgen(getter)]
    pub fn encapsulation_key(&self) -> Vec<u8> {
        self.encapsulation_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn decapsulation_key(&self) -> Vec<u8> {
        self.decapsulation_key.clone()
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKem768EncapResult {
    ciphertext: Vec<u8>,
    #[zeroize]
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl MlKem768EncapResult {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

#[wasm_bindgen]
pub fn ml_kem_768_generate() -> MlKem768KeyPair {
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

    let mut rng = rand_core::OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);

    MlKem768KeyPair {
        encapsulation_key: ek.as_bytes()[..].to_vec(),
        decapsulation_key: dk.as_bytes()[..].to_vec(),
    }
}

#[wasm_bindgen]
pub fn ml_kem_768_encapsulate(ek_bytes: &[u8]) -> Result<MlKem768EncapResult, JsError> {
    use ml_kem::kem::Encapsulate;
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

    type EK = <MlKem768 as KemCore>::EncapsulationKey;

    if ek_bytes.len() != 1184 {
        return Err(JsError::new("invalid encapsulation key length: expected 1184 bytes"));
    }

    let ek_enc = ml_kem::Encoded::<EK>::from_fn(|i| ek_bytes[i]);
    let ek = EK::from_bytes(&ek_enc);

    let mut rng = rand_core::OsRng;
    let (ct, ss) = ek
        .encapsulate(&mut rng)
        .map_err(|_| JsError::new("encapsulation failed"))?;

    Ok(MlKem768EncapResult {
        ciphertext: ct[..].to_vec(),
        shared_secret: ss[..].to_vec(),
    })
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKem768DecapResult {
    #[zeroize]
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl MlKem768DecapResult {
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

#[wasm_bindgen]
pub fn ml_kem_768_decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<MlKem768DecapResult, JsError> {
    use ml_kem::kem::Decapsulate;
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

    type DK = <MlKem768 as KemCore>::DecapsulationKey;
    type CT = ml_kem::Ciphertext<MlKem768>;

    if dk_bytes.len() != 2400 {
        return Err(JsError::new("invalid decapsulation key length: expected 2400 bytes"));
    }
    if ct_bytes.len() != 1088 {
        return Err(JsError::new("invalid ciphertext length: expected 1088 bytes"));
    }

    let dk_enc = ml_kem::Encoded::<DK>::from_fn(|i| dk_bytes[i]);
    let dk = DK::from_bytes(&dk_enc);

    let ct = CT::from_fn(|i| ct_bytes[i]);

    let ss = dk
        .decapsulate(&ct)
        .map_err(|_| JsError::new("decapsulation failed"))?;

    Ok(MlKem768DecapResult {
        shared_secret: ss[..].to_vec(),
    })
}

// ── ML-DSA-65 (FIPS 204) ───────────────────────────────────────────────────

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65KeyPair {
    verifying_key: Vec<u8>,
    #[zeroize]
    signing_key: Vec<u8>,
}

#[wasm_bindgen]
impl MlDsa65KeyPair {
    #[wasm_bindgen(getter)]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.verifying_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signing_key(&self) -> Vec<u8> {
        self.signing_key.clone()
    }
}

#[wasm_bindgen]
pub fn ml_dsa_65_generate() -> MlDsa65KeyPair {
    use ml_dsa::{B32, KeyGen, MlDsa65};
    use ml_dsa::signature::Keypair;

    // getrandom with the `js` feature routes to crypto.getRandomValues under wasm32
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).expect("getrandom failed");
    let mut seed = B32::from(seed_bytes);
    seed_bytes.zeroize();

    let kp = <MlDsa65 as KeyGen>::from_seed(&seed);
    let verifying_key = kp.verifying_key().encode()[..].to_vec();
    let signing_key = seed.as_slice().to_vec();
    seed.zeroize();

    MlDsa65KeyPair {
        verifying_key,
        signing_key,
    }
}

#[wasm_bindgen]
pub fn ml_dsa_65_sign(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    use ml_dsa::{B32, ExpandedSigningKey, MlDsa65};
    use ml_dsa::signature::Signer;

    if sk_bytes.len() != 32 {
        return Err(JsError::new("invalid signing key length: expected 32 bytes"));
    }

    let seed_arr: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| JsError::new("invalid signing key seed encoding"))?;
    let seed = B32::from(seed_arr);

    let sk = ExpandedSigningKey::<MlDsa65>::from_seed(&seed);
    let sig = sk.try_sign(message)
        .map_err(|e| JsError::new(&format!("signing failed: {}", e)))?;

    Ok(sig.encode()[..].to_vec())
}

#[wasm_bindgen]
pub fn ml_dsa_65_verify(vk_bytes: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
    use ml_dsa::{MlDsa65, Signature, VerifyingKey, EncodedVerifyingKey};
    use ml_dsa::signature::Verifier;

    if vk_bytes.len() != 1952 {
        return Err(JsError::new("invalid verifying key length: expected 1952 bytes"));
    }
    if signature.len() != 3309 {
        return Err(JsError::new("invalid signature length: expected 3309 bytes"));
    }

    let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes)
        .map_err(|_| JsError::new("invalid verifying key encoding"))?;
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);

    let sig = Signature::<MlDsa65>::try_from(signature)
        .map_err(|_| JsError::new("invalid signature encoding"))?;

    Ok(vk.verify(message, &sig).is_ok())
}
