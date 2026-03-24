// Core implementation — wraps the Rust WASM API.
// All free() calls happen here in try/finally — never exposed to the consumer.
// Parameter order is normalized here: StenVault convention (ct, sk), (msg, sk)
// maps to Rust convention (dk, ct), (sk, msg) internally.
//
// This file is imported by index.browser.ts and index.node.ts, which each
// provide their own ensurePqcInit() before delegating here.

import type { KemKeyPair, EncapsulateResult, SignatureKeyPair } from './types.js'

// The WASM bindings — injected by the index files after init
type WasmBindings = typeof import('../pkg-bundler/stenvault_pqc.js')

let wasm: WasmBindings | null = null

export function setWasmBindings(bindings: WasmBindings): void {
  wasm = bindings
}

function getWasm(): WasmBindings {
  if (!wasm) throw new Error('@stenvault/pqc-wasm: WASM not initialized. This is a bug.')
  return wasm
}

// ── ML-KEM-768 ──────────────────────────────────────────────────────────────

export function generateKemKeyPairCore(): KemKeyPair {
  const w = getWasm()
  const kp = w.ml_kem_768_generate()
  try {
    return {
      publicKey: new Uint8Array(kp.encapsulation_key),
      secretKey: new Uint8Array(kp.decapsulation_key),
    }
  } finally {
    kp.free()
  }
}

export function encapsulateCore(publicKey: Uint8Array): EncapsulateResult {
  const w = getWasm()
  const result = w.ml_kem_768_encapsulate(publicKey)
  try {
    return {
      ciphertext: new Uint8Array(result.ciphertext),
      sharedSecret: new Uint8Array(result.shared_secret),
    }
  } finally {
    result.free()
  }
}

export function decapsulateCore(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const w = getWasm()
  // Rust API: (dk, ct) — we receive (ct, sk) from StenVault convention
  return new Uint8Array(w.ml_kem_768_decapsulate(secretKey, ciphertext))
}

// ── ML-DSA-65 ───────────────────────────────────────────────────────────────

export function generateSignatureKeyPairCore(): SignatureKeyPair {
  const w = getWasm()
  const kp = w.ml_dsa_65_generate()
  try {
    return {
      publicKey: new Uint8Array(kp.verifying_key),
      secretKey: new Uint8Array(kp.signing_key),
    }
  } finally {
    kp.free()
  }
}

export function signCore(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const w = getWasm()
  // Rust API: (sk, msg) — we receive (msg, sk) from StenVault convention
  return new Uint8Array(w.ml_dsa_65_sign(secretKey, message))
}

export function verifyCore(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  const w = getWasm()
  // Rust API: (vk, msg, sig) — we receive (msg, sig, pk) from StenVault convention
  return w.ml_dsa_65_verify(publicKey, message, signature)
}
