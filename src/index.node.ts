// Node.js entry point — uses pkg-nodejs (CommonJS + fs WASM loading)
// ensurePqcInit() is internal, never exposed to the consumer.

import * as wasmBindings from '../pkg-nodejs/stenvault_pqc.js'
import { setWasmBindings, generateKemKeyPairCore, encapsulateCore, decapsulateCore, generateSignatureKeyPairCore, signCore, verifyCore } from './core.js'
import type { KemKeyPair, EncapsulateResult, SignatureKeyPair } from './types.js'

export type { KemKeyPair, EncapsulateResult, SignatureKeyPair, PqcApi } from './types.js'

// ── WASM init — invisible to consumer ───────────────────────────────────────

let initialized = false

function ensurePqcInit(): void {
  if (!initialized) {
    // pkg-nodejs target loads WASM synchronously via fs.readFileSync
    // No async init() needed — bindings are ready after require/import
    setWasmBindings(wasmBindings as any)
    initialized = true
  }
}

// ── ML-KEM-768 — public stable API ─────────────────────────────────────────

export async function generateKemKeyPair(): Promise<KemKeyPair> {
  ensurePqcInit()
  return generateKemKeyPairCore()
}

export async function encapsulate(publicKey: Uint8Array): Promise<EncapsulateResult> {
  ensurePqcInit()
  return encapsulateCore(publicKey)
}

export async function decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  ensurePqcInit()
  return decapsulateCore(ciphertext, secretKey)
}

// ── ML-DSA-65 — public stable API ──────────────────────────────────────────

export async function generateSignatureKeyPair(): Promise<SignatureKeyPair> {
  ensurePqcInit()
  return generateSignatureKeyPairCore()
}

export async function sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  ensurePqcInit()
  return signCore(message, secretKey)
}

export async function verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  ensurePqcInit()
  return verifyCore(message, signature, publicKey)
}
