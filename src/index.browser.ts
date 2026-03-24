// Browser entry point — uses pkg-bundler (Vite/webpack ESM)
// ensurePqcInit() is internal, never exposed to the consumer.
//
// wasm-bindgen bundler target auto-initializes via:
//   import * as wasm from "./stenvault_pqc_bg.wasm"
// The bundler (Vite/webpack) resolves the .wasm import at build time.
// No explicit init() call is needed — bindings are ready after import.

import * as wasmBindings from '../pkg-bundler/stenvault_pqc.js'
import { setWasmBindings, generateKemKeyPairCore, encapsulateCore, decapsulateCore, generateSignatureKeyPairCore, signCore, verifyCore } from './core.js'
import type { KemKeyPair, EncapsulateResult, SignatureKeyPair } from './types.js'

export type { KemKeyPair, EncapsulateResult, SignatureKeyPair, PqcApi } from './types.js'

// ── WASM init — invisible to consumer ───────────────────────────────────────

let initialized = false

function ensurePqcInit(): void {
  if (!initialized) {
    setWasmBindings(wasmBindings as any)
    initialized = true
  }
}

// ── ML-KEM-768 — public stable API ─────────────────────────────────────────

export async function generateKemKeyPair(): Promise<KemKeyPair> {
  await ensurePqcInit()
  return generateKemKeyPairCore()
}

export async function encapsulate(publicKey: Uint8Array): Promise<EncapsulateResult> {
  await ensurePqcInit()
  return encapsulateCore(publicKey)
}

export async function decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  await ensurePqcInit()
  return decapsulateCore(ciphertext, secretKey)
}

// ── ML-DSA-65 — public stable API ──────────────────────────────────────────

export async function generateSignatureKeyPair(): Promise<SignatureKeyPair> {
  await ensurePqcInit()
  return generateSignatureKeyPairCore()
}

export async function sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  await ensurePqcInit()
  return signCore(message, secretKey)
}

export async function verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  await ensurePqcInit()
  return verifyCore(message, signature, publicKey)
}
