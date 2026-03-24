// Public API types for @stenvault/pqc-wasm
// These types define the stable contract that StenVault imports.
// Changing the underlying implementation (RustCrypto, liboqs, etc.)
// must NOT change these types.

export interface KemKeyPair {
  publicKey: Uint8Array   // encapsulation key, 1,184 bytes
  secretKey: Uint8Array   // decapsulation key, 2,400 bytes
}

export interface EncapsulateResult {
  ciphertext: Uint8Array   // 1,088 bytes
  sharedSecret: Uint8Array // 32 bytes
}

export interface SignatureKeyPair {
  publicKey: Uint8Array   // verifying key, 1,952 bytes
  secretKey: Uint8Array   // signing key, 4,032 bytes
}

export interface PqcApi {
  generateKemKeyPair(): Promise<KemKeyPair>
  encapsulate(publicKey: Uint8Array): Promise<EncapsulateResult>
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>
  generateSignatureKeyPair(): Promise<SignatureKeyPair>
  sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>
}
