// Interoperability tests for @stenvault/pqc-wasm
//
// These tests validate:
// 1. Self-roundtrip: generate → encapsulate → decapsulate returns same shared secret
// 2. Self-roundtrip: generate → sign → verify returns true
// 3. Cross-library interop with @openforge-sh/liboqs (4 directions)
//
// Run with: npx tsx tests/interop.ts
// Requires both @stenvault/pqc-wasm (built) and @openforge-sh/liboqs installed

import {
  generateKemKeyPair,
  encapsulate,
  decapsulate,
  generateSignatureKeyPair,
  sign,
  verify,
} from '../src/index.node.js'

// ── Helpers ─────────────────────────────────────────────────────────────────

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`FAIL: ${message}`)
    process.exit(1)
  }
  console.log(`PASS: ${message}`)
}

// ── Self-roundtrip tests ────────────────────────────────────────────────────

async function testKemSelfRoundtrip(): Promise<void> {
  const kp = await generateKemKeyPair()
  assert(kp.publicKey.length === 1184, 'ML-KEM-768 public key is 1184 bytes')
  assert(kp.secretKey.length === 2400, 'ML-KEM-768 secret key is 2400 bytes')

  const { ciphertext, sharedSecret } = await encapsulate(kp.publicKey)
  assert(ciphertext.length === 1088, 'ML-KEM-768 ciphertext is 1088 bytes')
  assert(sharedSecret.length === 32, 'ML-KEM-768 shared secret is 32 bytes')

  const decrypted = await decapsulate(ciphertext, kp.secretKey)
  assert(decrypted.length === 32, 'Decapsulated shared secret is 32 bytes')
  assert(arraysEqual(sharedSecret, decrypted), 'KEM self-roundtrip: shared secrets match')
}

async function testDsaSelfRoundtrip(): Promise<void> {
  const kp = await generateSignatureKeyPair()
  assert(kp.publicKey.length === 1952, 'ML-DSA-65 public key is 1952 bytes')
  assert(kp.secretKey.length === 32, 'ML-DSA-65 secret key seed is 32 bytes (FIPS 204 canonical)')

  const message = new TextEncoder().encode('StenVault interop test message')
  const signature = await sign(message, kp.secretKey)
  assert(signature.length === 3309, 'ML-DSA-65 signature is 3309 bytes')

  const valid = await verify(message, signature, kp.publicKey)
  assert(valid, 'DSA self-roundtrip: signature verifies')

  // Tampered message should fail
  const tampered = new TextEncoder().encode('StenVault interop test message!')
  const invalid = await verify(tampered, signature, kp.publicKey)
  assert(!invalid, 'DSA self-roundtrip: tampered message rejects')
}

// ── Input validation tests ─────────────────────────────────────────────────
// These guard the length checks added in src/lib.rs so they don't regress
// silently. Every wasm-exported entry point that takes a byte slice rejects
// wrong-sized input with a JsError — we assert the Promise rejects.

async function expectReject(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn()
  } catch {
    console.log(`PASS: ${label}`)
    return
  }
  console.error(`FAIL: ${label} — expected rejection, got success`)
  process.exit(1)
}

async function testInputValidation(): Promise<void> {
  const kemKp = await generateKemKeyPair()
  const sigKp = await generateSignatureKeyPair()
  const msg = new TextEncoder().encode('validation probe')
  const goodSig = await sign(msg, sigKp.secretKey)

  await expectReject(
    'encapsulate rejects wrong-size public key',
    () => encapsulate(new Uint8Array(1183)),
  )
  await expectReject(
    'decapsulate rejects wrong-size secret key',
    () => decapsulate(new Uint8Array(1088), new Uint8Array(2399)),
  )
  await expectReject(
    'decapsulate rejects wrong-size ciphertext',
    () => decapsulate(new Uint8Array(1087), kemKp.secretKey),
  )
  await expectReject(
    'sign rejects wrong-size signing key seed',
    () => sign(msg, new Uint8Array(31)),
  )
  await expectReject(
    'verify rejects wrong-size verifying key',
    () => verify(msg, goodSig, new Uint8Array(1951)),
  )
  await expectReject(
    'verify rejects wrong-size signature',
    () => verify(msg, new Uint8Array(3308), sigKp.publicKey),
  )
}

// ── Cross-library interop tests (requires @openforge-sh/liboqs) ────────────
// These tests cover the 4 mandatory directions from the plan:
//
// ML-KEM-768:
// 1. Generate with openforge → encapsulate with RustCrypto → decapsulate with openforge
// 2. Generate with RustCrypto → encapsulate with openforge → decapsulate with RustCrypto
//
// ML-DSA-65:
// 3. Sign with openforge → verify with RustCrypto
// 4. Sign with RustCrypto → verify with openforge

async function testCrossLibraryKem(): Promise<void> {
  let liboqs: any
  try {
    liboqs = await import('@openforge-sh/liboqs')
  } catch {
    console.log('SKIP: @openforge-sh/liboqs not installed — cross-library KEM tests skipped')
    return
  }

  // Direction 1: openforge keygen → RustCrypto encap → openforge decap
  {
    const instance = await liboqs.createMLKEM768()
    try {
      const kp = instance.generateKeyPair()
      const { ciphertext, sharedSecret } = await encapsulate(kp.publicKey)
      const decrypted = instance.decapsulate(ciphertext, kp.secretKey)
      assert(
        arraysEqual(sharedSecret, new Uint8Array(decrypted)),
        'Cross KEM direction 1: openforge keygen → RustCrypto encap → openforge decap'
      )
    } finally {
      instance.destroy()
    }
  }

  // Direction 2: RustCrypto keygen → openforge encap → RustCrypto decap
  {
    const kp = await generateKemKeyPair()
    const instance = await liboqs.createMLKEM768()
    try {
      const { ciphertext, sharedSecret } = instance.encapsulate(kp.publicKey)
      const decrypted = await decapsulate(new Uint8Array(ciphertext), kp.secretKey)
      assert(
        arraysEqual(new Uint8Array(sharedSecret), decrypted),
        'Cross KEM direction 2: RustCrypto keygen → openforge encap → RustCrypto decap'
      )
    } finally {
      instance.destroy()
    }
  }
}

async function testCrossLibraryDsa(): Promise<void> {
  let liboqs: any
  try {
    liboqs = await import('@openforge-sh/liboqs')
  } catch {
    console.log('SKIP: @openforge-sh/liboqs not installed — cross-library DSA tests skipped')
    return
  }

  const message = new TextEncoder().encode('Cross-library signature interop test')

  // Direction 3: openforge sign → RustCrypto verify
  {
    const instance = await liboqs.createMLDSA65()
    try {
      const kp = instance.generateKeyPair()
      const signature = instance.sign(message, kp.secretKey)
      const valid = await verify(message, new Uint8Array(signature), new Uint8Array(kp.publicKey))
      assert(valid, 'Cross DSA direction 3: openforge sign → RustCrypto verify')
    } finally {
      instance.destroy()
    }
  }

  // Direction 4: RustCrypto sign → openforge verify
  {
    const kp = await generateSignatureKeyPair()
    const signature = await sign(message, kp.secretKey)
    const instance = await liboqs.createMLDSA65()
    try {
      const valid = instance.verify(message, signature, kp.publicKey)
      assert(valid, 'Cross DSA direction 4: RustCrypto sign → openforge verify')
    } finally {
      instance.destroy()
    }
  }
}

// ── Runner ──────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('=== @stenvault/pqc-wasm interop tests ===\n')

  console.log('--- ML-KEM-768 self-roundtrip ---')
  await testKemSelfRoundtrip()

  console.log('\n--- ML-DSA-65 self-roundtrip ---')
  await testDsaSelfRoundtrip()

  console.log('\n--- Input validation (negative tests) ---')
  await testInputValidation()

  console.log('\n--- ML-KEM-768 cross-library ---')
  await testCrossLibraryKem()

  console.log('\n--- ML-DSA-65 cross-library ---')
  await testCrossLibraryDsa()

  console.log('\n=== All tests passed ===')
}

main().catch((err) => {
  console.error('Test suite failed:', err)
  process.exit(1)
})
