# @stenvault/pqc-wasm

Post-quantum cryptography WASM wrapper for StenVault — ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) compiled from RustCrypto crates to WebAssembly.

## Why

Replaces `@openforge-sh/liboqs` (unofficial C wrapper, single anonymous maintainer, 0 stars) with a self-maintained Rust→WASM build using the RustCrypto ecosystem (`ml-kem` + `ml-dsa` crates).

WASM preserves constant-time properties from the Rust `subtle` crate — pure JS alternatives (noble-post-quantum, mlkem) cannot guarantee this due to V8 JIT and GC interference.

## Build

Requires Rust toolchain with `wasm32-unknown-unknown` target and `wasm-pack`:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Build both targets
wasm-pack build --target bundler --release --out-dir pkg-bundler
wasm-pack build --target nodejs  --release --out-dir pkg-nodejs
```

## API

```typescript
import {
  generateKemKeyPair,
  encapsulate,
  decapsulate,
  generateSignatureKeyPair,
  sign,
  verify,
} from '@stenvault/pqc-wasm'

// ML-KEM-768
const kp = await generateKemKeyPair()
// kp.publicKey: Uint8Array (1,184 bytes)
// kp.secretKey: Uint8Array (2,400 bytes)

const { ciphertext, sharedSecret } = await encapsulate(kp.publicKey)
const decrypted = await decapsulate(ciphertext, kp.secretKey)
// sharedSecret === decrypted (32 bytes)

// ML-DSA-65
const sigKp = await generateSignatureKeyPair()
// sigKp.publicKey: Uint8Array (1,952 bytes)
// sigKp.secretKey: Uint8Array (32 bytes, FIPS 204 seed)

const signature = await sign(message, sigKp.secretKey)
// signature: Uint8Array (3,309 bytes)

const valid = await verify(message, signature, sigKp.publicKey)
```

## Architecture

```
Consumer (StenVault)
    ↓ imports from "@stenvault/pqc-wasm"
index.browser.ts / index.node.ts   ← ensurePqcInit() + re-export
    ↓
core.ts                             ← free() in try/finally, param order normalization
    ↓
pkg-bundler/ or pkg-nodejs/         ← wasm-bindgen generated bindings
    ↓
src/lib.rs                          ← 7 Rust functions, zeroize on Drop
    ↓
ml-kem + ml-dsa (RustCrypto)        ← FIPS 203/204 implementations
```

The consumer never calls `free()`, never calls `init()`, and never imports from `pkg-*` directly. The `exports` field in `package.json` routes `browser` to `pkg-bundler` and `node`/`default` to `pkg-nodejs` automatically.

## Key sizes (FIPS)

| Algorithm | Public Key | Secret Key | Ciphertext | Signature | Shared Secret |
|-----------|-----------|-----------|-----------|----------|--------------|
| ML-KEM-768 | 1,184 B | 2,400 B | 1,088 B | — | 32 B |
| ML-DSA-65 | 1,952 B | 32 B (seed) | — | 3,309 B | — |

## Security

- **Constant-time**: `subtle` crate in Rust, preserved through WASM compilation
- **Memory zeroing**: `zeroize` crate with `#[derive(ZeroizeOnDrop)]` on all secret-holding structs
- **No audit**: Neither RustCrypto nor this wrapper have been independently audited. RustCrypto is honest about this.
- **CVE-2026-22705**: Timing side-channel in `ml-dsa` Decompose function, patched in `>= 0.1.0-rc.3` (Barrett reduction).
- **CVE-2026-24850**: Signature malleability via duplicate hint indices in `ml-dsa`, patched in `>= 0.1.0-rc.4`.
- **GHSA-h37v-hp6w-2pp8**: Off-by-two in `ml-dsa` `use_hint` when `r0 = 0` (FIPS 204 Alg. 40 deviation), patched in `>= 0.1.0-rc.5`.
- Cargo.toml pins `= 0.1.0-rc.8` (FIPS 204 seed API + WASM stack-overflow fix via PRs #1259 + #1261).
- **Supply chain**: `Cargo.lock` committed, CI runs `cargo audit` before every build.

## License

MIT
