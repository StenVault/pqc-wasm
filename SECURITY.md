# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in `@stenvault/pqc-wasm`, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Email **security@stenvault.io** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Suggested fix (if any)

We aim to acknowledge reports within **48 hours** and provide a fix or mitigation within **7 days** for critical issues.

## Security Measures

- **Constant-time operations**: RustCrypto's `subtle` crate, preserved through WASM compilation
- **Memory zeroing**: `zeroize` crate with `#[derive(ZeroizeOnDrop)]` on all secret-holding structs
- **Supply chain**: `Cargo.lock` committed, `cargo audit` runs before every CI build
- **Trusted Publishing**: npm packages published via OIDC (no static tokens), with `--provenance` attestation
- **Dependency monitoring**: Dependabot checks Rust crates daily for new advisories

## Known Limitations

- **JS-side memory**: Secret material copied across the WASM/JS boundary (via getters) cannot be deterministically zeroized by JavaScript. The Rust-side structs are zeroized on `free()`.
- **No independent audit**: Neither RustCrypto nor this wrapper have been independently audited.

## Past Vulnerabilities

| CVE | Severity | Description | Fixed In |
|-----|----------|-------------|----------|
| CVE-2026-24850 | Medium | Signature malleability via duplicate hint indices in `ml-dsa` | `ml-dsa >= 0.1.0-rc.4` |
| CVE-2026-22705 | High | Timing side-channel in `ml-dsa` Decompose function | `ml-dsa >= 0.1.0-rc.3` |
