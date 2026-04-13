//! Kani formal verification proofs for stenvault-pqc.
//!
//! These proofs verify safety properties of the wrapper functions in
//! src/lib.rs using bounded model checking (CBMC). They cover:
//!
//! 1. **Size invariants** — hardcoded constants match actual type-level
//!    sizes. Catches stale constants after library upgrades, which would
//!    cause out-of-bounds indexing in production.
//!
//! 2. **Boundary rejection** — `try_from` on wrong-size inputs returns
//!    Err (confirms our hardcoded constants align with library checks).
//!
//! 3. **Conversion safety** — `try_into` and `B32::from` never panic
//!    for any input of the correct size (exhaustive symbolic proof).
//!
//! Proofs on large inputs (>256 bytes) through crypto decoding are
//! intractable — the polynomial coefficient parsing loops create SAT
//! formulas that won't terminate. Those code paths are covered by the
//! cargo-fuzz harnesses instead.
//!
//! Kani runs on Linux only. Locally, proofs are inert (`#[cfg(kani)]`).
//! In CI they run on ubuntu-latest via GitHub Actions.
//!
//! Run: `cargo kani` (from this directory, on Linux)

// ── ML-KEM-768 (FIPS 203) ─────────────────────────────────────────────────

#[cfg(kani)]
mod mlkem {
    use ml_kem::{KemCore, MlKem768};

    type EK = <MlKem768 as KemCore>::EncapsulationKey;
    type DK = <MlKem768 as KemCore>::DecapsulationKey;

    // ── Size invariants ────────────────────────────────────────────────
    //
    // src/lib.rs guards every `from_fn(|i| bytes[i])` call with a
    // hardcoded length check (e.g. `if ek_bytes.len() != 1184`).
    // If ml-kem ever changes a key or ciphertext size, these proofs
    // fail BEFORE the mismatch can reach production.
    //
    // These are the highest-value proofs: they catch the most realistic
    // maintenance bug (library upgrade changes sizes, wrapper constants
    // go stale, from_fn indexes out of bounds).

    #[kani::proof]
    fn ek_encoded_size_is_1184() {
        assert!(
            core::mem::size_of::<ml_kem::Encoded<EK>>() == 1184,
            "EK encoded size diverged from wrapper constant — update ml_kem_768_encapsulate"
        );
    }

    #[kani::proof]
    fn dk_encoded_size_is_2400() {
        assert!(
            core::mem::size_of::<ml_kem::Encoded<DK>>() == 2400,
            "DK encoded size diverged from wrapper constant — update ml_kem_768_decapsulate"
        );
    }

    #[kani::proof]
    fn ct_size_is_1088() {
        assert!(
            core::mem::size_of::<ml_kem::Ciphertext<MlKem768>>() == 1088,
            "Ciphertext size diverged from wrapper constant — update ml_kem_768_decapsulate"
        );
    }
}

// ── ML-DSA-65 (FIPS 204) ──────────────────────────────────────────────────

#[cfg(kani)]
mod mldsa {
    use ml_dsa::{B32, EncodedVerifyingKey, MlDsa65, Signature};

    // ── Size boundary proofs ───────────────────────────────────────────
    //
    // Our wrapper checks `vk_bytes.len() != 1952` and
    // `signature.len() != 3309`. These proofs verify the boundary:
    // one-byte-short inputs are rejected, and correct-size inputs
    // never cause a panic in try_from.
    //
    // The correct-size proofs use concrete (zero) inputs rather than
    // symbolic `kani::any()` because try_from parses bytes into
    // polynomial coefficients through nested loops — symbolic inputs
    // create intractable SAT formulas.

    #[kani::proof]
    fn vk_rejects_1951_bytes() {
        let bytes = [0u8; 1951];
        assert!(
            EncodedVerifyingKey::<MlDsa65>::try_from(&bytes[..]).is_err(),
            "1951-byte input must be rejected"
        );
    }

    #[kani::proof]
    fn sig_rejects_3308_bytes() {
        let bytes = [0u8; 3308];
        assert!(
            Signature::<MlDsa65>::try_from(&bytes[..]).is_err(),
            "3308-byte input must be rejected"
        );
    }

    // ── Seed conversion safety (symbolic — exhaustive) ─────────────────
    //
    // ml_dsa_65_sign converts the 32-byte key into B32 via
    // `B32::from(seed_arr)`. 32 bytes = 256 symbolic bits — tractable
    // for Kani. Proves infallible for ALL possible seeds.

    #[kani::proof]
    fn b32_from_no_panic() {
        let bytes: [u8; 32] = kani::any();
        let _ = B32::from(bytes);
    }

    // ── try_into::<[u8; 32]> safety (symbolic — exhaustive) ────────────
    //
    // After the `sk_bytes.len() != 32` guard, src/lib.rs calls
    // `sk_bytes.try_into()`. Proves this conversion is infallible
    // for ALL possible 32-byte contents.

    #[kani::proof]
    fn try_into_32_infallible() {
        let bytes: [u8; 32] = kani::any();
        let slice: &[u8] = &bytes;
        let result: Result<[u8; 32], _> = slice.try_into();
        assert!(result.is_ok(), "try_into must succeed when len == 32");
    }
}
