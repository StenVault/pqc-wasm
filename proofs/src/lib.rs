//! Kani proofs for stenvault-pqc: size invariants, boundary rejection,
//! and exhaustive conversion safety for the wrappers in `src/lib.rs`.
//!
//! Full decoding paths are intractable (polynomial parsing blows up SAT);
//! those are covered by the cargo-fuzz harnesses instead.
//!
//! Linux only; inert elsewhere via `#[cfg(kani)]`. Run: `cargo kani`.

// ── ML-KEM-768 (FIPS 203) ─────────────────────────────────────────────────

#[cfg(kani)]
mod mlkem {
    use ml_kem::{KemCore, MlKem768};

    type EK = <MlKem768 as KemCore>::EncapsulationKey;
    type DK = <MlKem768 as KemCore>::DecapsulationKey;

    // ── Size invariants ────────────────────────────────────────────────
    // If ml-kem changes a key or ciphertext size, the hardcoded length
    // checks in src/lib.rs go stale and from_fn indexes out of bounds.
    // These proofs fail first.

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
    // Confirms one-byte-short inputs are rejected by try_from, aligning
    // the library's internal checks with our wrapper's length guards.

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
    // 256 symbolic bits is tractable; proves B32::from never panics
    // for any 32-byte seed used in ml_dsa_65_sign.

    #[kani::proof]
    fn b32_from_no_panic() {
        let bytes: [u8; 32] = kani::any();
        let _ = B32::from(bytes);
    }

    // ── try_into::<[u8; 32]> safety (symbolic — exhaustive) ────────────
    // Proves the try_into after the `len != 32` guard in src/lib.rs is
    // infallible for any 32-byte content.

    #[kani::proof]
    fn try_into_32_infallible() {
        let bytes: [u8; 32] = kani::any();
        let slice: &[u8] = &bytes;
        let result: Result<[u8; 32], _> = slice.try_into();
        assert!(result.is_ok(), "try_into must succeed when len == 32");
    }
}
