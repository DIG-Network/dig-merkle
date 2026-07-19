//! The DataLayer coin owner-discovery hint (SPEC §9) — a self-contained, byte-identical contract.
//!
//! A DataLayer store's launcher `CREATE_COIN` carries two indexed memos that make the store
//! discoverable on-chain:
//!
//! 1. the **owner hint** [`digstore_owner_hint`] — `sha256(DOMAIN ‖ owner_puzzle_hash)`, so a
//!    `get_coin_records_by_hint(owner_hint)` query returns exactly the DataLayer launcher coins that
//!    owner controls (never their ordinary XCH coins, which are hinted with the raw puzzle hash);
//! 2. the **global launcher hint** [`DATASTORE_LAUNCHER_HINT`] — `sha256("datastore")`, kept as a
//!    second memo for compatibility with launcher-hint-based tooling.
//!
//! These values are a **mutual byte-identical contract**: chip35_dl_coin (`store.rs`) and
//! digstore-chain (`singleton.rs`) already publish stores with exactly these bytes. A mismatch here
//! would silently make already-published stores undiscoverable, so the crate self-contains the
//! constants (no cross-crate dependency) and pins them with the golden tests below.

use chia_protocol::Bytes32;
use chia_sha2::Sha256;
use hex_literal::hex;

/// Domain tag for the digstore-scoped owner-discovery hint.
///
/// Scoping the hint to DataLayer stores (rather than hinting the raw owner puzzle hash) means a
/// coinset `get_coin_records_by_hint` query returns ONLY the owner's store launcher coins. Versioned
/// (`v1`) so the derivation can evolve without ambiguity. Byte-identical across chip35_dl_coin and
/// digstore-chain — changing it silently breaks owner enumeration for every existing store.
pub const DIGSTORE_OWNER_HINT_DOMAIN: &[u8] = b"dig:datastore:owner:v1";

/// The global DataLayer launcher hint = `sha256("datastore")`.
///
/// Emitted as the SECOND launcher memo for compatibility with launcher-hint-based tooling. Pinned
/// here as a literal and re-derived in the tests so the value can never drift from `sha256("datastore")`.
pub const DATASTORE_LAUNCHER_HINT: Bytes32 = Bytes32::new(hex!(
    "aa7e5b234e1d55967bf0a316395a2eab6cb3370332c0f251f0e44a5afb84fc68"
));

/// Derives the digstore-scoped owner-discovery hint = `sha256(DIGSTORE_OWNER_HINT_DOMAIN ‖ owner_puzzle_hash)`.
///
/// This is emitted as the FIRST (indexed) memo on a store's launcher `CREATE_COIN`, so the store is
/// discoverable by owner via `get_coin_records_by_hint(digstore_owner_hint(owner_ph))`. The
/// derivation MUST match chip35_dl_coin and digstore-chain byte-for-byte (same domain tag, same byte
/// order) or on-chain enumeration misses stores.
#[must_use]
pub fn digstore_owner_hint(owner_puzzle_hash: Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(DIGSTORE_OWNER_HINT_DOMAIN);
    hasher.update(owner_puzzle_hash);
    Bytes32::new(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The global launcher hint MUST equal `sha256("datastore")` — the golden pin for the second
    /// launcher memo (SPEC §9).
    #[test]
    fn launcher_hint_is_sha256_of_datastore() {
        let mut hasher = Sha256::new();
        hasher.update(b"datastore");
        assert_eq!(DATASTORE_LAUNCHER_HINT, Bytes32::new(hasher.finalize()));
    }

    /// The owner hint MUST equal `sha256(domain ‖ owner_ph)` for a known owner puzzle hash — the
    /// golden pin for the first (indexed) launcher memo and the cross-repo contract.
    #[test]
    fn owner_hint_matches_domain_prefixed_sha256() {
        let owner_ph = Bytes32::new([0x11; 32]);

        let mut hasher = Sha256::new();
        hasher.update(b"dig:datastore:owner:v1");
        hasher.update(owner_ph);
        let expected = Bytes32::new(hasher.finalize());

        assert_eq!(digstore_owner_hint(owner_ph), expected);
    }

    /// The derivation is deterministic and owner-specific: same input twice yields the same hint,
    /// different owners yield different hints.
    #[test]
    fn owner_hint_is_deterministic_and_owner_specific() {
        let a = Bytes32::new([0x11; 32]);
        let b = Bytes32::new([0x22; 32]);
        assert_eq!(digstore_owner_hint(a), digstore_owner_hint(a));
        assert_ne!(digstore_owner_hint(a), digstore_owner_hint(b));
    }

    /// The domain tag is the exact versioned bytes the on-chain producers use — a literal guard so a
    /// stray edit is caught at test time.
    #[test]
    fn domain_tag_is_the_pinned_bytes() {
        assert_eq!(DIGSTORE_OWNER_HINT_DOMAIN, b"dig:datastore:owner:v1");
    }
}
