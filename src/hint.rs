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
/// Emitted as the SECOND launcher memo for compatibility with launcher-hint-based tooling. This is
/// the hint for an ordinary file-backed store ([`StoreKind::File`]) — the ONLY kind existing
/// producers (chip35_dl_coin, digstore-chain) emit, so it stays the byte-identical default. Pinned
/// here as a literal and re-derived in the tests so the value can never drift from `sha256("datastore")`.
pub const DATASTORE_LAUNCHER_HINT: Bytes32 = Bytes32::new(hex!(
    "aa7e5b234e1d55967bf0a316395a2eab6cb3370332c0f251f0e44a5afb84fc68"
));

/// The DID-profile-store launcher hint = `sha256("dig:datastore:profile:v1")`.
///
/// Emitted as the second launcher memo for a [`StoreKind::DidProfile`] store — a DataLayer store
/// that anchors a DID profile rather than a file capsule (#1263). ADDITIVE: it is a brand-new
/// discriminator value that no existing store carries, so introducing it cannot change how any
/// already-published store is read. Pinned as a literal and re-derived in the tests so it can never
/// drift from `sha256("dig:datastore:profile:v1")`.
pub const DID_PROFILE_LAUNCHER_HINT: Bytes32 = Bytes32::new(hex!(
    "9c1d6b6d5d530dd613f4d7d2ced6b704ae8423377e4d567518493159c1d21d01"
));

/// The kind of a DataLayer store, as carried by the SECOND (discriminator) launcher memo.
///
/// A store's launcher `CREATE_COIN` carries two memos: `memo[0]` is the kind-agnostic owner hint
/// ([`digstore_owner_hint`]) and `memo[1]` is this kind discriminator. The first memo is always an
/// owner hint regardless of kind; the second names what the store anchors. The set is additive —
/// [`StoreKind::File`] is the pre-existing default (its hint is unchanged), and new kinds append new
/// discriminator constants without touching the File encoding (#1263, SPEC §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreKind {
    /// An ordinary file-backed capsule store — the pre-existing default, discriminator
    /// [`DATASTORE_LAUNCHER_HINT`].
    File,

    /// A DID-profile store, discriminator [`DID_PROFILE_LAUNCHER_HINT`] (#1263).
    DidProfile,
}

/// The launcher-hint discriminator (`memo[1]`) for a given [`StoreKind`].
///
/// `File` maps to [`DATASTORE_LAUNCHER_HINT`] (unchanged, byte-identical to existing producers);
/// `DidProfile` maps to [`DID_PROFILE_LAUNCHER_HINT`]. This is the write-side of the kind contract —
/// a minter chooses the kind, this yields the exact memo bytes to emit.
#[must_use]
pub fn launcher_hint_for(kind: StoreKind) -> Bytes32 {
    match kind {
        StoreKind::File => DATASTORE_LAUNCHER_HINT,
        StoreKind::DidProfile => DID_PROFILE_LAUNCHER_HINT,
    }
}

/// Classifies a store by its launcher-hint discriminator (`memo[1]`), the read-side of the kind
/// contract.
///
/// Returns the [`StoreKind`] whose discriminator equals `memo`, or `None` for an unrecognised value.
/// A legacy store — every store published before #1263 — carries [`DATASTORE_LAUNCHER_HINT`] and so
/// classifies as [`StoreKind::File`], preserving back-compat (SPEC §9, §5.1).
#[must_use]
pub fn from_launcher_hint(memo: Bytes32) -> Option<StoreKind> {
    if memo == DATASTORE_LAUNCHER_HINT {
        Some(StoreKind::File)
    } else if memo == DID_PROFILE_LAUNCHER_HINT {
        Some(StoreKind::DidProfile)
    } else {
        None
    }
}

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

    /// The DID-profile hint MUST equal `sha256("dig:datastore:profile:v1")` — the golden pin for the
    /// new kind discriminator (#1263, SPEC §9).
    #[test]
    fn did_profile_hint_is_sha256_of_domain() {
        let mut hasher = Sha256::new();
        hasher.update(b"dig:datastore:profile:v1");
        assert_eq!(DID_PROFILE_LAUNCHER_HINT, Bytes32::new(hasher.finalize()));
    }

    /// The two kind discriminators are distinct — a store's kind is unambiguous from `memo[1]`.
    #[test]
    fn file_and_did_profile_hints_are_distinct() {
        assert_ne!(DATASTORE_LAUNCHER_HINT, DID_PROFILE_LAUNCHER_HINT);
    }

    /// `launcher_hint_for` maps each kind to its discriminator, and `File` stays byte-identical to
    /// the pre-#1263 constant so existing producers need no change.
    #[test]
    fn launcher_hint_for_maps_each_kind() {
        assert_eq!(launcher_hint_for(StoreKind::File), DATASTORE_LAUNCHER_HINT);
        assert_eq!(
            launcher_hint_for(StoreKind::DidProfile),
            DID_PROFILE_LAUNCHER_HINT
        );
    }

    /// `from_launcher_hint` round-trips every kind and rejects an unknown discriminator with `None`.
    #[test]
    fn from_launcher_hint_round_trips_and_rejects_unknown() {
        for kind in [StoreKind::File, StoreKind::DidProfile] {
            assert_eq!(from_launcher_hint(launcher_hint_for(kind)), Some(kind));
        }
        assert_eq!(from_launcher_hint(Bytes32::new([0x00; 32])), None);
    }

    /// BACK-COMPAT (#1263, §5.1): a legacy store — every store published before the kind split —
    /// carries `DATASTORE_LAUNCHER_HINT` as `memo[1]` and MUST classify as `StoreKind::File`.
    #[test]
    fn legacy_launcher_hint_classifies_as_file() {
        // The exact bytes a pre-#1263 launcher emitted for its second memo.
        let legacy_memo = DATASTORE_LAUNCHER_HINT;
        assert_eq!(from_launcher_hint(legacy_memo), Some(StoreKind::File));
    }
}
