//! # dig-merkle — the DIG Network canonical CHIP-0035 DataLayer coin expert crate
//!
//! `dig-merkle` is a **pure, key-free, network-free** SpendBundle-builder for the Chia CHIP-0035
//! DataLayer singleton that anchors a `.dig` file's merkle root on-chain. It constructs the exact
//! [`CoinSpend`]s for every DataLayer-coin lifecycle operation and reports — via
//! [`required_signatures`] — the exact signatures a caller must produce. It never holds a secret
//! key, never signs, and never touches the network. The consumer signs the reported messages,
//! assembles the `SpendBundle`, and broadcasts.
//!
//! ## The DataLayer coin
//!
//! A DataLayer coin is a CHIP-0035 singleton whose `launcher_id` IS the DIG `store_id`. Its
//! [`DataStoreMetadata`] carries the capsule's `root_hash` (the anchored `.dig` merkle root) plus
//! optional `label`/`description`/`bytes`/`size_proof` and the additive DIG keys `program_hash`
//! (`"p"`) and `size_bucket` (`"sz"`, a power-of-2 size class — see [`SizeBucket`]), and its
//! [`DelegatedPuzzle`] list grants
//! admin/writer/oracle authority. Spending the coin recreates it with a new root, transferring
//! ownership, delegating write access, or melting it. dig-merkle builds each such spend unsigned.
//!
//! ## Invariants
//!
//! These four invariants hold across the entire crate and are the contract every unit is built to
//! (SPEC §1):
//!
//! - **INV-1 — No network.** dig-merkle performs NO network or chain I/O. Every function is a pure
//!   transform of its inputs; the caller fetches coins and broadcasts bundles.
//! - **INV-2 — No keys.** dig-merkle never accepts, holds, derives, or logs a secret key. It
//!   computes what must be signed ([`required_signatures`]); the caller's signer produces the
//!   signatures.
//! - **INV-3 — Unsigned output.** Every operation returns an unsigned [`MerkleCoinSpend`] — coin
//!   spends plus the recreated child DataStore. Signatures are always the caller's responsibility.
//! - **INV-4 — SDK byte-source-of-truth.** Every puzzle, layer, and coin-spend byte is produced by
//!   `chia-wallet-sdk` (pinned to the 0.30 / chia-protocol 0.26 family, `chip-0035` feature).
//!   dig-merkle adds DataLayer-workflow ergonomics on top; it never re-implements a puzzle or
//!   hand-rolls a spend bundle, and re-exports the SDK's DataStore types verbatim.
//!
//! ## Consumer pattern
//!
//! ```text
//! build an unsigned MerkleCoinSpend  ->  required_signatures(&spend.coin_spends, &constants)
//!   ->  caller signs each reported message  ->  assemble SpendBundle  ->  broadcast
//! ```
//!
//! ## Status
//!
//! U1 ships the foundation: the type surface ([`MerkleCoinSpend`], [`Owner`], and the re-exported
//! SDK DataStore types), the error taxonomy ([`MerkleError`]), the inner-spend helpers, and the
//! signing boundary ([`required_signatures`]). The DataLayer operations land in their own units
//! against this foundation; their modules are declared below as doc-only stubs so the layout is
//! final.
//!
//! The planned operation surface (each a future unit):
//! - `mint` — launch a new DataLayer coin anchoring a root (`mint_root_from_launcher` takes a
//!   parent coin id, so a DID-authorized launcher composes without a dig-did dependency).
//! - `update` — recreate the coin with a new merkle root (an owner or writer update).
//! - `delegation` — grant/revoke admin/writer/oracle [`DelegatedPuzzle`] authority.
//! - `oracle` — spend the oracle delegated puzzle to read the coin for a fee.
//! - `melt` — terminally spend the coin, leaving no successor.
//! - `read` — parse the current on-chain state (no spend).
//! - `hydrate` — reconstruct a spendable [`DataStore`] from a parent coin spend (fail-closed).
//! - `lineage` — derive the [`LineageProof`] a child spend requires.
//! - `hint` — the owner/delegation hint memo domain (`b"dig:datastore:owner:v1"`).
//! - `fee` — attach a reserve fee condition to any operation.

// Internal helpers — not part of the public surface.
mod context;

// Public modules.
pub mod error;
pub mod sign;
pub mod types;

// The DataLayer operation modules — declared now so the crate layout is final; each is filled in
// its own unit (doc-only until then, so they add no untested surface).

pub mod metadata;

pub mod mint;

pub mod size;

/// Recreate the DataLayer coin with a new merkle root — an owner or writer update (future unit,
/// SPEC §3.2).
pub mod update {}

/// Grant or revoke admin/writer/oracle [`crate::DelegatedPuzzle`] authority (future unit,
/// SPEC §3.3).
pub mod delegation {}

/// Spend the oracle delegated puzzle to read the coin for a fee (future unit, SPEC §3.4).
pub mod oracle {}

/// Terminally spend (melt) the DataLayer coin, leaving no successor (future unit, SPEC §3.5).
pub mod melt {}

pub mod read;

/// Reconstruct a spendable [`crate::DataStore`] from a parent coin spend, fail-closed (future unit,
/// SPEC §5).
pub mod hydrate {}

/// Derive the [`crate::LineageProof`] a child DataLayer spend requires (future unit, SPEC §5).
pub mod lineage {}

pub mod hint;

/// Attach a reserve fee condition to any DataLayer operation (future unit, SPEC §3).
pub mod fee {}

// The curated public surface — consumers depend on these paths, not the module layout.
pub use error::{MerkleError, MerkleResult};
pub use hint::{digstore_owner_hint, DATASTORE_LAUNCHER_HINT, DIGSTORE_OWNER_HINT_DOMAIN};
pub use metadata::DigDataStoreMetadata;
pub use mint::mint_datastore;
pub use read::{did_ref_from_spend, DidRef};
pub use sign::required_signatures;
pub use size::SizeBucket;
pub use types::{
    Bytes32, Coin, CoinSpend, DataStore, DataStoreInfo, DataStoreMetadata, DelegatedPuzzle,
    LineageProof, MerkleCoinSpend, Owner, Proof,
};

// Re-export the signing types a consumer needs to CALL [`required_signatures`] and consume its
// result, so a downstream crate need not add a direct chia-wallet-sdk dependency for them.
pub use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
