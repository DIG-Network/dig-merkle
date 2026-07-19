//! The public type surface of `dig-merkle` (SPEC §2).
//!
//! Two kinds of types live here: the DataLayer/coin types re-exported verbatim from chia-wallet-sdk
//! (the byte-source-of-truth, INV-4 — this crate never re-defines a puzzle-carrying type), and the
//! small `dig-merkle`-owned types that describe an *unsigned* operation result
//! ([`MerkleCoinSpend`]) and *who* is authorized to spend a DataLayer coin ([`Owner`]).

use chia_wallet_sdk::driver::Spend;
use chia_wallet_sdk::prelude::PublicKey;

// Re-exported from chia-wallet-sdk so consumers of dig-merkle never need a direct SDK dependency to
// name the DataLayer coin it produces. These are the canonical Chia CHIP-0035 types (gated behind
// the SDK's `chip-0035` feature) — dig-merkle adds no shadow copy (INV-4).
pub use chia_protocol::{Bytes32, Coin, CoinSpend};
pub use chia_puzzle_types::{LineageProof, Proof};
pub use chia_wallet_sdk::driver::{DataStore, DataStoreInfo, DataStoreMetadata, DelegatedPuzzle};

/// The result of building a DataLayer-coin operation: the unsigned coin spends plus the recreated
/// child DataStore.
///
/// This is the crate's output contract (INV-3). A `MerkleCoinSpend` carries NO signature — the
/// consumer feeds `coin_spends` to [`crate::required_signatures`], signs the reported messages,
/// assembles a `SpendBundle`, and broadcasts. `child` is the DataStore as it will exist AFTER the
/// spend confirms (`None` for a terminal operation such as a melt, which leaves no successor).
#[derive(Debug, Clone)]
#[must_use]
pub struct MerkleCoinSpend {
    /// The unsigned coin spends this operation produces, in spend order.
    pub coin_spends: Vec<CoinSpend>,

    /// The DataStore as it will exist after these spends confirm, or `None` for a terminal
    /// operation.
    pub child: Option<DataStore>,
}

impl MerkleCoinSpend {
    /// Creates a [`MerkleCoinSpend`] from its coin spends and (optional) recreated child DataStore.
    pub fn new(coin_spends: Vec<CoinSpend>, child: Option<DataStore>) -> Self {
        Self { coin_spends, child }
    }
}

/// Who is authorized to spend a DataLayer coin — i.e. the p2 ("inner") puzzle that guards it.
///
/// Every DataLayer operation is authorized by spending the coin's inner puzzle. `Owner` lets a
/// caller pick that inner puzzle without dig-merkle hard-coding one:
///
/// - [`Owner::Standard`] is the common case — the standard single-key p2 puzzle. dig-merkle builds
///   the `StandardLayer` for you; the resulting spend requires one `AGG_SIG_ME` over the given key.
/// - [`Owner::Custom`] is the escape hatch — the caller supplies an already-built inner [`Spend`]
///   (any p2 puzzle: a custom vault, a multisig, a DID-authorized delegated puzzle). dig-merkle
///   passes it through unchanged, so the caller owns its signature requirements.
#[derive(Debug, Clone, Copy)]
pub enum Owner {
    /// The standard single-key p2 puzzle, owned by the given (synthetic) public key.
    Standard(PublicKey),

    /// A fully pre-built inner spend for a custom p2 puzzle, passed through unchanged.
    Custom(Spend),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_coin_spend_carries_its_coin_spends_and_child() {
        let spend = MerkleCoinSpend::new(Vec::new(), None);
        assert!(spend.coin_spends.is_empty());
        assert!(spend.child.is_none());
    }

    #[test]
    fn owner_standard_holds_the_given_key() {
        let key = PublicKey::default();
        let owner = Owner::Standard(key);
        match owner {
            Owner::Standard(k) => assert_eq!(k, key),
            Owner::Custom(_) => panic!("expected a standard owner"),
        }
    }
}
