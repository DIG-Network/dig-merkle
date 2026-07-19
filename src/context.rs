//! Internal spend-construction helpers shared by every DataLayer operation (SPEC §2).
//!
//! These are the two primitives every operation module builds on: turning an [`Owner`] into the
//! concrete inner [`Spend`] that authorizes a DataLayer-coin spend, and draining a [`SpendContext`]
//! into the flat `Vec<CoinSpend>` that [`crate::MerkleCoinSpend`] exposes. Keeping them here means
//! each operation module reads as pure DataLayer logic — the p2/context mechanics live in one place.

use chia_wallet_sdk::driver::{Spend, SpendContext, SpendWithConditions};
use chia_wallet_sdk::types::Conditions;

use crate::types::Owner;
use crate::MerkleResult;

/// Builds the inner (p2) [`Spend`] that authorizes a DataLayer-coin spend, given the coin's
/// [`Owner`].
///
/// - [`Owner::Standard`] curries the standard single-key p2 layer over the owner key and emits the
///   supplied `conditions` from it (the usual path — one `AGG_SIG_ME` results).
/// - [`Owner::Custom`] returns the caller's pre-built inner spend unchanged. A custom p2 puzzle
///   bakes its own conditions in when the caller constructs it, so `conditions` is intentionally
///   ignored for this variant — the caller owns the inner spend end to end.
///
/// Consumed by every DataLayer operation module (mint, update, delegation, and beyond).
// U1 ships this foundation helper before the operation modules that call it; it is exercised by the
// unit tests below and consumed by mint/update/... in their own units. `allow(dead_code)` keeps the
// crate warning-clean until then without hiding a real unused symbol.
#[allow(dead_code)]
pub(crate) fn inner_spend(
    ctx: &mut SpendContext,
    owner: Owner,
    conditions: Conditions,
) -> MerkleResult<Spend> {
    match owner {
        Owner::Standard(public_key) => {
            let layer = chia_wallet_sdk::driver::StandardLayer::new(public_key);
            Ok(layer.spend_with_conditions(ctx, conditions)?)
        }
        Owner::Custom(spend) => Ok(spend),
    }
}

/// Drains every coin spend accumulated in the [`SpendContext`] into a flat vector, in spend order.
///
/// A thin wrapper over [`SpendContext::take`] that names the intent at the DataLayer call sites.
/// Consumed by every operation module that returns a [`crate::MerkleCoinSpend`].
// See the `inner_spend` note above — a U1 foundation helper used by the tests now and the operation
// modules in their own units.
#[allow(dead_code)]
pub(crate) fn drain_coin_spends(ctx: &mut SpendContext) -> Vec<chia_protocol::CoinSpend> {
    ctx.take()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::driver::Spend;
    use chia_wallet_sdk::prelude::PublicKey;

    #[test]
    fn standard_owner_builds_an_inner_spend() {
        let mut ctx = SpendContext::new();
        let owner = Owner::Standard(PublicKey::default());

        let spend = inner_spend(&mut ctx, owner, Conditions::new())
            .expect("standard layer should curry a spend");

        // A real puzzle + solution were allocated (they are distinct node pointers).
        assert_ne!(spend.puzzle, spend.solution);
        // Building the p2 puzzle staged CLVM into the context but no coin spend yet.
        assert!(drain_coin_spends(&mut ctx).is_empty());
    }

    #[test]
    fn custom_owner_passes_the_inner_spend_through_unchanged() {
        let mut ctx = SpendContext::new();
        // Two distinct pointers so we can prove they survive the passthrough byte-for-byte.
        let puzzle = ctx.one();
        let solution = ctx.nil();
        let prebuilt = Spend::new(puzzle, solution);

        let spend = inner_spend(&mut ctx, Owner::Custom(prebuilt), Conditions::new())
            .expect("custom passthrough never fails");

        assert_eq!(spend.puzzle, puzzle);
        assert_eq!(spend.solution, solution);
    }
}
