//! Reading on-chain DataLayer state without spending (SPEC §3.6/§3.7) — owner-DID discovery.
//!
//! A DIG store can be rooted in a DID: the store's launcher coin is created by spending a
//! DID-authorized coin (an [`crate::Owner::Custom`] mint whose parent is the DID coin). This module
//! recovers that owning DID by walking the store's launcher lineage one hop up to its creator and
//! recognising a DID coin spend.
//!
//! ## What ships now vs. what is pending
//!
//! The load-bearing, SDK-heavy part — recognising a DID from a coin spend — ships now as the pure,
//! network-free [`did_ref_from_spend`]. The launcher-lineage WALK that fetches the two coin spends
//! (`store_id` → its parent) is `resolve_owner_did`, which consumes the CANONICAL
//! `dig_chainsource_interface::ChainSource` read interface (a reference-DOWN pure leaf). That crate
//! is not yet on crates.io and dig-merkle publishes to crates.io (no git deps), so the walk lands as
//! a follow-up once the interface publishes; see the PENDING note below. Detecting the DID — the
//! hard bit — is fully implemented and tested here today.

use chia_wallet_sdk::driver::{Did, Puzzle};
use chia_wallet_sdk::prelude::Allocator;
use clvm_traits::ToClvm;

use crate::types::{Bytes32, CoinSpend};
use crate::{MerkleError, MerkleResult};

/// A reference to a DID, identified by its immutable `launcher_id` (the DID's on-chain identity).
///
/// This is the successful result of owner-DID discovery: the launcher id uniquely names the DID that
/// authorized a store's creation, and a caller resolves it to a full DID document via its own DID
/// tooling (dig-merkle deliberately holds no `dig-did` dependency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidRef {
    /// The DID's launcher id — its permanent on-chain identity.
    pub launcher_id: Bytes32,
}

/// Recognises whether a coin spend is a DID spend and, if so, returns its [`DidRef`]. Fail-closed:
/// any spend that is not a parseable DID yields `Ok(None)` rather than an error.
///
/// This is the pure, network-free core of owner-DID discovery. Given the spend of a store launcher's
/// PARENT coin, a `Some` result means that parent was a DID — i.e. the store is DID-owned — and names
/// the owning DID. A `None` result means the parent was an ordinary coin (e.g. a plain standard mint,
/// SPEC §3.7 fail-closed).
///
/// The parse runs in a private [`Allocator`], allocating the spend's puzzle and solution and handing
/// them to the SDK's [`Did::parse`] (the byte-source-of-truth, INV-4). It performs NO network I/O and
/// never signs or spends — it only inspects the given bytes.
///
/// # Errors
///
/// Returns [`MerkleError::Parse`] if the spend's puzzle/solution CLVM cannot be allocated, or
/// [`MerkleError::Driver`] if the SDK's DID parser errors on a puzzle that structurally should have
/// been a DID. A puzzle that simply is not a DID is `Ok(None)`, not an error.
pub fn did_ref_from_spend(spend: &CoinSpend) -> MerkleResult<Option<DidRef>> {
    let mut allocator = Allocator::new();

    let puzzle_ptr = spend
        .puzzle_reveal
        .to_clvm(&mut allocator)
        .map_err(|error| MerkleError::Parse(format!("puzzle reveal: {error}")))?;
    let solution_ptr = spend
        .solution
        .to_clvm(&mut allocator)
        .map_err(|error| MerkleError::Parse(format!("solution: {error}")))?;

    let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

    match Did::parse(&allocator, spend.coin, puzzle, solution_ptr)? {
        Some((did, _p2_spend)) => Ok(Some(DidRef {
            launcher_id: did.info.launcher_id,
        })),
        None => Ok(None),
    }
}

// PENDING dig-chainsource-interface v0.1.0: add the `resolve_owner_did<C: ChainSource>(store_id,
// chain)` wrapper here. It walks the launcher lineage with two `ChainSource::coin_spend` lookups —
// `coin_spend(store_id)` for the launcher spend, then `coin_spend(launcher_spend.coin
// .parent_coin_info)` for its creator — and passes that creator spend to `did_ref_from_spend`,
// fail-closed to `Ok(None)` at every missing step (SPEC §3.7). Blocked only on the canonical
// `dig_chainsource_interface::ChainSource` publishing to crates.io (dig-merkle allows no git deps).

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::driver::{Launcher, SpendContext, StandardLayer};
    use chia_wallet_sdk::test::Simulator;

    /// A real DID coin spend is recognised, and the returned [`DidRef`] carries the DID's own
    /// launcher id — the proof `did_ref_from_spend` drives the SDK's DID parser correctly.
    #[test]
    fn did_spend_is_recognised_with_its_launcher_id() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);

        // Create a DID, then settle it on chain so its coin exists to be spent again.
        let (create_did, did) =
            Launcher::new(alice.coin.coin_id(), 1).create_simple_did(ctx, &alice_p2)?;
        alice_p2.spend(ctx, alice.coin, create_did)?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))?;

        // Spend the DID coin (an update spend recreates it) — this is the spend we recognise.
        let did_coin = did.coin;
        let _child = did.update(ctx, &alice_p2, chia_wallet_sdk::types::Conditions::new())?;
        let coin_spends = ctx.take();
        sim.spend_coins(coin_spends.clone(), std::slice::from_ref(&alice.sk))?;

        let did_spend = coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == did_coin.coin_id())
            .expect("the DID coin spend is present");

        let did_ref = did_ref_from_spend(did_spend)?.expect("a DID spend is recognised");
        assert_eq!(
            did_ref.launcher_id, did.info.launcher_id,
            "the DidRef names the DID's own launcher id"
        );
        Ok(())
    }

    /// A plain standard-coin spend is NOT a DID — discovery fails closed to `None`, never an error
    /// (SPEC §3.7).
    #[test]
    fn plain_standard_spend_is_not_a_did() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);
        let memos = ctx.hint(alice.puzzle_hash)?;
        alice_p2.spend(
            ctx,
            alice.coin,
            chia_wallet_sdk::types::Conditions::new().create_coin(alice.puzzle_hash, 1, memos),
        )?;
        let coin_spends = ctx.take();

        let standard_spend = coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == alice.coin.coin_id())
            .expect("the standard coin spend is present");

        assert_eq!(
            did_ref_from_spend(standard_spend)?,
            None,
            "a plain standard spend is not a DID"
        );
        Ok(())
    }
}
