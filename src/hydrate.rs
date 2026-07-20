//! Reconstructing a spendable DataLayer coin from its parent spend (SPEC §5) — fail-closed.
//!
//! To spend an existing DataLayer coin a caller needs the current [`DataStore`] — coin, lineage
//! proof, metadata, owner, and delegation set. [`hydrate`] reconstructs it from the coin spend that
//! CREATED it (its parent's spend), delegating the parse to the SDK's `DataStore::from_spend` (the
//! byte-source-of-truth, INV-4). It performs NO network I/O; the caller supplies the real parent
//! spend from a trusted chain source.
//!
//! Hydration is FAIL-CLOSED (SPEC §5): a spend that is not a DataLayer singleton yields
//! [`MerkleError::NotDataStore`], a spend that recreated no successor coin yields
//! [`MerkleError::MissingLineage`], and a spend missing a required hint/memo yields
//! [`MerkleError::MissingHint`]. dig-merkle never fabricates missing chain state.

use chia_wallet_sdk::driver::{DataStore, DriverError, SpendContext};

use crate::metadata::DigDataStoreMetadata;
use crate::types::CoinSpend;
use crate::{MerkleError, MerkleResult};

/// Reconstructs the spendable [`DataStore`] created by `parent_spend`.
///
/// `parent_spend` is the coin spend that produced the store coin to be hydrated — either the
/// launcher spend (for an eve store) or a prior recreation spend. The returned store carries the
/// lineage proof and metadata a subsequent [`crate::update_root`]/[`crate::melt()`] needs.
///
/// # Fail-closed errors (SPEC §5)
///
/// - [`MerkleError::NotDataStore`] — `parent_spend` does not parse as a DataLayer singleton.
/// - [`MerkleError::MissingLineage`] — `parent_spend` recreated no successor coin (e.g. it was a
///   terminal melt), so there is no child to hydrate.
/// - [`MerkleError::MissingHint`] — `parent_spend` is missing a hint/memo required to rebuild the
///   store's delegation set.
/// - [`MerkleError::Driver`] — any other SDK parse failure.
pub fn hydrate(parent_spend: &CoinSpend) -> MerkleResult<DataStore<DigDataStoreMetadata>> {
    let mut ctx = SpendContext::new();

    match DataStore::<DigDataStoreMetadata>::from_spend(&mut ctx, parent_spend, &[]) {
        Ok(Some(store)) => Ok(store),
        Ok(None) => Err(MerkleError::NotDataStore),
        // A spend that recreated no odd (singleton) coin — a terminal melt — leaves nothing to
        // hydrate; report it as a missing lineage rather than leaking the SDK's internal variant.
        Err(DriverError::MissingChild) => Err(MerkleError::MissingLineage),
        Err(DriverError::MissingHint | DriverError::MissingMemo) => Err(MerkleError::MissingHint),
        Err(other) => Err(MerkleError::Driver(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::melt::melt;
    use crate::mint::mint_datastore;
    use crate::types::{Bytes32, Owner};
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::driver::StandardLayer;
    use chia_wallet_sdk::test::Simulator;

    /// hydrate reconstructs a spendable store from a real launcher spend: the reconstructed store has
    /// the anchored root and matching launcher id, and it is spendable (an update settles).
    #[test]
    fn hydrate_reconstructs_a_spendable_store() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let root = Bytes32::new([0x5a; 32]);
        let built = mint_datastore(
            owner.coin,
            Owner::Standard(owner.pk),
            root,
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            0,
        )?;
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let minted = built.child.expect("mint yields a child");

        let launcher_spend = built
            .coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == minted.info.launcher_id)
            .expect("launcher-coin spend present");

        let store = hydrate(launcher_spend)?;
        assert_eq!(store.info.metadata.root_hash, root);
        assert_eq!(store.info.launcher_id, minted.info.launcher_id);

        // Prove it is spendable: an update off the hydrated store validates.
        let updated = crate::update::update_root(
            &store,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x77; 32]),
                ..Default::default()
            },
        )?;
        sim.spend_coins(updated.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok(())
    }

    /// FAIL-CLOSED: a plain (non-DataLayer) standard coin spend hydrates to `NotDataStore`, never a
    /// fabricated store.
    #[test]
    fn hydrate_fails_closed_on_a_non_datastore_spend() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let mut ctx = SpendContext::new();
        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);
        let memos = ctx.hint(alice.puzzle_hash)?;
        alice_p2.spend(
            &mut ctx,
            alice.coin,
            chia_wallet_sdk::types::Conditions::new().create_coin(alice.puzzle_hash, 1, memos),
        )?;
        let spends = ctx.take();
        let standard_spend = spends
            .iter()
            .find(|s| s.coin.coin_id() == alice.coin.coin_id())
            .expect("standard spend present");

        assert!(
            matches!(hydrate(standard_spend), Err(MerkleError::NotDataStore)),
            "a plain standard spend is not a DataLayer coin"
        );
        Ok(())
    }

    /// FAIL-CLOSED: hydrating a terminal melt spend (which recreated no successor) yields
    /// `MissingLineage`, never a fabricated child.
    #[test]
    fn hydrate_fails_closed_on_a_terminal_melt() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let built = mint_datastore(
            owner.coin,
            Owner::Standard(owner.pk),
            Bytes32::new([0x5a; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            0,
        )?;
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let store = built.child.expect("mint yields a child");

        let melted = melt(&store, Owner::Standard(owner.pk))?;
        sim.spend_coins(melted.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;

        let melt_spend = &melted.coin_spends[0];
        assert!(
            matches!(hydrate(melt_spend), Err(MerkleError::MissingLineage)),
            "a terminal melt has no child to hydrate"
        );
        Ok(())
    }
}
