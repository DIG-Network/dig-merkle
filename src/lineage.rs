//! DataLayer-coin lineage proofs (SPEC §5) — the proof a child singleton spend requires.
//!
//! A singleton child spend must carry a [`LineageProof`] that attests to its parent's identity
//! (parent's parent, parent's inner puzzle hash, parent's amount). [`child_lineage_proof`] derives
//! that proof from a hydrated [`DataStore`] — the store as it exists now — so a caller can build the
//! next spend against it. It is a pure transform over the SDK's own derivation (INV-1, INV-4).

use chia_wallet_sdk::driver::{get_merkle_tree, DataStore, NftStateLayer, SpendContext};
use chia_wallet_sdk::prelude::{ToTreeHash, TreeHash};
use chia_wallet_sdk::types::puzzles::{DelegationLayerArgs, DL_METADATA_UPDATER_PUZZLE_HASH};

use crate::metadata::DigDataStoreMetadata;
use crate::types::LineageProof;
use crate::MerkleResult;

/// Derives the [`LineageProof`] that a spend of `store`'s CHILD must carry.
///
/// The proof binds the child to `store` as its parent — `store`'s own parent coin, `store`'s inner
/// puzzle hash, and `store`'s amount — exactly the lineage a CHIP-0035 singleton verifies when it is
/// recreated.
///
/// We do NOT delegate `parent_inner_puzzle_hash` to the SDK's `DataStore::child_lineage_proof` /
/// `DataStoreInfo::inner_puzzle_hash`: that path currys the NFT-DEFAULT metadata updater
/// (`NFT_METADATA_UPDATER_DEFAULT_HASH`, via `NftStateLayerArgs::curry_tree_hash`), whereas a real
/// on-chain DataLayer coin currys `DL_METADATA_UPDATER_PUZZLE_HASH` (via
/// `into_layers_without_delegation_layer` / `into_layers_with_delegation_layer`). The two updaters
/// produce different NFT-state-layer tree hashes, so the SDK value is the WRONG
/// `parent_inner_puzzle_hash` and a child spend built against it is consensus-rejected with
/// `AssertMyParentIdFailed` (#1332). We instead reconstruct the inner puzzle hash the SAME way the DL
/// layers are built, currying the DL updater, for both the empty- and delegated-inner cases (INV-4).
///
/// # Errors
///
/// Returns [`MerkleError::Driver`](crate::MerkleError::Driver) if the store's metadata or delegated
/// puzzles cannot be allocated to compute the inner puzzle hash.
pub fn child_lineage_proof(store: &DataStore<DigDataStoreMetadata>) -> MerkleResult<LineageProof> {
    let mut ctx = SpendContext::new();
    Ok(LineageProof {
        parent_parent_coin_info: store.coin.parent_coin_info,
        parent_inner_puzzle_hash: parent_inner_puzzle_hash(store, &mut ctx)?.into(),
        parent_amount: store.coin.amount,
    })
}

/// Computes `store`'s singleton inner puzzle hash — the NFT-state-layer tree hash — via the DataLayer
/// path, currying [`DL_METADATA_UPDATER_PUZZLE_HASH`] exactly as the SDK's `into_layers_*` builders do
/// when they construct the real on-chain coin (#1332). This is the value a child singleton's lineage
/// proof must carry.
fn parent_inner_puzzle_hash(
    store: &DataStore<DigDataStoreMetadata>,
    ctx: &mut SpendContext,
) -> MerkleResult<TreeHash> {
    let metadata_ptr = ctx.alloc(&store.info.metadata)?;
    let metadata_hash = ctx.tree_hash(metadata_ptr);

    // The innermost puzzle under the NFT state layer: the delegation layer when the store carries
    // admin/writer/oracle delegated puzzles, else the bare owner puzzle (SPEC §5).
    let inner_puzzle_hash = if store.info.delegated_puzzles.is_empty() {
        store.info.owner_puzzle_hash.into()
    } else {
        DelegationLayerArgs::curry_tree_hash(
            store.info.launcher_id,
            store.info.owner_puzzle_hash,
            get_merkle_tree(ctx, store.info.delegated_puzzles.clone())?.root(),
        )
    };

    Ok(NftStateLayer::new(
        metadata_hash,
        DL_METADATA_UPDATER_PUZZLE_HASH.into(),
        inner_puzzle_hash,
    )
    .tree_hash())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::mint_datastore;
    use crate::types::{Bytes32, Owner, Proof};
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::test::Simulator;

    /// GROUND TRUTH (#1332): the proof produced by [`child_lineage_proof`] must be BYTE-IDENTICAL to
    /// the lineage proof the SDK derives by PARSING the real on-chain parent puzzle (via
    /// `DataStore::from_spend`, which sets a child's `.proof` from the actual singleton layer).
    ///
    /// The concern: `child_lineage_proof` derives `parent_inner_puzzle_hash` from
    /// `DataStoreInfo::inner_puzzle_hash`, which currys the NFT-DEFAULT metadata updater
    /// (`NFT_METADATA_UPDATER_DEFAULT_HASH`), while a real DataLayer coin currys
    /// `DL_METADATA_UPDATER_PUZZLE_HASH` (via `into_layers_without_delegation_layer`). If the two
    /// updater hashes propagate into the inner-puzzle tree hash, the standalone proof would carry the
    /// WRONG `parent_inner_puzzle_hash` and a child spend built against it would be consensus-rejected.
    #[test]
    fn child_lineage_proof_matches_the_parsed_on_chain_proof() -> anyhow::Result<()> {
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
        let store1 = built.child.expect("mint yields a child (eve store)");

        // The standalone proof for a CHILD of store1.
        let standalone = child_lineage_proof(&store1)?;

        // The SDK-parsed proof: update store1 → store2; `from_spend` sets store2.proof by PARSING
        // store1's real puzzle. This is the byte-source-of-truth lineage proof for a child of store1.
        let built2 = crate::update::update_root(
            &store1,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x77; 32]),
                ..Default::default()
            },
        )?;
        let store2 = built2.child.clone().expect("update yields a child");
        let parsed = match store2.proof {
            Proof::Lineage(lp) => lp,
            Proof::Eve(_) => panic!("store2 is not an eve coin"),
        };

        assert_eq!(
            standalone.parent_inner_puzzle_hash, parsed.parent_inner_puzzle_hash,
            "child_lineage_proof's parent_inner_puzzle_hash must equal the SDK-parsed on-chain value"
        );
        assert_eq!(
            standalone.parent_parent_coin_info,
            parsed.parent_parent_coin_info
        );
        assert_eq!(standalone.parent_amount, parsed.parent_amount);
        Ok(())
    }

    /// GROUND TRUTH (#1332), consensus edition: a CHILD spend whose lineage proof is supplied
    /// EXCLUSIVELY by [`child_lineage_proof`] must be accepted by the simulator (real singleton
    /// consensus recomputes the parent coin id from `parent_inner_puzzle_hash` and rejects a mismatch).
    #[test]
    fn child_lineage_proof_produces_a_consensus_valid_child_spend() -> anyhow::Result<()> {
        use crate::types::DataStore;

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
        let store1 = built.child.expect("mint yields a child (eve store)");

        // Put store2 on chain so it is a spendable coin.
        let built2 = crate::update::update_root(
            &store1,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x77; 32]),
                ..Default::default()
            },
        )?;
        sim.spend_coins(built2.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let store2 = built2.child.expect("update yields a child");

        // Reconstruct store2 but with its proof supplied SOLELY by child_lineage_proof(store1) — the
        // exact path a lineage-walker (dig-store walk_lineage) takes to build the next spend. store2's
        // parent is store1, so a child-of-store1 proof is what a store2 spend must carry.
        let store2_via_clp = DataStore::new(
            store2.coin,
            Proof::Lineage(child_lineage_proof(&store1)?),
            store2.info.clone(),
        );

        // Spend store2 (an update) using ONLY the child_lineage_proof-derived proof. If the proof's
        // parent_inner_puzzle_hash were wrong, singleton consensus would reject this.
        let built3 = crate::update::update_root(
            &store2_via_clp,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x88; 32]),
                ..Default::default()
            },
        )?;
        sim.spend_coins(built3.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok(())
    }

    /// GROUND TRUTH (#1332), DELEGATED store: a store minted with a non-empty delegation set
    /// (admin + writer) exercises the delegation-layer branch of [`parent_inner_puzzle_hash`]. Its
    /// standalone proof must still equal the SDK-parsed on-chain value AND yield a consensus-valid
    /// child spend — the delegation layer curries under the DL updater exactly like the empty case.
    #[test]
    fn child_lineage_proof_matches_the_parsed_on_chain_proof_for_a_delegated_store(
    ) -> anyhow::Result<()> {
        use crate::types::DelegatedPuzzle;

        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let delegated_puzzles = vec![
            DelegatedPuzzle::Admin(chia_wallet_sdk::prelude::TreeHash::new([0x11; 32])),
            DelegatedPuzzle::Writer(chia_wallet_sdk::prelude::TreeHash::new([0x22; 32])),
        ];
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
            delegated_puzzles.clone(),
            0,
        )?;
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let store1 = built.child.expect("mint yields a child (eve store)");
        assert!(
            !store1.info.delegated_puzzles.is_empty(),
            "test precondition: the store carries a delegation set"
        );

        let standalone = child_lineage_proof(&store1)?;

        let built2 = crate::update::update_root(
            &store1,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x77; 32]),
                ..Default::default()
            },
        )?;
        let store2 = built2.child.clone().expect("update yields a child");
        let parsed = match store2.proof {
            Proof::Lineage(lp) => lp,
            Proof::Eve(_) => panic!("store2 is not an eve coin"),
        };

        assert_eq!(
            standalone.parent_inner_puzzle_hash, parsed.parent_inner_puzzle_hash,
            "delegated store: parent_inner_puzzle_hash must equal the SDK-parsed on-chain value"
        );
        assert_eq!(
            standalone.parent_parent_coin_info,
            parsed.parent_parent_coin_info
        );
        assert_eq!(standalone.parent_amount, parsed.parent_amount);
        Ok(())
    }

    /// GROUND TRUTH (#1332), DELEGATED store, consensus edition: a child spend whose lineage proof is
    /// supplied SOLELY by [`child_lineage_proof`] for a delegated store must be accepted by the
    /// simulator (no `AssertMyParentIdFailed`).
    #[test]
    fn child_lineage_proof_produces_a_consensus_valid_child_spend_for_a_delegated_store(
    ) -> anyhow::Result<()> {
        use crate::types::{DataStore, DelegatedPuzzle};

        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let delegated_puzzles = vec![
            DelegatedPuzzle::Admin(chia_wallet_sdk::prelude::TreeHash::new([0x11; 32])),
            DelegatedPuzzle::Writer(chia_wallet_sdk::prelude::TreeHash::new([0x22; 32])),
        ];
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
            delegated_puzzles,
            0,
        )?;
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let store1 = built.child.expect("mint yields a child (eve store)");

        let built2 = crate::update::update_root(
            &store1,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x77; 32]),
                ..Default::default()
            },
        )?;
        sim.spend_coins(built2.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let store2 = built2.child.expect("update yields a child");

        // Reconstruct store2 with its proof supplied SOLELY by child_lineage_proof(store1).
        let store2_via_clp = DataStore::new(
            store2.coin,
            Proof::Lineage(child_lineage_proof(&store1)?),
            store2.info.clone(),
        );

        let built3 = crate::update::update_root(
            &store2_via_clp,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x88; 32]),
                ..Default::default()
            },
        )?;
        sim.spend_coins(built3.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok(())
    }

    /// The child lineage proof binds to the store's own coin: its `parent_amount` equals the store
    /// coin's amount and its `parent_parent_coin_info` equals the store coin's parent — the fields a
    /// child singleton spend validates.
    #[test]
    fn lineage_proof_binds_to_the_store_coin() -> anyhow::Result<()> {
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

        let proof = child_lineage_proof(&store)?;
        assert_eq!(proof.parent_amount, store.coin.amount);
        assert_eq!(
            proof.parent_parent_coin_info, store.coin.parent_coin_info,
            "the proof references the store coin's parent"
        );
        Ok(())
    }

    /// The derived proof actually lets a CHILD spend validate on the simulator: mint → update (which
    /// uses the lineage internally) settles, proving the proof shape is spendable.
    #[test]
    fn lineage_proof_lets_a_child_spend_validate() -> anyhow::Result<()> {
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

        // A child spend (an update) carries the store's proof internally; if the lineage shape were
        // wrong the simulator would reject it.
        let child = crate::update::update_root(
            &store,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x77; 32]),
                ..Default::default()
            },
        )?;
        sim.spend_coins(child.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok(())
    }
}
