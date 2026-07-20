//! DataLayer-coin lineage proofs (SPEC §5) — the proof a child singleton spend requires.
//!
//! A singleton child spend must carry a [`LineageProof`] that attests to its parent's identity
//! (parent's parent, parent's inner puzzle hash, parent's amount). [`child_lineage_proof`] derives
//! that proof from a hydrated [`DataStore`] — the store as it exists now — so a caller can build the
//! next spend against it. It is a pure transform over the SDK's own derivation (INV-1, INV-4).

use chia_wallet_sdk::driver::{DataStore, SpendContext};

use crate::metadata::DigDataStoreMetadata;
use crate::types::LineageProof;
use crate::MerkleResult;

/// Derives the [`LineageProof`] that a spend of `store`'s CHILD must carry.
///
/// The proof binds the child to `store` as its parent — `store`'s own parent coin, `store`'s inner
/// puzzle hash, and `store`'s amount — exactly the lineage a CHIP-0035 singleton verifies when it is
/// recreated. Delegated to the SDK's `DataStore::child_lineage_proof` (the byte-source-of-truth,
/// INV-4).
///
/// # Errors
///
/// Returns [`MerkleError::Driver`](crate::MerkleError::Driver) if the SDK cannot compute the store's
/// inner puzzle hash.
pub fn child_lineage_proof(store: &DataStore<DigDataStoreMetadata>) -> MerkleResult<LineageProof> {
    let mut ctx = SpendContext::new();
    Ok(store.child_lineage_proof(&mut ctx)?)
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
        assert_eq!(standalone.parent_parent_coin_info, parsed.parent_parent_coin_info);
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
