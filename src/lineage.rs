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
    use crate::types::{Bytes32, Owner};
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::test::Simulator;

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
