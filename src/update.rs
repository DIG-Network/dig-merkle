//! The DataLayer-coin update builder (SPEC §3.2) — recreate the coin anchoring a new root.
//!
//! [`update_root`] spends an existing DataLayer store and recreates it with new metadata (a new
//! `root_hash`, and any other [`DigDataStoreMetadata`] fields), preserving the store's identity:
//! its `launcher_id`, owner puzzle hash, and delegated-puzzle set carry forward unchanged. The
//! caller supplies the FULL replacement metadata — metadata is replaced wholesale on chain, so an
//! update that means to KEEP an anchored `program_hash` (or size bucket, label, …) MUST re-send it
//! in `new_metadata`; omitting a field DROPS it (SPEC §3.2).
//!
//! Like every operation the returned spend is unsigned (INV-1..4): an [`Owner::Standard`] update
//! requires exactly one `AGG_SIG_ME` over the owner's synthetic key, obtained via
//! [`crate::required_signatures`].

use chia_wallet_sdk::driver::{DataStore, SpendContext};
use chia_wallet_sdk::types::Conditions;

use crate::context::inner_spend;
use crate::metadata::DigDataStoreMetadata;
use crate::types::{MerkleCoinSpend, Owner};
use crate::{MerkleError, MerkleResult};

/// Recreates `store` with `new_metadata`, preserving its `launcher_id`, owner, and delegation set.
///
/// The store's inner puzzle emits two conditions — an NFT metadata update to `new_metadata` and a
/// recreation `CREATE_COIN` back to the same owner puzzle hash carrying the same delegated puzzles —
/// both built by the SDK (INV-4, never hand-rolled). The resulting child [`DataStore`] is hydrated
/// from the freshly-built spend and returned in [`MerkleCoinSpend::child`].
///
/// # Metadata is replaced wholesale
///
/// `new_metadata` becomes the store's ENTIRE new metadata. To preserve an existing `program_hash`,
/// `size_bucket`, label, or description, copy it into `new_metadata` before calling; a field left
/// `None` is dropped from the anchored state (SPEC §3.2).
///
/// # Signing
///
/// The returned spend is UNSIGNED. An [`Owner::Standard`] update requires exactly one `AGG_SIG_ME`
/// over the owner's synthetic key; a custom/delegated inner owns its own requirement. Obtain the
/// requirement via [`crate::required_signatures`].
///
/// # Errors
///
/// Returns [`MerkleError::Driver`] if the SDK fails to build the update conditions or the store
/// spend, and [`MerkleError::NotDataStore`] if the freshly-built spend does not hydrate a child
/// store (which would indicate a malformed recreation).
pub fn update_root(
    store: &DataStore<DigDataStoreMetadata>,
    owner: Owner,
    new_metadata: DigDataStoreMetadata,
) -> MerkleResult<MerkleCoinSpend> {
    let mut ctx = SpendContext::new();

    let launcher_id = store.info.launcher_id;
    let owner_puzzle_hash = store.info.owner_puzzle_hash;
    let delegated_puzzles = store.info.delegated_puzzles.clone();
    let hint_delegated_puzzles = !delegated_puzzles.is_empty();

    // The two conditions the inner puzzle emits: update the on-chain metadata, then recreate the
    // singleton back to the same owner with the same delegation set (the byte-source-of-truth SDK
    // helpers, INV-4).
    let new_metadata_condition = DataStore::new_metadata_condition(&mut ctx, new_metadata)?;
    let recreate_condition = DataStore::<DigDataStoreMetadata>::owner_create_coin_condition(
        &mut ctx,
        launcher_id,
        owner_puzzle_hash,
        delegated_puzzles.clone(),
        hint_delegated_puzzles,
    )?;

    let conditions = Conditions::new()
        .with(new_metadata_condition)
        .with(recreate_condition);
    let owner_spend = inner_spend(&mut ctx, owner, conditions)?;

    let store_spend = store.clone().spend(&mut ctx, owner_spend)?;

    // Hydrate the recreated child from the spend we just built, so callers get the post-update store
    // (with the new root/metadata) without re-fetching it from chain.
    let child =
        DataStore::<DigDataStoreMetadata>::from_spend(&mut ctx, &store_spend, &delegated_puzzles)?
            .ok_or(MerkleError::NotDataStore)?;

    Ok(MerkleCoinSpend::new(vec![store_spend], Some(child)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::mint_datastore;
    use crate::required_signatures;
    use crate::types::{Bytes32, DataStore};
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
    use chia_wallet_sdk::test::Simulator;

    /// Mints a store on the simulator and returns its (settled) eve DataStore plus the owner keypair,
    /// so update tests start from a real on-chain store.
    fn minted_store(
        sim: &mut Simulator,
    ) -> anyhow::Result<(
        chia_wallet_sdk::test::BlsPairWithCoin,
        DataStore<DigDataStoreMetadata>,
    )> {
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let built = mint_datastore(
            owner.coin,
            Owner::Standard(owner.pk),
            Bytes32::new([0x5a; 32]),
            Some("site".into()),
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            0,
        )?;
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok((owner, built.child.expect("mint yields a child")))
    }

    /// mint → update round-trips a NEW root: the child store carries the updated root and preserves
    /// the launcher id and owner, and the update validates on the simulator.
    #[test]
    fn update_round_trips_a_new_root() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, store) = minted_store(&mut sim)?;

        let new_root = Bytes32::new([0x77; 32]);
        let new_metadata = DigDataStoreMetadata {
            root_hash: new_root,
            label: Some("site".into()),
            ..Default::default()
        };

        let built = update_root(&store, Owner::Standard(owner.pk), new_metadata)?;
        let child = built.child.clone().expect("update yields a child");

        assert_eq!(child.info.metadata.root_hash, new_root, "root updated");
        assert_eq!(
            child.info.launcher_id, store.info.launcher_id,
            "launcher id preserved"
        );
        assert_eq!(
            child.info.owner_puzzle_hash, store.info.owner_puzzle_hash,
            "owner preserved"
        );

        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok(())
    }

    /// The unsigned update requires exactly one `AGG_SIG_ME` over the owner's key — the custody
    /// contract for a standard-owner update.
    #[test]
    fn update_requires_a_single_agg_sig_me() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, store) = minted_store(&mut sim)?;

        let built = update_root(
            &store,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x01; 32]),
                ..Default::default()
            },
        )?;

        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = required_signatures(&built.coin_spends, &constants)?;
        assert_eq!(required.len(), 1, "one AGG_SIG_ME expected");
        match &required[0] {
            RequiredSignature::Bls(bls) => assert_eq!(bls.public_key, owner.pk),
            RequiredSignature::Secp(_) => panic!("standard owner uses a BLS key"),
        }
        Ok(())
    }

    /// Metadata is replaced wholesale: omitting `program_hash` in the update DROPS a previously
    /// anchored program hash (SPEC §3.2).
    #[test]
    fn update_replaces_metadata_wholesale() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();

        // Mint a store WITH a program hash.
        let built = mint_datastore(
            owner.coin,
            Owner::Standard(owner.pk),
            Bytes32::new([0x5a; 32]),
            None,
            None,
            None,
            Some(Bytes32::new([0xcc; 32])),
            None,
            owner_ph,
            vec![],
            0,
        )?;
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let store = built.child.expect("mint yields a child");
        assert_eq!(
            store.info.metadata.program_hash,
            Some(Bytes32::new([0xcc; 32]))
        );

        // Update with new_metadata that omits program_hash → it is dropped.
        let updated = update_root(
            &store,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x99; 32]),
                ..Default::default()
            },
        )?;
        let child = updated.child.expect("update yields a child");
        assert_eq!(
            child.info.metadata.program_hash, None,
            "omitted program_hash is dropped (wholesale replacement)"
        );
        Ok(())
    }
}
