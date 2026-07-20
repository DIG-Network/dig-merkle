//! The DataLayer-coin melt builder (SPEC §3.5) — terminally spend the coin, leaving no successor.
//!
//! [`melt`] spends a DataLayer store's coin with a `MELT_SINGLETON` (magic `-113`) condition rather
//! than recreating it, so the singleton is permanently retired: the returned [`MerkleCoinSpend`]
//! carries `child == None`. Like every operation the spend is unsigned (INV-1..4); an
//! [`Owner::Standard`] melt requires exactly one `AGG_SIG_ME` over the owner's synthetic key,
//! obtained via [`crate::required_signatures`].

use chia_wallet_sdk::driver::{DataStore, SpendContext};
use chia_wallet_sdk::types::Conditions;

use crate::context::inner_spend;
use crate::metadata::DigDataStoreMetadata;
use crate::types::{MerkleCoinSpend, Owner};
use crate::MerkleResult;

/// Terminally spends `store`, producing no successor coin (`child == None`).
///
/// The store's inner puzzle emits a single `MELT_SINGLETON` condition (the SDK builder, INV-4), so
/// the singleton is melted and no child DataStore is recreated. The one coin spend produced is
/// returned unsigned.
///
/// # Signing
///
/// An [`Owner::Standard`] melt requires exactly one `AGG_SIG_ME` over the owner's synthetic key; a
/// custom inner owns its own requirement. Obtain it via [`crate::required_signatures`].
///
/// # Errors
///
/// Returns [`MerkleError::Driver`](crate::MerkleError::Driver) if the SDK fails to build the melt
/// spend.
pub fn melt(
    store: &DataStore<DigDataStoreMetadata>,
    owner: Owner,
) -> MerkleResult<MerkleCoinSpend> {
    let mut ctx = SpendContext::new();

    let conditions = Conditions::new().melt_singleton();
    let owner_spend = inner_spend(&mut ctx, owner, conditions)?;
    let store_spend = store.clone().spend(&mut ctx, owner_spend)?;

    Ok(MerkleCoinSpend::new(vec![store_spend], None))
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

    /// Mints and settles a store on the simulator, returning the owner keypair and the eve store.
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
        Ok((owner, built.child.expect("mint yields a child")))
    }

    /// mint → melt yields no child and the melt validates on the simulator: the singleton is gone.
    #[test]
    fn melt_yields_no_child_and_validates() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, store) = minted_store(&mut sim)?;

        let built = melt(&store, Owner::Standard(owner.pk))?;
        assert!(built.child.is_none(), "a melt leaves no successor");
        assert_eq!(built.coin_spends.len(), 1, "melt is a single coin spend");

        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok(())
    }

    /// The unsigned melt requires exactly one `AGG_SIG_ME` over the owner's key.
    #[test]
    fn melt_requires_a_single_agg_sig_me() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, store) = minted_store(&mut sim)?;

        let built = melt(&store, Owner::Standard(owner.pk))?;

        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = required_signatures(&built.coin_spends, &constants)?;
        assert_eq!(required.len(), 1, "one AGG_SIG_ME expected");
        match &required[0] {
            RequiredSignature::Bls(bls) => assert_eq!(bls.public_key, owner.pk),
            RequiredSignature::Secp(_) => panic!("standard owner uses a BLS key"),
        }
        Ok(())
    }
}
