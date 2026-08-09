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
use crate::{MerkleError, MerkleResult};

/// Terminally spends `store`, producing no successor coin (`child == None`).
///
/// The store's inner puzzle emits a single `MELT_SINGLETON` condition (the SDK builder, INV-4), so
/// the singleton is melted and no child DataStore is recreated. The one coin spend produced is
/// returned unsigned.
///
/// # Signing
///
/// An [`Owner::Standard`] melt requires exactly one `AGG_SIG_ME` over the owner's synthetic key.
/// Obtain it via [`crate::required_signatures`].
///
/// # Errors
///
/// Returns [`MerkleError::UnsupportedOwner`] for [`Owner::Custom`]: the `MELT_SINGLETON` condition is
/// built inside this call, so a pre-built inner spend cannot contain it and the returned bundle would
/// melt nothing while reporting success (#2418).
///
/// (`Owner::Custom` is in practice unusable across this crate's whole public API: a
/// [`chia_wallet_sdk::driver::Spend`] holds CLVM node pointers valid only in the allocator that built
/// them, and no public operation exposes its [`SpendContext`] for the caller to build one in.)
///
/// Returns [`MerkleError::Driver`](crate::MerkleError::Driver) if the SDK fails to build the melt
/// spend.
pub fn melt(
    store: &DataStore<DigDataStoreMetadata>,
    owner: Owner,
) -> MerkleResult<MerkleCoinSpend> {
    if matches!(owner, Owner::Custom(_)) {
        return Err(MerkleError::UnsupportedOwner(
            "a melt's MELT_SINGLETON condition is built inside this call, so Owner::Custom cannot \
             emit it — the bundle would melt nothing",
        ));
    }

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

    /// REGRESSION (#2418): a melt MUST refuse [`Owner::Custom`] rather than return a bundle with no
    /// `MELT_SINGLETON` condition.
    ///
    /// `melt` builds the melt condition INSIDE this call, and `context::inner_spend` drops the
    /// conditions for a custom owner — so accepting one returned `Ok` for a spend that recreates
    /// nothing and melts nothing. That is #2418's signature verbatim, on a second entry point.
    #[test]
    fn a_custom_owner_melt_is_refused() -> anyhow::Result<()> {
        use chia_wallet_sdk::driver::{SpendContext, SpendWithConditions, StandardLayer};

        let mut sim = Simulator::new();
        let (owner, store) = minted_store(&mut sim)?;

        let mut ctx = SpendContext::new();
        let prebuilt = StandardLayer::new(owner.pk)
            .spend_with_conditions(&mut ctx, chia_wallet_sdk::types::Conditions::new())?;

        let result = melt(&store, Owner::Custom(prebuilt));

        assert!(
            matches!(result, Err(crate::MerkleError::UnsupportedOwner(_))),
            "a custom-owner melt must refuse, not return a bundle that never melts, got: {result:?}"
        );
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
