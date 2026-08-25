//! The DataLayer-coin melt builder (SPEC §3.5) — terminally spend the coin, leaving no successor.
//!
//! [`melt`] spends a DataLayer store's coin with a `MELT_SINGLETON` (magic `-113`) condition rather
//! than recreating it, so the singleton is permanently retired: the returned [`MerkleCoinSpend`]
//! carries `child == None`. Like every operation the spend is unsigned (INV-1..4); an
//! [`Owner::Standard`] melt requires exactly one `AGG_SIG_ME` over the owner's synthetic key,
//! obtained via [`crate::required_signatures`].

use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::{Datastore, SpendContext};
use chia_wallet_sdk::types::Conditions;

use crate::context::inner_spend;
use crate::metadata::DigDataStoreMetadata;
use crate::types::{MerkleCoinSpend, Owner};
use crate::{MerkleError, MerkleResult};

/// Terminally spends `store`, producing no successor coin (`child == None`).
///
/// The store's inner puzzle emits a single `MELT_SINGLETON` condition (the SDK builder, INV-4), so
/// the singleton is melted and no child Datastore is recreated. The one coin spend produced is
/// returned unsigned.
///
/// # This is irreversible, and the caller must mean it
///
/// A launcher id is derived from a coin that has been spent, so a melted store can never be
/// recreated: every `dig://` reference anchored to it becomes permanently unresolvable. There is no
/// undo at any layer.
///
/// The coin's amount is not recoverable either, and that is structural rather than an omission: the
/// singleton top layer admits AT MOST ONE odd-amount `CREATE_COIN`, and the melt magic condition
/// `(51 () -113)` occupies it. A second odd-amount output makes the puzzle fail outright, and an
/// even-amount output cannot carry an odd singleton's whole amount. The amount is therefore an
/// implicit fee to the farmer — one mojo for a conventional store. **Do not add a recovery path**;
/// none can exist in this spend.
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
/// Returns [`MerkleError::NotTheOwner`] if `owner`'s key does not curry to the store's current
/// `owner_puzzle_hash` — i.e. the caller cannot prove it controls the singleton. Because the melt is
/// irreversible, authority is checked BEFORE any spend exists rather than left to fail at mempool
/// admission with a signature the caller could never produce (#3045).
///
/// Returns [`MerkleError::Driver`] if the SDK fails to build the melt spend.
pub fn melt(
    store: &Datastore<DigDataStoreMetadata>,
    owner: Owner,
) -> MerkleResult<MerkleCoinSpend> {
    if matches!(owner, Owner::Custom(_)) {
        return Err(MerkleError::UnsupportedOwner(
            "a melt's MELT_SINGLETON condition is built inside this call, so Owner::Custom cannot \
             emit it — the bundle would melt nothing",
        ));
    }

    gate_owner_controls_store(store, owner)?;

    let mut ctx = SpendContext::new();

    let conditions = Conditions::new().melt_singleton();
    let owner_spend = inner_spend(&mut ctx, owner, conditions)?;
    let store_spend = store.clone().spend(&mut ctx, owner_spend)?;

    Ok(MerkleCoinSpend::new(vec![store_spend], None))
}

/// Refuses `owner` unless its key curries to the store's current `owner_puzzle_hash`.
///
/// The check is `StandardArgs::curry_tree_hash(pk) == store.info.owner_puzzle_hash` — the same
/// commitment the store's own puzzle enforces on chain, evaluated here so an unauthorized melt is
/// refused before a spend exists. Fail-closed by construction: only an exact match proceeds, and
/// the non-`Standard` arm refuses rather than falling through, so this helper is total on its own
/// and does not rely on [`melt`]'s earlier `Owner::Custom` refusal still being there.
///
/// # Why `info.owner_puzzle_hash` and not the coin's puzzle hash
///
/// A store may carry delegated puzzles, in which case the coin wears a delegation layer curried
/// OVER the owner's p2 puzzle hash, and `coin.puzzle_hash` is neither the owner's nor stable across
/// the two shapes. `info.owner_puzzle_hash` is the field the owner path authenticates against in
/// BOTH shapes (see `Datastore::spend`, whose delegated branch supplies `merkle_proof: None` for an
/// owner spend), so keying the gate on it refuses a stranger without locking out the owner of a
/// delegated store.
///
/// # What this gate is, and is not
///
/// It decides on `store.info.owner_puzzle_hash`, the SAME field and the SAME value that the spend
/// below is then built from — there is no window in which a caller could vary the authority after
/// it was granted, because the authorization and the construction read one value in one call. Its
/// warrant is only as good as the `Datastore` handed in: a caller that fabricates an `info` it does
/// not own defeats its own guard and gets a spend that cannot confirm. That is acceptable, because
/// the value protected here is the caller who obtained the store honestly — [`crate::hydrate`]
/// binds a parsed store's puzzle reveal to the coin's puzzle hash, so a store read from chain
/// carries the real owner and this refusal is real.
fn gate_owner_controls_store<M>(store: &Datastore<M>, owner: Owner) -> MerkleResult<()> {
    let Owner::Standard(public_key) = owner else {
        return Err(MerkleError::UnsupportedOwner(
            "melt requires Owner::Standard to prove control of the store",
        ));
    };

    if StandardArgs::curry_tree_hash(public_key) != store.info.owner_puzzle_hash.into() {
        return Err(MerkleError::NotTheOwner);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::mint_datastore;
    use crate::required_signatures;
    use crate::types::{Bytes32, Datastore, DelegatedPuzzle};
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::clvm_utils::TreeHash;
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
    use chia_wallet_sdk::test::Simulator;

    /// Mints and settles a store on the simulator, returning the owner keypair and the eve store.
    fn minted_store(
        sim: &mut Simulator,
    ) -> anyhow::Result<(
        chia_wallet_sdk::test::BlsPairWithCoin,
        Datastore<DigDataStoreMetadata>,
    )> {
        minted_store_with_delegation(sim, vec![])
    }

    /// As [`minted_store`], but the settled store carries `delegated_puzzles`.
    ///
    /// The owner's authority over a store with a delegation layer is committed in the SAME field as
    /// one without (`info.owner_puzzle_hash`; the delegation layer is curried OVER it), so this
    /// shape exists to prove the gate reads that field rather than the coin's outer puzzle hash —
    /// which differs between the two shapes and would refuse a legitimate owner here.
    fn minted_store_with_delegation(
        sim: &mut Simulator,
        delegated_puzzles: Vec<DelegatedPuzzle>,
    ) -> anyhow::Result<(
        chia_wallet_sdk::test::BlsPairWithCoin,
        Datastore<DigDataStoreMetadata>,
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
            delegated_puzzles,
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

    /// THE acceptance property (#3045): a melt is REFUSED when the supplied owner key does not
    /// control the store, before any spend exists.
    ///
    /// Until this gate, `melt` refused only `Owner::Custom` and asked nothing else, so this call
    /// returned `Ok` — a fully-built, irreversible destructive spend against a store the caller
    /// does not own, handed back for signing.
    #[test]
    fn a_melt_by_a_non_owner_is_refused() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, store) = minted_store(&mut sim)?;
        let stranger = sim.bls(0);

        // Control: the SAME store melts for its real owner, so the refusal below is attributable to
        // the key and not to something else about this store.
        let _owner_can = melt(&store, Owner::Standard(owner.pk))
            .expect("the real owner must still be able to melt this store");

        let result = melt(&store, Owner::Standard(stranger.pk));

        assert!(
            matches!(result, Err(MerkleError::NotTheOwner)),
            "a melt by a key that does not control the store must be refused, got: {result:?}"
        );
        Ok(())
    }

    /// A refused melt destroys NOTHING — and the paired owner melt proves that is not vacuous.
    ///
    /// `Err` alone does not establish that no damage occurred; it only establishes what this call
    /// returned. So the store coin is asked of the simulator directly: it is live before, still
    /// live after the stranger's attempt, and spent only once its real owner melts it. Without the
    /// final leg, "still live" would also hold for a harness where no melt could ever work.
    #[test]
    fn a_refused_melt_leaves_the_store_alive_while_the_owners_melt_ends_it() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (owner, store) = minted_store(&mut sim)?;
        let stranger = sim.bls(0);

        assert!(
            sim.coin_state(store.coin.coin_id())
                .is_some_and(|state| state.spent_height.is_none()),
            "the store must be live before anyone tries to melt it"
        );

        let refused = melt(&store, Owner::Standard(stranger.pk));
        assert!(matches!(refused, Err(MerkleError::NotTheOwner)));

        assert!(
            sim.coin_state(store.coin.coin_id())
                .is_some_and(|state| state.spent_height.is_none()),
            "a refused melt must leave the store singleton untouched on chain"
        );

        let built = melt(&store, Owner::Standard(owner.pk))?;
        sim.spend_coins(built.coin_spends, std::slice::from_ref(&owner.sk))?;

        assert!(
            sim.coin_state(store.coin.coin_id())
                .is_some_and(|state| state.spent_height.is_some()),
            "the owner's melt must really spend the store coin, or the assertions above are vacuous"
        );
        Ok(())
    }

    /// A CONTROL against an OVER-STRICT gate: the owner of a store carrying delegated puzzles must
    /// still be able to melt it.
    ///
    /// A delegation layer changes the coin's outer puzzle hash but NOT `info.owner_puzzle_hash` —
    /// it is curried over it. A gate keyed on the coin's puzzle hash would pass the plain shape and
    /// refuse this one, locking a legitimate owner out of their own store. Refusing too much is as
    /// much a defect as refusing too little, and only this shape can see it.
    #[test]
    fn the_owner_of_a_store_with_delegated_puzzles_may_still_melt() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let delegated = vec![DelegatedPuzzle::Admin(TreeHash::new([0x11; 32]))];
        let (owner, store) = minted_store_with_delegation(&mut sim, delegated)?;

        assert!(
            !store.info.delegated_puzzles.is_empty(),
            "this control is meaningless unless the store really carries a delegation layer"
        );
        assert_ne!(
            store.coin.puzzle_hash, store.info.owner_puzzle_hash,
            "the delegation layer must make the coin's puzzle hash differ from the owner's, \
             otherwise this shape cannot distinguish a gate keyed on the wrong field"
        );

        let built = melt(&store, Owner::Standard(owner.pk))
            .expect("the owner of a delegated store must still be able to melt it");

        // Not merely "the builder returned Ok": the delegation layer must actually admit the melt
        // through its owner path, and the store must really be gone afterwards.
        sim.spend_coins(built.coin_spends, std::slice::from_ref(&owner.sk))?;
        assert!(
            sim.coin_state(store.coin.coin_id())
                .is_some_and(|state| state.spent_height.is_some()),
            "the owner's melt of a delegated store must confirm, not merely build"
        );
        Ok(())
    }

    /// The gate refuses a stranger on a delegated store too — the delegation layer is not a hole.
    #[test]
    fn a_non_owner_melt_of_a_delegated_store_is_also_refused() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let delegated = vec![DelegatedPuzzle::Admin(TreeHash::new([0x11; 32]))];
        let (_owner, store) = minted_store_with_delegation(&mut sim, delegated)?;
        let stranger = sim.bls(0);

        let result = melt(&store, Owner::Standard(stranger.pk));

        assert!(
            matches!(result, Err(MerkleError::NotTheOwner)),
            "a delegation layer must not admit a melt by a non-owner, got: {result:?}"
        );
        Ok(())
    }
}
