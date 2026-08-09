//! Reading on-chain DataLayer state without spending (SPEC §3.6/§3.7) — owner-DID discovery.
//!
//! A DIG store can be rooted in a DID: the store's launcher coin descends from a DID-authorized
//! parent coin whose spend emits [`crate::DatastoreLaunch::parent_conditions`] (returned by
//! [`crate::mint_datastore_launch_with_kind`]). A DID is a singleton, so it cannot parent the
//! odd-amount launcher directly and interposes an even-amount intermediate coin (SPEC §3.1a). This
//! module recovers the owning DID by walking the store's launcher lineage up — one hop, or two
//! through that intermediate — and recognising a DID coin spend.
//!
//! ## Two layers
//!
//! [`did_ref_from_spend`] is the pure, network-free core — it recognises a DID from a single coin
//! spend. [`resolve_owner_did`] is the launcher-lineage WALK on top: it fetches the coin spends
//! (`store_id` → its creator, and at most one hop beyond) through the injected CANONICAL
//! [`dig_chainsource_interface::ChainSource`] read interface (a reference-DOWN pure leaf) and passes
//! the creator spend to `did_ref_from_spend`, fail-closed to `Ok(None)` at every missing hop.
//! dig-merkle itself opens no socket (INV-1) — the caller implements the chain read.

use chia_puzzle_types::nft::NftIntermediateLauncherArgs;
use chia_wallet_sdk::driver::{Did, Puzzle};
use chia_wallet_sdk::prelude::{Allocator, TreeHash};
use chia_wallet_sdk::puzzles::{NFT_INTERMEDIATE_LAUNCHER_HASH, SINGLETON_LAUNCHER_HASH};
use clvm_traits::{FromClvm, ToClvm};
use dig_chainsource_interface::ChainSource;

use crate::types::{Bytes32, Coin, CoinSpend};
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
/// # Authoritative ONLY for a CONFIRMED on-chain spend (NC-9)
///
/// This function trusts its input and only recognises STRUCTURE; it does NOT verify that the spend
/// happened on chain. A caller feeding an unconfirmed, attacker-shaped, or otherwise unverified spend
/// can be made to mis-attribute ownership — a crafted puzzle that parses as a DID yields a `Some`
/// that proves nothing. Genuine chain-proven attribution MUST fetch the store launcher's parent spend
/// from a TRUSTED chain source and verify it was actually spent on chain before trusting the result.
/// Do NOT treat a `Some` result from an unverified spend as proof of ownership.
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

/// Recovers the DID that OWNS the store launched at `store_id`, walking its launcher lineage up
/// (SPEC §3.7).
///
/// A DID-owned store has its launcher coin created — directly or through one intermediate coin — by
/// spending a DID-authorized coin. This walks that lineage via the injected [`ChainSource`] (INV-1 —
/// dig-merkle opens no socket; the caller supplies the chain read):
///
/// 1. `chain.coin_spend(store_id)` — the launcher coin's spend (`store_id == launcher_id`).
/// 2. `launcher_spend.coin.parent_coin_info` — the coin that CREATED the launcher.
/// 3. `chain.coin_spend(parent_id)` — that creator's spend. A DID here is the answer.
/// 4. Otherwise, IF that creator is an intermediate-launcher coin (see below), ONE further hop to
///    its own creator, which is where a singleton-parent launch puts the DID.
///
/// # The walk is bounded at TWO creator hops, and the second is earned, not assumed
///
/// A singleton's inner puzzle may emit exactly one odd-amount `CREATE_COIN` — its own successor — so
/// a DID cannot parent a 1-mojo launcher directly; it creates an even-amount intermediate coin that
/// creates the launcher (SPEC §3.1a). The walk therefore tolerates exactly ONE such hop. It is not a
/// general parent walk: an unbounded climb over coin records an untrusted source controls is a DoS,
/// and it would also mis-attribute an ordinary store whose funding coin merely happened to come from
/// a DID. The second hop is taken only when the creator IS the `nft_intermediate_launcher` puzzle,
/// curried to the singleton launcher, and the launcher that puzzle necessarily creates is this
/// store's. Anything else stops the walk at `Ok(None)`.
///
/// **The walk runs NO chain-supplied CLVM.** Every step parses or derives; none evaluates. An
/// untrusted [`ChainSource`] therefore cannot spend the caller's CPU on a program of its choosing.
///
/// It is **fail-closed to `Ok(None)`** at every missing/non-DID/unexpected step — a store that is
/// simply not DID-owned is `Ok(None)`, never an error — and READ-ONLY (never signs, spends, or
/// broadcasts). A [`ChainSource`] read error surfaces as [`MerkleError::Chain`].
///
/// # Authoritative ONLY for a CONFIRMED on-chain spend (NC-9)
///
/// The DID recognition in step 4 trusts STRUCTURE, not confirmation (see [`did_ref_from_spend`]).
/// The result is chain-proven ownership ONLY when the injected [`ChainSource`] returns genuine,
/// confirmed on-chain spends. A source that can be made to return unconfirmed or attacker-shaped
/// spends can be made to mis-attribute ownership; do not treat a `Some` result as proof of ownership
/// unless the `ChainSource` is trusted to return confirmed spends.
///
/// # Errors
///
/// Returns [`MerkleError::Chain`] if a [`ChainSource`] read fails, or [`MerkleError::Parse`] /
/// [`MerkleError::Driver`] if the creator spend fails to parse (propagated from
/// [`did_ref_from_spend`]).
pub fn resolve_owner_did<C: ChainSource>(
    store_id: Bytes32,
    chain: &C,
) -> MerkleResult<Option<DidRef>> {
    let Some(launcher_spend) = read_coin_spend(chain, store_id)? else {
        return Ok(None);
    };

    // Fail-closed identity binding (NC-9): a DIG store id IS its launcher coin id (read.rs docstring
    // step 1). The injected ChainSource is only trusted to return CONFIRMED spends, never to return
    // the RIGHT coin — a hostile/buggy source (e.g. the attacker-influenceable public gateway, §5.3)
    // can answer this read with a DIFFERENT store's valid, DID-rooted launcher. Without this check the
    // walk would attribute that other store's owning DID to `store_id`. Reject with an error (not
    // Ok(None)) so a substituted answer is distinguishable from a genuinely non-DID-owned store.
    if launcher_spend.coin.coin_id() != store_id {
        return Err(MerkleError::Chain(format!(
            "launcher spend for {store_id} is coin {}, not the requested store's launcher",
            launcher_spend.coin.coin_id()
        )));
    }

    let Some(creator_spend) = read_bound_spend(chain, launcher_spend.coin.parent_coin_info)? else {
        return Ok(None);
    };
    if let Some(did_ref) = did_ref_from_spend(&creator_spend)? {
        return Ok(Some(did_ref));
    }

    // The creator was not a DID. The ONE remaining shape a DID-rooted store can have is a singleton
    // parent that interposed an intermediate launcher coin; take exactly one more hop, and only when
    // this creator really is that intermediate.
    if !is_launcher_intermediate(&creator_spend, launcher_spend.coin) {
        return Ok(None);
    }
    let Some(singleton_spend) = read_bound_spend(chain, creator_spend.coin.parent_coin_info)?
    else {
        return Ok(None);
    };

    did_ref_from_spend(&singleton_spend)
}

/// Reads the spend of `coin_id` and binds the answer to the id that was asked for.
///
/// Fail-closed identity binding (NC-9): the injected [`ChainSource`] is trusted to return CONFIRMED
/// spends, never to return the RIGHT coin — a hostile or buggy source (the attacker-influenceable
/// public gateway, §5.3) can answer any read with an unrelated but valid DID spend, and without this
/// check the walk would recognise a DID that never authorized this store. A substituted answer is an
/// `Err`, not `Ok(None)`, so it stays distinguishable from a genuinely non-DID-owned store.
fn read_bound_spend<C: ChainSource>(
    chain: &C,
    coin_id: Bytes32,
) -> MerkleResult<Option<CoinSpend>> {
    let Some(spend) = read_coin_spend(chain, coin_id)? else {
        return Ok(None);
    };
    if spend.coin.coin_id() != coin_id {
        return Err(MerkleError::Chain(format!(
            "spend for {coin_id} is coin {}, not the coin that was requested",
            spend.coin.coin_id()
        )));
    }
    Ok(Some(spend))
}

/// Whether `spend` is the intermediate-launcher coin that created `launcher_coin` — the single hop
/// the owner walk is allowed to traverse (SPEC §3.1a/§3.7).
///
/// Recognised by the coin's actual PUZZLE: the uncurried `nft_intermediate_launcher` mod hash, with
/// its curried `launcher_puzzle_hash` argument bound to the singleton launcher. Because that puzzle
/// is fixed, its one `CREATE_COIN` is fully determined by the coin it is spending — so the launcher
/// it produces is DERIVED here rather than observed, and matched by full coin id.
///
/// Two reasons this is not recognised by shape instead:
///
/// - **It would run chain-supplied CLVM.** The spend comes from an untrusted [`ChainSource`], and
///   evaluating it means executing an attacker's program: 28 bytes of non-terminating puzzle burns
///   seconds of CPU at the block cost limit, and the walk still returns `Ok(None)`, so a caller sees
///   only latency and never an error. Uncurrying parses; it does not execute.
/// - **Shape is a looser bind than the puzzle.** "A 0-amount coin whose spend creates exactly this
///   launcher" admits ANY puzzle that happens to emit that one condition, not just the intermediate
///   launcher the walk means to traverse.
///
/// The `mint_number`/`mint_total` the caller chose are deliberately not constrained — they vary the
/// curried puzzle hash but not the behaviour. Any parse failure is `false` — fail closed.
fn is_launcher_intermediate(spend: &CoinSpend, launcher_coin: Coin) -> bool {
    if spend.coin.amount != 0 {
        return false;
    }

    let mut allocator = Allocator::new();
    let Ok(puzzle_ptr) = spend.puzzle_reveal.to_clvm(&mut allocator) else {
        return false;
    };
    let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

    // The reveal must be the coin it claims to be; a chain source that returns a different puzzle
    // than the coin commits to cannot steer the walk.
    if Bytes32::from(puzzle.curried_puzzle_hash()) != spend.coin.puzzle_hash {
        return false;
    }

    let Some(curried) = puzzle.as_curried() else {
        return false;
    };
    if curried.mod_hash != TreeHash::new(NFT_INTERMEDIATE_LAUNCHER_HASH) {
        return false;
    }

    let Ok(args) = NftIntermediateLauncherArgs::from_clvm(&allocator, curried.args) else {
        return false;
    };
    if args.launcher_puzzle_hash != Bytes32::from(SINGLETON_LAUNCHER_HASH) {
        return false;
    }

    // The intermediate puzzle's only output is a 1-mojo coin at the curried launcher puzzle hash,
    // parented by the coin being spent — so the launcher is derivable without running anything.
    Coin::new(spend.coin.coin_id(), args.launcher_puzzle_hash, 1).coin_id()
        == launcher_coin.coin_id()
}

/// Reads the spend that spent `coin_id`, mapping the source's own error into [`MerkleError::Chain`]
/// so the crate's error surface never leaks a generic `ChainSource::Error` type parameter.
fn read_coin_spend<C: ChainSource>(chain: &C, coin_id: Bytes32) -> MerkleResult<Option<CoinSpend>> {
    chain
        .coin_spend(coin_id)
        .map_err(|error| MerkleError::Chain(format!("chain read for {coin_id}: {error}")))
}

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

    use crate::resolve_owner_did;
    use crate::types::{Coin, CoinSpend};
    use chia_wallet_sdk::types::Conditions;
    use dig_chainsource_interface::{ChainSourceError, MockChainSource};

    /// Builds a real, on-chain DID and returns (its coin spend, its launcher id). The DID coin is
    /// created then update-spent so a genuine DID spend exists to be recognised.
    fn did_coin_and_spend(sim: &mut Simulator) -> anyhow::Result<(CoinSpend, Bytes32)> {
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);

        let (create_did, did) =
            Launcher::new(alice.coin.coin_id(), 1).create_simple_did(ctx, &alice_p2)?;
        alice_p2.spend(ctx, alice.coin, create_did)?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))?;

        let did_coin = did.coin;
        let _child = did.update(ctx, &alice_p2, Conditions::new())?;
        let coin_spends = ctx.take();
        sim.spend_coins(coin_spends.clone(), std::slice::from_ref(&alice.sk))?;

        let did_spend = coin_spends
            .into_iter()
            .find(|s| s.coin.coin_id() == did_coin.coin_id())
            .expect("the DID coin spend is present");
        Ok((did_spend, did.info.launcher_id))
    }

    /// A DID-owned store resolves to the owning DID: the walk fetches the launcher spend, reads its
    /// creator (the DID coin), and recognises the DID (SPEC §3.7).
    #[test]
    fn resolve_owner_did_returns_the_did_for_a_did_rooted_store() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (did_spend, did_launcher_id) = did_coin_and_spend(&mut sim)?;
        let did_coin_id = did_spend.coin.coin_id();

        // The store's launcher coin was created by spending the DID coin: its parent IS the DID coin.
        // A DIG store id IS its launcher coin id, so derive it from the launcher coin (the binding
        // the walk now enforces).
        let launcher_coin = Coin::new(did_coin_id, Bytes32::new([0xb2; 32]), 1);
        let store_id = launcher_coin.coin_id();
        // Only `launcher_spend.coin.parent_coin_info` is read by the walk; reuse a real program pair.
        let launcher_spend = CoinSpend::new(
            launcher_coin,
            did_spend.puzzle_reveal.clone(),
            did_spend.solution.clone(),
        );

        let chain = MockChainSource::new()
            .with_spend(store_id, launcher_spend)
            .with_spend(did_coin_id, did_spend);

        let did_ref = resolve_owner_did(store_id, &chain)?.expect("store is DID-owned");
        assert_eq!(
            did_ref.launcher_id, did_launcher_id,
            "resolve names the owning DID's launcher id"
        );
        Ok(())
    }

    /// LOAD-BEARING (#2418): a store launched from a DID SINGLETON — which must interpose an
    /// intermediate launcher coin to stay legal on chain — still resolves to its owning DID.
    ///
    /// Every spend here is real and was accepted by the simulator, so the walk is exercised against
    /// the exact bytes the launch composition produces, not a synthetic stand-in. Without the second
    /// hop this returns `Ok(None)` — a DID-rooted store reporting as not DID-owned.
    #[test]
    fn resolve_owner_did_traverses_the_intermediate_launcher_hop() -> anyhow::Result<()> {
        use chia_wallet_sdk::driver::IntermediateLauncher;

        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1_000_000);
        let alice_p2 = StandardLayer::new(alice.pk);

        let (create_did, did) =
            Launcher::new(alice.coin.coin_id(), 1).create_simple_did(ctx, &alice_p2)?;
        alice_p2.spend(ctx, alice.coin, create_did)?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))?;

        let did_coin_id = did.coin.coin_id();
        let did_launcher_id = did.info.launcher_id;
        let launcher = IntermediateLauncher::new(did_coin_id, 0, 1).create(ctx)?;
        let launch = crate::mint_datastore_launch_with_kind(
            ctx,
            crate::StoreKind::DidProfile,
            launcher,
            Bytes32::new([0x6d; 32]),
            None,
            None,
            None,
            None,
            None,
            alice.puzzle_hash,
            vec![],
        )?;
        let _child = did.update(ctx, &alice_p2, launch.parent_conditions.clone())?;

        // The intermediate coin is created at 0 mojos, so the launcher's mojo comes from elsewhere.
        let funder = sim.bls(1);
        StandardLayer::new(funder.pk).spend(ctx, funder.coin, Conditions::new())?;

        let coin_spends = ctx.take();
        sim.spend_coins(coin_spends.clone(), &[alice.sk.clone(), funder.sk.clone()])?;

        // Serve the REAL, on-chain-accepted spends back through the chain source.
        let store_id = launch.datastore.info.launcher_id;
        let chain = coin_spends
            .iter()
            .fold(MockChainSource::new(), |chain, spend| {
                chain.with_spend(spend.coin.coin_id(), spend.clone())
            });

        let did_ref = resolve_owner_did(store_id, &chain)?
            .expect("a singleton-rooted store resolves through the intermediate hop");
        assert_eq!(
            did_ref.launcher_id, did_launcher_id,
            "the walk names the DID that authorized the launch"
        );
        Ok(())
    }

    /// The walk STOPS after the intermediate hop: a DID sitting one creator further up is NOT
    /// reported. Chain: launcher ← a real intermediate ← an ordinary coin ← the DID.
    ///
    /// An unbounded parent walk returns `Some(did)` here, so this observes the bound rather than
    /// restating it — and the bound is what keeps an untrusted source from driving an unbounded climb,
    /// and keeps a store whose funding coin merely descends from a DID out of that DID's name.
    #[test]
    fn resolve_owner_did_does_not_walk_past_the_intermediate_hop() -> anyhow::Result<()> {
        use chia_wallet_sdk::driver::IntermediateLauncher;

        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let (did_spend, _did_launcher_id) = did_coin_and_spend(&mut sim)?;
        let did_coin_id = did_spend.coin.coin_id();

        // An ordinary coin whose PARENT is the DID coin — the extra hop the walk must not take.
        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);
        let memos = ctx.hint(alice.puzzle_hash)?;
        alice_p2.spend(
            ctx,
            alice.coin,
            Conditions::new().create_coin(alice.puzzle_hash, 1, memos),
        )?;
        let template = ctx
            .take()
            .into_iter()
            .find(|spend| spend.coin.coin_id() == alice.coin.coin_id())
            .expect("standard spend present");
        let ordinary_coin = Coin::new(did_coin_id, alice.puzzle_hash, alice.coin.amount);
        let ordinary_spend = CoinSpend::new(
            ordinary_coin,
            template.puzzle_reveal.clone(),
            template.solution.clone(),
        );

        // A real intermediate launcher parented to that ordinary coin.
        let intermediate = IntermediateLauncher::new(ordinary_coin.coin_id(), 0, 1);
        let launcher_coin = intermediate.launcher_coin();
        let _launcher = intermediate.create(ctx)?;
        let intermediate_spend = ctx
            .take()
            .into_iter()
            .next()
            .expect("the intermediate coin spend is staged");
        let launcher_spend = CoinSpend::new(
            launcher_coin,
            template.puzzle_reveal.clone(),
            template.solution.clone(),
        );

        let store_id = launcher_coin.coin_id();
        let chain = MockChainSource::new()
            .with_spend(store_id, launcher_spend)
            .with_spend(intermediate_spend.coin.coin_id(), intermediate_spend)
            .with_spend(ordinary_coin.coin_id(), ordinary_spend)
            .with_spend(did_coin_id, did_spend);

        assert_eq!(
            resolve_owner_did(store_id, &chain)?,
            None,
            "a DID two creators above the launcher is out of the walk's bound"
        );
        Ok(())
    }

    /// LOAD-BEARING: a hostile [`ChainSource`] cannot make the walk EXECUTE a program of its
    /// choosing.
    ///
    /// The fixture is a 7-byte non-terminating puzzle — `(a 1 1)`, which applies its own solution to
    /// itself forever — presented as the launcher's creator at amount 0, with the coin's puzzle hash
    /// set to that puzzle's real tree hash so the spend is internally consistent. It therefore
    /// satisfies every precondition the old shape-based recogniser checked before running the spend,
    /// which is what makes it discriminating: the previous implementation evaluated it at the full
    /// mainnet block cost limit (measured: ~7.1s of single-thread CPU in a release build, far worse
    /// unoptimised) and still answered `Ok(None)`, so a caller saw only unexplained latency.
    ///
    /// The elapsed-time bound is the assertion, because the property IS about CPU. The margin is
    /// enormous by construction — recognising the puzzle without running it is microseconds, and the
    /// old path could not finish in seconds — so this cannot flake on a slow machine.
    #[test]
    fn the_walk_never_runs_a_chain_supplied_puzzle() -> anyhow::Result<()> {
        use chia_wallet_sdk::clvm_utils::tree_hash;
        use std::time::Instant;

        // `(a 1 1)`: apply the environment as a program, in that same environment — non-terminating.
        let hostile_bytes = hex_literal::hex!("ff02ff01ff0180").to_vec();
        let hostile = crate::types::CoinSpend::new(
            Coin::new(Bytes32::new([0x9e; 32]), Bytes32::new([0; 32]), 0),
            hostile_bytes.clone().into(),
            hostile_bytes.into(),
        );

        // Bind the coin to the puzzle it reveals, so the fixture passes every check that precedes
        // the point at which the old implementation would have started executing.
        let mut allocator = Allocator::new();
        let puzzle_ptr = hostile.puzzle_reveal.to_clvm(&mut allocator)?;
        let hostile = crate::types::CoinSpend::new(
            Coin::new(
                hostile.coin.parent_coin_info,
                tree_hash(&allocator, puzzle_ptr).into(),
                0,
            ),
            hostile.puzzle_reveal,
            hostile.solution,
        );

        let launcher_coin = Coin::new(
            hostile.coin.coin_id(),
            Bytes32::from(SINGLETON_LAUNCHER_HASH),
            1,
        );
        let store_id = launcher_coin.coin_id();
        let launcher_spend = CoinSpend::new(
            launcher_coin,
            hostile.puzzle_reveal.clone(),
            hostile.solution.clone(),
        );
        let chain = MockChainSource::new()
            .with_spend(store_id, launcher_spend)
            .with_spend(hostile.coin.coin_id(), hostile);

        let started = Instant::now();
        let resolved = resolve_owner_did(store_id, &chain)?;
        let elapsed = started.elapsed();

        assert_eq!(resolved, None, "a hostile creator is not a DID owner");
        assert!(
            elapsed.as_secs() < 2,
            "the walk must recognise the hop without executing chain-supplied CLVM, but took \
             {elapsed:?}"
        );
        Ok(())
    }

    /// A plain (non-DID) store resolves to `None`: the launcher's creator is an ordinary coin, not a
    /// DID — fail-closed, never an error (SPEC §3.7).
    #[test]
    fn resolve_owner_did_returns_none_for_a_plain_store() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);
        let memos = ctx.hint(alice.puzzle_hash)?;
        alice_p2.spend(
            ctx,
            alice.coin,
            Conditions::new().create_coin(alice.puzzle_hash, 1, memos),
        )?;
        let creator_spend = ctx
            .take()
            .into_iter()
            .find(|s| s.coin.coin_id() == alice.coin.coin_id())
            .expect("standard creator spend present");

        // A DIG store id IS its launcher coin id (the binding the walk enforces).
        let launcher_coin = Coin::new(alice.coin.coin_id(), Bytes32::new([0xd4; 32]), 1);
        let store_id = launcher_coin.coin_id();
        let launcher_spend = CoinSpend::new(
            launcher_coin,
            creator_spend.puzzle_reveal.clone(),
            creator_spend.solution.clone(),
        );

        let chain = MockChainSource::new()
            .with_spend(store_id, launcher_spend)
            .with_spend(alice.coin.coin_id(), creator_spend);

        assert_eq!(
            resolve_owner_did(store_id, &chain)?,
            None,
            "a plainly-minted store has no owning DID"
        );
        Ok(())
    }

    /// A missing launcher spend fails closed to `Ok(None)` — the store is unknown to the source.
    #[test]
    fn resolve_owner_did_none_when_launcher_spend_missing() -> anyhow::Result<()> {
        let chain = MockChainSource::new();
        assert_eq!(
            resolve_owner_did(Bytes32::new([0xee; 32]), &chain)?,
            None,
            "an unknown store id resolves to None"
        );
        Ok(())
    }

    /// A missing CREATOR spend (launcher present, its parent unknown) also fails closed to `Ok(None)`.
    #[test]
    fn resolve_owner_did_none_when_creator_spend_missing() -> anyhow::Result<()> {
        let parent_id = Bytes32::new([0x2b; 32]);
        // A launcher spend whose creator (parent) is not in the source. A DIG store id IS its
        // launcher coin id (the binding the walk enforces).
        let mut sim = Simulator::new();
        let (any_spend, _) = did_coin_and_spend(&mut sim)?;
        let launcher_coin = Coin::new(parent_id, Bytes32::new([0x3c; 32]), 1);
        let store_id = launcher_coin.coin_id();
        let launcher_spend = CoinSpend::new(
            launcher_coin,
            any_spend.puzzle_reveal.clone(),
            any_spend.solution.clone(),
        );

        let chain = MockChainSource::new().with_spend(store_id, launcher_spend);
        assert_eq!(resolve_owner_did(store_id, &chain)?, None);
        Ok(())
    }

    /// A SUBSTITUTED launcher — the source answers `store_id` with a DIFFERENT store's valid,
    /// DID-rooted launcher — fails closed to `Err(MerkleError::Chain)`, NOT the wrong DID and NOT
    /// `Ok(None)`. Without the `launcher_spend.coin.coin_id() == store_id` binding this returns
    /// `Ok(Some(other_did))` and mis-attributes ownership (NC-9, §5.3).
    #[test]
    fn resolve_owner_did_rejects_a_substituted_launcher() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (did_spend, _did_launcher_id) = did_coin_and_spend(&mut sim)?;
        let did_coin_id = did_spend.coin.coin_id();

        // A genuine, DID-rooted launcher for store B (its coin_id is store B's real id).
        let launcher_coin = Coin::new(did_coin_id, Bytes32::new([0xb2; 32]), 1);
        let store_b_id = launcher_coin.coin_id();
        let launcher_spend = CoinSpend::new(
            launcher_coin,
            did_spend.puzzle_reveal.clone(),
            did_spend.solution.clone(),
        );

        // The caller asks for store A, but the source returns store B's launcher under A's id.
        let store_a_id = Bytes32::new([0xa1; 32]);
        assert_ne!(
            store_a_id, store_b_id,
            "the requested id differs from the answer's coin id"
        );
        let chain = MockChainSource::new()
            .with_spend(store_a_id, launcher_spend)
            .with_spend(did_coin_id, did_spend);

        assert!(
            matches!(
                resolve_owner_did(store_a_id, &chain),
                Err(MerkleError::Chain(_))
            ),
            "a substituted launcher is rejected, not attributed to the other store's DID"
        );
        Ok(())
    }

    /// A WRONG creator — the launcher is genuine, but the source answers `parent_id` with a spend of
    /// a coin whose `coin_id() != parent_id` — fails closed to `Err(MerkleError::Chain)`. Without the
    /// `creator_spend.coin.coin_id() == parent_id` binding this recognises a DID that never authorized
    /// the store (NC-9).
    #[test]
    fn resolve_owner_did_rejects_a_wrong_creator() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let (did_spend, _did_launcher_id) = did_coin_and_spend(&mut sim)?;
        let did_coin_id = did_spend.coin.coin_id();

        // The launcher's parent is a fabricated id that is NOT the DID coin's id.
        let fake_parent_id = Bytes32::new([0x7f; 32]);
        assert_ne!(
            fake_parent_id, did_coin_id,
            "the parent id is not the DID coin's id"
        );
        let launcher_coin = Coin::new(fake_parent_id, Bytes32::new([0xb2; 32]), 1);
        let store_id = launcher_coin.coin_id();
        let launcher_spend = CoinSpend::new(
            launcher_coin,
            did_spend.puzzle_reveal.clone(),
            did_spend.solution.clone(),
        );

        // The source returns the real DID spend (coin_id == did_coin_id) under the fake parent id.
        let chain = MockChainSource::new()
            .with_spend(store_id, launcher_spend)
            .with_spend(fake_parent_id, did_spend);

        assert!(
            matches!(
                resolve_owner_did(store_id, &chain),
                Err(MerkleError::Chain(_))
            ),
            "a creator spend not bound to the launcher's parent is rejected"
        );
        Ok(())
    }

    /// PINS A KNOWN GAP, tracked as **#2463** — this is NOT desired behaviour.
    ///
    /// The memo-scannable profile chain (`DID coin -> ordinary EVEN-amount coin -> launcher (memos
    /// intact) -> store`, SPEC §3.1a) is NOT lineage-resolvable: the launcher's creator is an
    /// ordinary coin, which is neither a DID nor the recognised intermediate launcher, so the walk
    /// stops at `Ok(None)` and a DID-rooted profile store reports as not-DID-owned.
    ///
    /// Extending the walk over that hop is refused deliberately: an ordinary coin's outputs are
    /// knowable only by EXECUTING its puzzle — the chain-supplied CLVM the walk exists to never run
    /// (see [`is_launcher_intermediate`]) — and accepting the parent claim unexamined would let any
    /// store whose launcher's parent happened to be DID-created falsely claim DID ownership.
    ///
    /// Every spend here is real and was accepted by the simulator, so this pins what the composition
    /// the SPEC recommends actually resolves to today, and will fail the moment #2463 changes it.
    #[test]
    fn the_memo_scannable_profile_chain_does_not_resolve_its_did() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1_000_000);
        let alice_p2 = StandardLayer::new(alice.pk);

        // Every block's spends are kept, because the chain source must serve the WHOLE lineage —
        // the walk stopping early must be the resolver's doing, not a source that forgot the DID.
        let mut settled: Vec<CoinSpend> = Vec::new();

        // Block 1 — the DID exists.
        let (create_did, did) =
            Launcher::new(alice.coin.coin_id(), 1).create_simple_did(ctx, &alice_p2)?;
        alice_p2.spend(ctx, alice.coin, create_did)?;
        let block = ctx.take();
        sim.spend_coins(block.clone(), std::slice::from_ref(&alice.sk))?;
        settled.extend(block);

        // Block 2 — the DID creates an ORDINARY, EVEN-amount coin. Even keeps the singleton's
        // one-odd-`CREATE_COIN` rule satisfied, which is what makes this composition legal.
        let did_coin_id = did.coin.coin_id();
        let ordinary = Coin::new(did_coin_id, alice.puzzle_hash, 2);
        let hint = ctx.hint(alice.puzzle_hash)?;
        let _child = did.update(
            ctx,
            &alice_p2,
            Conditions::new().create_coin(alice.puzzle_hash, 2, hint),
        )?;
        // The DID recreates itself AND emits the 2-mojo coin, so the bundle needs those 2 mojos from
        // elsewhere; Chia balances a bundle in aggregate, not per coin.
        let funder = sim.bls(2);
        StandardLayer::new(funder.pk).spend(ctx, funder.coin, Conditions::new())?;
        let block = ctx.take();
        sim.spend_coins(block.clone(), &[alice.sk.clone(), funder.sk.clone()])?;
        settled.extend(block);

        // Block 3 — the ordinary coin launches the store DIRECTLY, so the memos ARE written.
        let launch = crate::mint_datastore_launch_with_kind(
            ctx,
            crate::StoreKind::DidProfile,
            Launcher::new(ordinary.coin_id(), 1),
            Bytes32::new([0x6d; 32]),
            None,
            None,
            None,
            None,
            None,
            alice.puzzle_hash,
            vec![],
        )?;
        assert!(
            launch.launcher_memos_written,
            "the direct shape is the one that IS memo-scannable (test precondition)"
        );
        alice_p2.spend(ctx, ordinary, launch.parent_conditions.clone())?;
        let block = ctx.take();
        sim.spend_coins(block.clone(), std::slice::from_ref(&alice.sk))?;
        settled.extend(block);

        let store_id = launch.datastore.info.launcher_id;
        let chain = settled.iter().fold(MockChainSource::new(), |chain, spend| {
            chain.with_spend(spend.coin.coin_id(), spend.clone())
        });

        // The `None` must be caused by the ORDINARY hop, not by a fixture that lost its DID: the
        // launcher's creator really is the ordinary coin, that coin's creator really is the DID coin,
        // and the source really can serve every spend in between. Without these the assertion below
        // would also pass on a chain that simply had no DID in it.
        let launcher_spend = chain
            .coin_spend(store_id)?
            .expect("the source serves the launcher spend");
        assert_eq!(
            launcher_spend.coin.parent_coin_info,
            ordinary.coin_id(),
            "the launcher's creator is the ordinary even-amount coin"
        );
        let ordinary_spend = chain
            .coin_spend(ordinary.coin_id())?
            .expect("the source serves the ordinary coin's spend");
        assert_eq!(
            ordinary_spend.coin.parent_coin_info, did_coin_id,
            "and that coin's own creator is the DID — the DID sits exactly two hops up"
        );
        assert!(
            crate::did_ref_from_spend(&ordinary_spend)?.is_none()
                && !super::is_launcher_intermediate(&ordinary_spend, launcher_spend.coin),
            "the creator is neither a DID nor the recognised intermediate launcher — the only two \
             shapes the walk can traverse, which is exactly why it stops"
        );
        assert!(
            crate::did_ref_from_spend(
                &chain
                    .coin_spend(did_coin_id)?
                    .expect("the source serves the DID spend")
            )?
            .is_some(),
            "the DID spend IS present and IS recognisable, so only the ordinary hop stops the walk"
        );

        assert_eq!(
            resolve_owner_did(store_id, &chain)?,
            None,
            "KNOWN GAP #2463: the memo-scannable profile chain resolves to None, because the \
             launcher's creator is an ordinary coin the walk cannot traverse without running \
             chain-supplied CLVM"
        );
        Ok(())
    }

    /// A [`ChainSource`] read ERROR surfaces as [`MerkleError::Chain`] — distinct from a fail-closed
    /// `None` (the chain could not be consulted, so ownership is unknown).
    #[test]
    fn resolve_owner_did_maps_chain_error() {
        let chain = MockChainSource::new().fail_with(ChainSourceError::Timeout);
        let result = resolve_owner_did(Bytes32::new([0x44; 32]), &chain);
        assert!(
            matches!(result, Err(MerkleError::Chain(_))),
            "a source read error is a Chain error, not None"
        );
    }
}
