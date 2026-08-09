//! The DataLayer-coin mint builder (SPEC §3.1) — launch a new store singleton anchoring a root.
//!
//! [`mint_datastore`] builds the unsigned coin spends that launch a fresh CHIP-0035 DataLayer
//! singleton whose `launcher_id` becomes the DIG `store_id`. It funds the launcher from a caller-
//! supplied `parent_coin`, curries the store's [`DigDataStoreMetadata`] (the anchored merkle
//! `root_hash` plus optional label/description/size-proof/program-hash/size-bucket) and
//! delegated-puzzle set, and — the
//! load-bearing detail — overrides the launcher `CREATE_COIN` memos to the two-memo owner-discovery
//! hint so a minted store is byte-identical to the stores chip35_dl_coin and digstore-chain already
//! publish on-chain (SPEC §9).
//!
//! The builder is pure, key-free, and unsigned (INV-1..4): the parent/owner spend it produces
//! requires an `AGG_SIG_ME` over the owner's synthetic key, which the caller obtains via
//! [`crate::required_signatures`] and fulfils with its own signer.

use chia_wallet_sdk::driver::{Launcher, SpendContext};
use chia_wallet_sdk::puzzles::SINGLETON_LAUNCHER_HASH;
use chia_wallet_sdk::types::conditions::CreateCoin;
use chia_wallet_sdk::types::{Condition, Conditions};
use clvm_traits::FromClvm;

use crate::context::{drain_coin_spends, inner_spend};
use crate::hint::{digstore_owner_hint, launcher_hint_for, StoreKind};
use crate::metadata::DigDataStoreMetadata;
use crate::size::SizeBucket;
use crate::types::{Bytes32, Coin, DataStore, DelegatedPuzzle, MerkleCoinSpend, Owner};
use crate::{MerkleError, MerkleResult};

/// The well-known singleton launcher puzzle hash, as a coin puzzle hash. A `CREATE_COIN` to it mints
/// the store's launcher coin (whose `coin_id == launcher_id == store_id`); it is the memo carrier
/// [`override_launcher_hint`] rewrites with the owner-discovery hint.
///
/// Sourced from the SDK constant [`crate::read`] also reads, so the mint's legality guard and the
/// read recogniser can never compare against two different definitions of one canonical value. (The
/// ecosystem-wide move of such constants into `dig-constants` is tracked as #2464.)
const SINGLETON_LAUNCHER_PUZZLE_HASH: Bytes32 = Bytes32::new(SINGLETON_LAUNCHER_HASH);

/// Builds the unsigned spends that mint a new DataLayer store singleton anchoring `root_hash`.
///
/// The `parent_coin` funds and parents the launcher: its `coin_id` becomes the launcher's parent, so
/// `launcher_id == store_id` is derived from it. `parent_coin` is spent by `owner` (its p2 puzzle),
/// which authorizes creating the launcher coin (1 mojo) and returns any value above `fee + 1` mojos
/// as change to `owner_puzzle_hash`. The `fee` is paid implicitly as the difference between the
/// parent coin's value and the launcher + change amounts — no explicit `RESERVE_FEE` condition,
/// matching the on-chain producers byte-for-byte.
///
/// `program_hash` optionally anchors the CLVM tree-hash of a program/puzzle associated with the
/// store/capsule; it is stored and echoed verbatim in the store metadata (CLVM key `"p"`) and is
/// `None` for an ordinary store. `size_bucket` optionally anchors the store's size as a power-of-2
/// bucket (CLVM key `"sz"`, appended last — see [`SizeBucket`]). With BOTH `None`, a mint is
/// byte-identical to the SDK's default metadata (SPEC §2/§8). dig-merkle never computes either; the
/// producer passes them in.
///
/// `owner_puzzle_hash` is the store owner recorded in the singleton (and the target of the owner
/// discovery hint + any change); `delegated_puzzles` grants admin/writer/oracle authority. The
/// launcher `CREATE_COIN` memos are overridden to
/// `[digstore_owner_hint(owner_puzzle_hash), DATASTORE_LAUNCHER_HINT]` so the store is discoverable
/// by owner and byte-identical to existing on-chain stores (SPEC §9).
///
/// # DID composition
///
/// dig-merkle never depends on `dig-did`. To root a store in a DID, do NOT use this function: it
/// parents the launcher directly to `parent_coin`, and a DID is a singleton, whose inner puzzle may
/// emit exactly ONE odd-amount `CREATE_COIN` — its own successor. A 1-mojo launcher alongside that
/// recreation is a second odd output, so the bundle is REJECTED on chain. Use
/// [`mint_datastore_launch_with_kind`] with an `IntermediateLauncher` instead; it returns the
/// conditions the DID's own spend must emit as [`DatastoreLaunch::parent_conditions`], and the
/// launcher descends from the DID through an even-amount intermediate coin with no `dig-did`
/// coupling here.
///
/// # Signing
///
/// The returned spends are UNSIGNED. An [`Owner::Standard`] mint requires exactly one `AGG_SIG_ME`
/// over the owner's synthetic key on the parent/owner spend; obtain it via
/// [`crate::required_signatures`].
///
/// # Errors
///
/// Returns [`MerkleError::Driver`] if the SDK fails to construct the
/// launcher or the owner spend (e.g. an invalid metadata or delegated-puzzle set).
#[allow(clippy::too_many_arguments)]
pub fn mint_datastore(
    parent_coin: Coin,
    owner: Owner,
    root_hash: Bytes32,
    label: Option<String>,
    description: Option<String>,
    size_proof: Option<String>,
    program_hash: Option<Bytes32>,
    size_bucket: Option<SizeBucket>,
    owner_puzzle_hash: Bytes32,
    delegated_puzzles: Vec<DelegatedPuzzle>,
    fee: u64,
) -> MerkleResult<MerkleCoinSpend> {
    // The historical entry point mints an ordinary file-backed store — byte-identical to every store
    // chip35_dl_coin and digstore-chain already publish (its launcher discriminator is unchanged).
    mint_datastore_with_kind(
        StoreKind::File,
        parent_coin,
        owner,
        root_hash,
        label,
        description,
        size_proof,
        program_hash,
        size_bucket,
        owner_puzzle_hash,
        delegated_puzzles,
        fee,
    )
}

/// Builds the unsigned spends that mint a new DataLayer store of a chosen [`StoreKind`] (#1263).
///
/// Identical to [`mint_datastore`] in every respect except the SECOND launcher memo — the kind
/// discriminator ([`launcher_hint_for`]). [`StoreKind::File`] emits exactly the same bytes as
/// [`mint_datastore`] (they share this implementation), so a file mint stays byte-identical to
/// existing on-chain stores; [`StoreKind::DidProfile`] emits the DID-profile discriminator instead.
/// The first launcher memo is always the kind-agnostic owner hint. See [`mint_datastore`] for the
/// full argument, DID-composition, signing, and error semantics.
///
/// # Errors
///
/// Returns [`MerkleError::UnsupportedOwner`] for [`Owner::Custom`]: this function builds the launch
/// conditions itself, so a pre-built inner spend cannot possibly emit them (it would return a bundle
/// that never creates the launcher coin). Custom owners compose the launch via
/// [`mint_datastore_launch_with_kind`].
#[allow(clippy::too_many_arguments)]
pub fn mint_datastore_with_kind(
    kind: StoreKind,
    parent_coin: Coin,
    owner: Owner,
    root_hash: Bytes32,
    label: Option<String>,
    description: Option<String>,
    size_proof: Option<String>,
    program_hash: Option<Bytes32>,
    size_bucket: Option<SizeBucket>,
    owner_puzzle_hash: Bytes32,
    delegated_puzzles: Vec<DelegatedPuzzle>,
    fee: u64,
) -> MerkleResult<MerkleCoinSpend> {
    if matches!(owner, Owner::Custom(_)) {
        return Err(MerkleError::UnsupportedOwner(
            "a launch's parent conditions are built inside this call, so Owner::Custom cannot emit \
             them — use mint_datastore_launch_with_kind and compose the parent spend yourself",
        ));
    }

    let mut ctx = SpendContext::new();

    // ONE code path with the caller-composed launch (below), so byte identity is structural. An
    // ordinary (non-singleton) parent creates the 1-mojo launcher directly — see
    // [`mint_datastore_launch_with_kind`] for why a singleton parent cannot.
    // This path always launches directly from an ordinary coin, so the memos are always written; the
    // flag exists for callers that compose their own launcher shape. The `debug_assert!` below makes
    // that claim load-bearing rather than a comment that could quietly stop being true.
    let DatastoreLaunch {
        parent_conditions: launch_conditions,
        datastore,
        launcher_memos_written,
        ..
    } = mint_datastore_launch_with_kind(
        &mut ctx,
        kind,
        Launcher::new(parent_coin.coin_id(), 1),
        root_hash,
        label,
        description,
        size_proof,
        program_hash,
        size_bucket,
        owner_puzzle_hash,
        delegated_puzzles,
    )?;
    debug_assert!(
        launcher_memos_written,
        "a direct launch emits the launcher CREATE_COIN itself, so the memo rewrite must have fired"
    );

    // Return the parent coin's surplus (above the 1-mojo launcher + `fee`) to the owner as change,
    // hinted to their puzzle hash. The fee is thereby paid implicitly (coins in minus coins out).
    let reserved = fee
        .checked_add(1)
        .ok_or_else(|| MerkleError::Chain("fee overflow: fee + 1 exceeds u64::MAX".into()))?;
    let owner_conditions = if parent_coin.amount > reserved {
        let change_hint = ctx.hint(owner_puzzle_hash)?;
        launch_conditions.create_coin(
            owner_puzzle_hash,
            parent_coin.amount - reserved,
            change_hint,
        )
    } else {
        launch_conditions
    };

    // Spend the parent coin with the owner's inner puzzle, emitting the launch + change conditions.
    let owner_spend = inner_spend(&mut ctx, owner, owner_conditions)?;
    ctx.spend(parent_coin, owner_spend)?;

    Ok(MerkleCoinSpend::new(
        drain_coin_spends(&mut ctx),
        Some(datastore),
    ))
}

/// Everything a DataLayer launch needs EXCEPT the parent-coin spend.
///
/// `parent_conditions` are allocated in the [`SpendContext`] passed to
/// [`mint_datastore_launch_with_kind`] and are valid ONLY in that context — `Conditions` holds CLVM
/// node pointers that index into the allocator that built them. The launcher-coin and eve-DataStore
/// spends are already staged into that same context; the caller adds its parent-coin spend and drains
/// the context ONCE, at the end.
/// Marked `#[non_exhaustive]` so a future launch fact can be reported without breaking downstream
/// destructuring: callers MUST use `..` and this crate stays the only constructor.
#[derive(Debug, Clone)]
#[must_use]
#[non_exhaustive]
pub struct DatastoreLaunch {
    /// What the parent coin's spend must emit: the `CREATE_COIN` that starts the launch — the
    /// launcher itself (carrying the two DIG owner-discovery memos) for a direct launch, or the
    /// even-amount intermediate coin for a singleton-parent launch — plus the announcement
    /// assertions binding the chain together. No change, no fee — those belong to whoever pays, and
    /// the caller adds them to its own spend.
    pub parent_conditions: Conditions,

    /// The eve DataStore as it will exist once the launch confirms.
    pub datastore: DataStore<DigDataStoreMetadata>,

    /// Whether this launch actually wrote the launcher memos — the two-memo owner-discovery hint AND
    /// the [`StoreKind`] discriminator (SPEC §9).
    ///
    /// `true` for a DIRECT launch, where the launcher `CREATE_COIN` is one of `parent_conditions` and
    /// can therefore be rewritten. `false` for an INTERMEDIATE launch, where that condition is
    /// emitted by the intermediate coin's own fixed `NftIntermediateLauncherArgs` puzzle, which this
    /// crate does not author and cannot add memos to — so the `kind` argument is silently unrecorded
    /// on chain and the store is invisible to a launcher-memo scan.
    ///
    /// This is measured, not inferred: it reports whether the rewrite fired, so it cannot drift from
    /// what the bundle actually contains. A caller whose store MUST be memo-scannable — every profile
    /// store — checks this field and uses the direct shape.
    pub launcher_memos_written: bool,
}

/// Builds a DataLayer launch into the CALLER's [`SpendContext`], returning the conditions the
/// caller's parent-coin spend must emit (SPEC §3.1).
///
/// This is the composable half of [`mint_datastore_with_kind`]: it stages the launcher-coin and
/// eve-DataStore spends into `ctx` and hands back the parent conditions, leaving the caller free to
/// authorize the parent coin however it likes — a DID-authorized spend, a vault, a multisig — and to
/// add its own change and fee. `mint_datastore_with_kind` is exactly this function plus a standard-p2
/// parent spend, so both paths emit identical bytes by construction.
///
/// # The context is the caller's, and this function does NOT drain it
///
/// `ctx` MUST be the same context the caller will build its parent spend in and drain: the returned
/// [`Conditions`] hold node pointers into that allocator, and the launcher/eve coin spends are staged
/// there. Draining here would strand them. The caller's sequence is: call this, add its parent spend
/// via `ctx.spend(..)`, then drain once.
///
/// # The caller supplies the launcher — because the legal shape depends on the parent
///
/// `launcher` is pre-built by the caller, which is what lets ONE function serve both parent shapes
/// without dig-merkle knowing anything about DIDs or singletons:
///
/// - **An ordinary coin** parents the launcher directly: `Launcher::new(parent_coin.coin_id(), 1)`.
/// - **A singleton** (a DID, another DataStore, a vault singleton) MUST interpose an intermediate
///   coin: `IntermediateLauncher::new(parent_coin.coin_id(), 0, 1).create(ctx)?`. A Chia singleton's
///   inner puzzle may emit exactly ONE odd-amount `CREATE_COIN` — its own successor — so a 1-mojo
///   launcher emitted alongside the recreation is a second odd output and the bundle is REJECTED on
///   chain. `IntermediateLauncher` creates its intermediate coin at amount 0 (even); only that coin
///   creates the odd launcher.
///
/// The launcher is checked for LEGALITY — the singleton launcher puzzle hash, and an ODD
/// `singleton_amount` — and its `CREATE_COIN` chain is then checked for REACHABILITY. The two are
/// independent: reachability alone is satisfied by construction for any caller-supplied launcher,
/// because the conditions are built from that same coin's fields.
///
/// The odd-amount check is on the SINGLETON's amount, which is what the store is minted at — NOT the
/// launcher coin's, which is not an invariant (a 0-amount launcher minting a 1-mojo singleton is a
/// legal SDK composition). An even-amount store builds cleanly AND is accepted on chain, and only
/// then is it discovered to be permanently frozen: the singleton odd-amount rule makes every later
/// `update_root` and `melt` raise, so it can never be spent again and the mojos are burned. Refusing
/// it here is the only point at which that is still reversible.
///
/// # The owner-discovery memos need a DIRECT launcher (SPEC §3.7), and `kind` rides on them
///
/// The two-memo owner-discovery hint (SPEC §9) lives on the launcher `CREATE_COIN`, so it can only be
/// written when THIS launch emits that condition — i.e. the direct shape. An intermediate-launcher
/// launch has its launcher `CREATE_COIN` emitted by the intermediate coin's own fixed
/// `NftIntermediateLauncherArgs` puzzle, which this crate does not author and cannot add memos to.
///
/// So on the intermediate path BOTH memos are absent: the owner hint AND the `kind` discriminator.
/// **`kind` is accepted but not honoured there** — the launch still succeeds, and reports
/// [`DatastoreLaunch::launcher_memos_written`] `== false` so the caller can see it. Such a store is
/// invisible to a launcher-memo scan and is discovered only by the lineage walk in
/// [`crate::resolve_owner_did`], which traverses the intermediate hop.
///
/// **A PROFILE store must be memo-scannable, so the intermediate is NOT the profile-launch shape.**
/// The supported profile chain is `DID coin -> ordinary EVEN-amount coin -> launcher (memos intact)
/// -> store`: the singleton creates an ordinary even-amount coin, and THAT coin launches directly.
/// This is legal because the one-odd-`CREATE_COIN` restriction binds the *singleton's* inner puzzle,
/// not an ordinary coin. Use the intermediate shape only where memo-scannability is not required.
///
/// # Errors
///
/// Returns [`MerkleError::Driver`] if the SDK fails to construct the launcher, and
/// [`MerkleError::Chain`] if the supplied launcher coin is not a legal launcher (wrong puzzle hash,
/// or an even amount) or if the built conditions do not lead to it. Together these are fail-closed
/// class guards, so neither an unlaunchable bundle nor one that launches a permanently frozen store
/// can be returned as a success.
#[allow(clippy::too_many_arguments)]
pub fn mint_datastore_launch_with_kind(
    ctx: &mut SpendContext,
    kind: StoreKind,
    launcher: Launcher,
    root_hash: Bytes32,
    label: Option<String>,
    description: Option<String>,
    size_proof: Option<String>,
    program_hash: Option<Bytes32>,
    size_bucket: Option<SizeBucket>,
    owner_puzzle_hash: Bytes32,
    delegated_puzzles: Vec<DelegatedPuzzle>,
) -> MerkleResult<DatastoreLaunch> {
    // The launcher coin and the singleton amount are both fixed the moment the caller builds the
    // `Launcher`; capture them before the builder consumes it, so the guards below can read them.
    let launcher_coin = launcher.coin();
    assert_launcher_is_legal(launcher_coin, launcher.singleton_amount())?;

    // Build the launcher + eve DataStore via the SDK (the byte-source-of-truth, INV-4). The returned
    // conditions are what the parent coin must emit to create the launcher coin.
    let (launch_conditions, datastore) = launcher.mint_datastore(
        ctx,
        DigDataStoreMetadata {
            root_hash,
            label,
            description,
            size_proof,
            program_hash,
            size_bucket,
        },
        owner_puzzle_hash.into(),
        delegated_puzzles,
    )?;
    assert_minted_singleton_amount_is_odd(datastore.coin.amount)?;

    // Override the launcher CREATE_COIN memos to the two-memo owner-discovery hint (SPEC §9). This is
    // the byte-identity requirement: the raw SDK mint emits only a single default hint, which matches
    // no store already on chain.
    let (parent_conditions, launcher_memos_written) =
        override_launcher_hint(ctx, launch_conditions, owner_puzzle_hash, kind)?;

    #[cfg(test)]
    let parent_conditions = tests::drop_launcher_if_armed(parent_conditions);

    assert_launch_reaches_the_launcher(ctx, &parent_conditions, launcher_coin)?;

    Ok(DatastoreLaunch {
        parent_conditions,
        datastore,
        launcher_memos_written,
    })
}

/// Fails closed unless the caller's [`Launcher`] could actually mint a spendable store singleton.
///
/// This is a check on what the CALLER supplied, and it is deliberately separate from the reachability
/// guard below, which cannot substitute for it: the launch conditions are derived from the launcher
/// coin's own puzzle hash and amount, so "the conditions create this coin" is true by construction for
/// every caller-supplied launcher and says nothing about whether the launch is legal.
///
/// Two properties, each catching a bundle the chain would otherwise accept or silently mishandle:
///
/// - **The singleton launcher puzzle hash.** A launcher at any other puzzle hash never mints a
///   singleton, and [`override_launcher_hint`] — which matches on this same constant — would silently
///   leave the owner-discovery memos unwritten.
/// - **An ODD `singleton_amount`.** A singleton's amount must stay odd; an even-amount store is
///   ACCEPTED on chain and every subsequent spend of it raises, so it can never be updated or melted
///   and its mojos are burned. That failure is irreversible and surfaces only much later, which is
///   why it is refused at build time.
///
/// **The invariant lives on the SINGLETON's amount, never the launcher coin's.**
/// [`Launcher::singleton_amount`] is a separate SDK field that merely DEFAULTS to the launcher coin's
/// amount and can be overridden ([`Launcher::with_singleton_amount`]); the minted store's amount is
/// always that field. Reading the launcher coin's amount instead would both admit a 1-mojo launcher
/// minting an even singleton (a frozen store reported as success) and refuse the SDK's own documented
/// composition, a 0-amount launcher minting a 1-mojo singleton — which is perfectly legal, because the
/// launcher coin's own amount is not an invariant at all.
fn assert_launcher_is_legal(launcher_coin: Coin, singleton_amount: u64) -> MerkleResult<()> {
    if launcher_coin.puzzle_hash != SINGLETON_LAUNCHER_PUZZLE_HASH {
        return Err(MerkleError::Chain(format!(
            "the supplied launcher coin's puzzle hash is {}, not the singleton launcher puzzle — it \
             would not mint a store singleton",
            launcher_coin.puzzle_hash
        )));
    }

    assert_minted_singleton_amount_is_odd(singleton_amount)
}

/// Fails closed unless a minted store singleton's `amount` is ODD.
///
/// Called twice on purpose. Once on the caller's declared [`Launcher::singleton_amount`], where it can
/// name the mistake before anything is built; and once on `datastore.coin.amount` — the amount the SDK
/// ACTUALLY minted — after the launch is constructed. The second call is the class-level guard: it
/// holds however the `Launcher` was configured, so a future SDK builder field that steers the minted
/// amount cannot silently reopen the frozen-store hole.
fn assert_minted_singleton_amount_is_odd(singleton_amount: u64) -> MerkleResult<()> {
    if singleton_amount % 2 == 0 {
        return Err(MerkleError::Chain(format!(
            "the store singleton's amount would be {singleton_amount}, which is even — a singleton's \
             amount must be odd, and an even-amount launch is accepted on chain but produces a store \
             that can never be updated or melted"
        )));
    }

    Ok(())
}

/// Fails closed unless the parent's `conditions` actually lead to `launcher_coin`.
///
/// The `Owner::Custom` refusal catches the one known way to lose the launcher; this catches the
/// CLASS — an `override_launcher_hint` regression, a delegated-puzzle path, a future `Owner` variant,
/// or a caller-supplied [`Launcher`] whose coin no condition ever creates.
///
/// Two shapes are legal, and each is verified end to end:
///
/// - **Direct** — the conditions create the launcher coin themselves. A puzzle-hash + amount match on
///   the already-parsed [`Conditions`] settles it (O(n), no CLVM re-run).
/// - **Via an intermediate** — the conditions create an even-amount intermediate coin whose OWN
///   staged spend creates the launcher. The intermediate is matched by puzzle hash and amount only
///   (the parent coin's id is not an input to this function, so a caller that names the wrong parent
///   when constructing the `IntermediateLauncher` is not detected here); the launcher coin is verified
///   by its full coin id via `spend_creates`.
fn assert_launch_reaches_the_launcher(
    ctx: &mut SpendContext,
    conditions: &Conditions,
    launcher_coin: Coin,
) -> MerkleResult<()> {
    if creates_coin(conditions, launcher_coin.puzzle_hash, launcher_coin.amount) {
        return Ok(());
    }

    // Not direct, so the only other legal shape is an intermediate coin — already staged into `ctx`
    // by the caller's `IntermediateLauncher::create` — sitting between the parent and the launcher.
    let intermediate = staged_spend_of(ctx, launcher_coin.parent_coin_info).ok_or_else(|| {
        MerkleError::Chain(
            "launch conditions do not create the launcher coin, and no staged spend creates it \
             either — the supplied Launcher is unreachable from this parent"
                .into(),
        )
    })?;

    if !creates_coin(
        conditions,
        intermediate.coin.puzzle_hash,
        intermediate.coin.amount,
    ) {
        return Err(MerkleError::Chain(
            "launch conditions do not create the intermediate coin the launcher descends from"
                .into(),
        ));
    }

    if !spend_creates(ctx, &intermediate, launcher_coin)? {
        return Err(MerkleError::Chain(
            "the intermediate coin's spend does not create the launcher coin".into(),
        ));
    }

    Ok(())
}

/// Whether `conditions` contain a `CREATE_COIN` for exactly this puzzle hash and amount.
fn creates_coin(conditions: &Conditions, puzzle_hash: Bytes32, amount: u64) -> bool {
    conditions.iter().any(|condition| {
        matches!(condition, Condition::CreateCoin(cc)
            if cc.puzzle_hash == puzzle_hash && cc.amount == amount)
    })
}

/// The already-staged spend of `coin_id`, if the context holds one. Reads without draining — the
/// caller drains exactly once, at the end (see [`DatastoreLaunch`]).
fn staged_spend_of(ctx: &SpendContext, coin_id: Bytes32) -> Option<MerkleCoinSpendItem> {
    ctx.iter()
        .find(|spend| spend.coin.coin_id() == coin_id)
        .cloned()
}

/// The coin-spend type the [`SpendContext`] stages, named locally so the helper signatures read.
type MerkleCoinSpendItem = crate::types::CoinSpend;

/// Runs `spend` and reports whether it creates `expected` — identity by full coin id, so a coin that
/// merely shares a puzzle hash cannot satisfy it.
fn spend_creates(
    ctx: &mut SpendContext,
    spend: &MerkleCoinSpendItem,
    expected: Coin,
) -> MerkleResult<bool> {
    let puzzle = ctx.alloc(&spend.puzzle_reveal)?;
    let solution = ctx.alloc(&spend.solution)?;
    let output = ctx.run(puzzle, solution)?;
    let conditions = Vec::<Condition>::from_clvm(&**ctx, output)
        .map_err(|error| MerkleError::Parse(format!("intermediate spend conditions: {error}")))?;

    let parent_id = spend.coin.coin_id();
    Ok(conditions.into_iter().any(|condition| {
        matches!(condition, Condition::CreateCoin(cc)
            if Coin::new(parent_id, cc.puzzle_hash, cc.amount).coin_id() == expected.coin_id())
    }))
}

/// Rewrites the launcher `CREATE_COIN` in `conditions` to carry the two owner-discovery memos.
///
/// The SDK's `mint_datastore` emits the launcher `CREATE_COIN` with a single default hint; every DIG
/// producer replaces it with `[digstore_owner_hint(owner_ph), launcher_hint_for(kind)]` so the store
/// is owner-discoverable and byte-identical on chain (SPEC §9). The second memo is the kind
/// discriminator — [`StoreKind::File`] keeps the historical `DATASTORE_LAUNCHER_HINT` bytes. Every
/// other condition passes through unchanged.
///
/// Returns the rewritten conditions and whether a launcher `CREATE_COIN` was actually found to
/// rewrite. It is absent whenever the launcher is created by an intermediate coin rather than by the
/// parent, and in that case `kind` and the owner hint reach no condition at all — the caller reports
/// that fact as [`DatastoreLaunch::launcher_memos_written`] rather than claiming a hint it never
/// wrote.
fn override_launcher_hint(
    ctx: &mut SpendContext,
    conditions: Conditions,
    owner_puzzle_hash: Bytes32,
    kind: StoreKind,
) -> MerkleResult<(Conditions, bool)> {
    let mut memos_written = false;
    let mut rewritten = Conditions::new();
    for condition in conditions {
        match condition {
            Condition::CreateCoin(create_coin)
                if create_coin.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH =>
            {
                let memos = ctx.memos(&[
                    digstore_owner_hint(owner_puzzle_hash),
                    launcher_hint_for(kind),
                ])?;
                rewritten = rewritten.with(Condition::CreateCoin(CreateCoin {
                    puzzle_hash: create_coin.puzzle_hash,
                    amount: create_coin.amount,
                    memos,
                }));
                memos_written = true;
            }
            other => rewritten = rewritten.with(other),
        }
    }
    Ok((rewritten, memos_written))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::required_signatures;
    use crate::types::DataStore;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::SpendContext;
    use chia_wallet_sdk::prelude::{NodePtr, MAINNET_CONSTANTS};
    use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
    use chia_wallet_sdk::test::Simulator;
    use clvm_traits::{FromClvm, ToClvm};

    /// A deterministic owner puzzle hash derived from a hashed seed (never an integer literal — a
    /// CodeQL-flagged pattern). Standard-layer curried so the mint's owner spend is real.
    fn seeded_owner() -> (chia_wallet_sdk::prelude::PublicKey, Bytes32) {
        let mut sim = Simulator::new();
        let owner = sim.bls(0);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        (owner.pk, owner_ph)
    }

    /// Runs a coin spend's puzzle against its solution and returns the emitted conditions.
    fn conditions_of(spend: &crate::types::CoinSpend) -> Vec<Condition> {
        let mut ctx = SpendContext::new();
        let puzzle = ctx.alloc(&spend.puzzle_reveal).expect("alloc puzzle");
        let solution = ctx.alloc(&spend.solution).expect("alloc solution");
        let output = ctx.run(puzzle, solution).expect("run puzzle");
        Vec::<Condition>::from_clvm(&*ctx, output).expect("parse conditions")
    }

    /// Extracts the memos (as `Bytes32`) from the launcher `CREATE_COIN` across a set of coin spends.
    /// Parsing happens in one allocator so the memo `NodePtr` stays valid.
    fn launcher_memos(coin_spends: &[crate::types::CoinSpend]) -> Vec<Bytes32> {
        for spend in coin_spends {
            let mut ctx = SpendContext::new();
            let puzzle = ctx.alloc(&spend.puzzle_reveal).expect("alloc puzzle");
            let solution = ctx.alloc(&spend.solution).expect("alloc solution");
            let output = ctx.run(puzzle, solution).expect("run puzzle");
            let conditions = Vec::<Condition>::from_clvm(&*ctx, output).expect("parse conditions");
            for condition in conditions {
                if let Condition::CreateCoin(cc) = condition {
                    if cc.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH {
                        let Memos::Some(ptr) = cc.memos else {
                            panic!("launcher CREATE_COIN must carry memos");
                        };
                        return Vec::<Bytes32>::from_clvm(&*ctx, ptr)
                            .expect("parse launcher memos");
                    }
                }
            }
        }
        panic!("no launcher CREATE_COIN found");
    }

    /// LOAD-BEARING golden test: the launcher `CREATE_COIN` memos are EXACTLY
    /// `[digstore_owner_hint(owner_ph), DATASTORE_LAUNCHER_HINT]` — the proof a minted store is
    /// byte-identical to the stores already on chain (SPEC §8/§9).
    #[test]
    fn launcher_carries_the_two_memo_owner_discovery_hint() {
        let (owner_pk, owner_ph) = seeded_owner();
        let parent = Coin::new(Bytes32::new([0x33; 32]), owner_ph, 1_000_000);
        let root = Bytes32::new([0xab; 32]);

        let spend = mint_datastore(
            parent,
            Owner::Standard(owner_pk),
            root,
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            1_000,
        )
        .expect("mint builds");

        let memos = launcher_memos(&spend.coin_spends);
        assert_eq!(
            memos,
            vec![
                digstore_owner_hint(owner_ph),
                launcher_hint_for(StoreKind::File)
            ],
            "launcher memos must be [owner_hint, launcher_hint] byte-for-byte"
        );
    }

    /// #1263: a `DidProfile` mint emits the DID-profile discriminator as `memo[1]` while keeping the
    /// kind-agnostic owner hint as `memo[0]` — the additive kind split on the write side.
    #[test]
    fn did_profile_mint_carries_the_profile_discriminator() {
        use crate::hint::DID_PROFILE_LAUNCHER_HINT;
        use crate::mint::mint_datastore_with_kind;

        let (owner_pk, owner_ph) = seeded_owner();
        let parent = Coin::new(Bytes32::new([0x55; 32]), owner_ph, 1_000_000);

        let spend = mint_datastore_with_kind(
            StoreKind::DidProfile,
            parent,
            Owner::Standard(owner_pk),
            Bytes32::new([0xab; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            1_000,
        )
        .expect("did-profile mint builds");

        let memos = launcher_memos(&spend.coin_spends);
        assert_eq!(
            memos,
            vec![digstore_owner_hint(owner_ph), DID_PROFILE_LAUNCHER_HINT],
            "a DidProfile mint carries the profile discriminator as memo[1]"
        );
    }

    /// Golden root-encoding pin: `DigDataStoreMetadata` CLVM has the `root_hash` as its first atom,
    /// so a reader recovers the anchored root unchanged (SPEC §8). We assert via the encoder that the
    /// car of the metadata CLVM equals `root_hash`.
    #[test]
    fn metadata_clvm_encodes_root_as_first_atom() {
        let mut ctx = SpendContext::new();
        let root = Bytes32::new([0xcd; 32]);
        let metadata = DigDataStoreMetadata {
            root_hash: root,
            label: Some("site".into()),
            description: Some("desc".into()),
            size_proof: None,
            program_hash: None,
            size_bucket: None,
        };
        let node = metadata.to_clvm(&mut *ctx).expect("encode metadata");
        let (car, _rest) = <(Bytes32, NodePtr)>::from_clvm(&*ctx, node)
            .expect("metadata is a pair with a Bytes32 car");
        assert_eq!(car, root, "root_hash must be the first metadata atom");
    }

    /// The mint validates on the in-process simulator and the eve DataStore hydrates back with the
    /// same root, owner, and delegated-puzzle set (SPEC §5 roundtrip).
    #[test]
    fn mint_validates_and_hydrates_on_simulator() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let root = Bytes32::new([0x5a; 32]);

        let built = mint_datastore(
            owner.coin,
            Owner::Standard(owner.pk),
            root,
            Some("site".into()),
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            0,
        )?;
        let datastore = built.child.clone().expect("mint yields a child datastore");

        // The simulator validates the spend against TESTNET11, so sign for testnet.
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;

        // Hydrate the eve store from the launcher-coin spend and confirm it round-trips.
        let mut ctx = SpendContext::new();
        let launcher_spend = built
            .coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == datastore.info.launcher_id)
            .expect("launcher-coin spend present");
        let hydrated =
            DataStore::<DigDataStoreMetadata>::from_spend(&mut ctx, launcher_spend, &[])?
                .expect("launcher spend hydrates a datastore");

        assert_eq!(hydrated.info.metadata.root_hash, root);
        assert_eq!(hydrated.info.owner_puzzle_hash, owner_ph);
        assert_eq!(hydrated.info.launcher_id, datastore.info.launcher_id);
        assert!(hydrated.info.delegated_puzzles.is_empty());
        Ok(())
    }

    /// The unsigned mint requires exactly one `AGG_SIG_ME` over the owner's key — never an
    /// `AGG_SIG_UNSAFE`. This is the custody contract: the caller signs precisely this.
    #[test]
    fn mint_requires_a_single_agg_sig_me_for_the_owner() {
        let (owner_pk, owner_ph) = seeded_owner();
        let parent = Coin::new(Bytes32::new([0x77; 32]), owner_ph, 500_000);

        let built = mint_datastore(
            parent,
            Owner::Standard(owner_pk),
            Bytes32::new([0x01; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            1_000,
        )
        .expect("mint builds");

        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required =
            required_signatures(&built.coin_spends, &constants).expect("signatures compute");
        assert_eq!(required.len(), 1, "one AGG_SIG_ME expected");
        match &required[0] {
            RequiredSignature::Bls(bls) => assert_eq!(bls.public_key, owner_pk),
            RequiredSignature::Secp(_) => panic!("standard owner uses a BLS key"),
        }
    }

    /// Edge case: a parent coin worth exactly `fee + 1` leaves no change — the builder still produces
    /// a valid single-coin-spend mint, never panicking on the no-change path.
    #[test]
    fn mint_without_change_omits_the_change_coin() {
        let (owner_pk, owner_ph) = seeded_owner();
        let parent = Coin::new(Bytes32::new([0x99; 32]), owner_ph, 1); // == fee(0) + 1

        let built = mint_datastore(
            parent,
            Owner::Standard(owner_pk),
            Bytes32::new([0x02; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            0,
        )
        .expect("mint builds with no change");

        // The parent/owner spend creates only the launcher coin — no change CREATE_COIN.
        let parent_spend = built
            .coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == parent.coin_id())
            .expect("parent spend present");
        let create_coins: Vec<_> = conditions_of(parent_spend)
            .into_iter()
            .filter(|c| matches!(c, Condition::CreateCoin(_)))
            .collect();
        assert_eq!(
            create_coins.len(),
            1,
            "only the launcher CREATE_COIN, no change"
        );
    }

    /// Builds the same coin spends `mint_datastore` does but currying the SDK's `DataStoreMetadata`
    /// (with `bytes == None`, since dig-merkle never emits `"b"`), so a byte-identity comparison
    /// isolates JUST the metadata type swap.
    #[allow(clippy::too_many_arguments)]
    fn reference_sdk_mint(
        parent_coin: Coin,
        owner_pk: chia_wallet_sdk::prelude::PublicKey,
        root: Bytes32,
        label: Option<String>,
        description: Option<String>,
        size_proof: Option<String>,
        owner_puzzle_hash: Bytes32,
        fee: u64,
    ) -> Vec<crate::types::CoinSpend> {
        use chia_wallet_sdk::driver::DataStoreMetadata;

        let mut ctx = SpendContext::new();
        let (launch_conditions, _datastore) = Launcher::new(parent_coin.coin_id(), 1)
            .mint_datastore(
                &mut ctx,
                DataStoreMetadata {
                    root_hash: root,
                    label,
                    description,
                    bytes: None,
                    size_proof,
                },
                owner_puzzle_hash.into(),
                vec![],
            )
            .expect("reference mint builds");
        let (launch_conditions, memos_written) = override_launcher_hint(
            &mut ctx,
            launch_conditions,
            owner_puzzle_hash,
            StoreKind::File,
        )
        .expect("reference hint override");
        assert!(
            memos_written,
            "the reference bundle launches directly, so the memos must have been written"
        );

        let reserved = fee + 1;
        let owner_conditions = if parent_coin.amount > reserved {
            let change_hint = ctx.hint(owner_puzzle_hash).expect("hint");
            launch_conditions.create_coin(
                owner_puzzle_hash,
                parent_coin.amount - reserved,
                change_hint,
            )
        } else {
            launch_conditions
        };
        let owner_spend =
            crate::context::inner_spend(&mut ctx, Owner::Standard(owner_pk), owner_conditions)
                .expect("reference owner spend");
        ctx.spend(parent_coin, owner_spend)
            .expect("reference parent spend");
        crate::context::drain_coin_spends(&mut ctx)
    }

    /// LOAD-BEARING back-compat proof (§5.1): a mint with `program_hash == None` produces coin spends
    /// BYTE-IDENTICAL to a mint currying the SDK's own `DataStoreMetadata` — so an ordinary DIG store
    /// is indistinguishable on chain from a plain DataLayer store.
    #[test]
    fn mint_none_program_hash_is_byte_identical() {
        let (owner_pk, owner_ph) = seeded_owner();
        let parent = Coin::new(Bytes32::new([0x44; 32]), owner_ph, 1_000_000);
        let root = Bytes32::new([0xba; 32]);

        let dig = mint_datastore(
            parent,
            Owner::Standard(owner_pk),
            root,
            Some("store".into()),
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            1_000,
        )
        .expect("dig mint builds");

        let reference = reference_sdk_mint(
            parent,
            owner_pk,
            root,
            Some("store".into()),
            None,
            None,
            owner_ph,
            1_000,
        );

        assert_eq!(
            dig.coin_spends, reference,
            "a None-extras mint must be byte-identical to an SDK-metadata mint"
        );
    }

    /// A mint carrying a `program_hash` validates on the simulator and hydrates back with BOTH the
    /// anchored root and the program hash preserved (SPEC §2/§5 roundtrip).
    #[test]
    fn mint_with_program_hash_hydrates() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let root = Bytes32::new([0x5b; 32]);
        let program_hash = Bytes32::new([0xcc; 32]);

        let built = mint_datastore(
            owner.coin,
            Owner::Standard(owner.pk),
            root,
            None,
            None,
            None,
            Some(program_hash),
            None,
            owner_ph,
            vec![],
            0,
        )?;
        let datastore = built.child.clone().expect("mint yields a child datastore");

        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;

        let mut ctx = SpendContext::new();
        let launcher_spend = built
            .coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == datastore.info.launcher_id)
            .expect("launcher-coin spend present");
        let hydrated =
            DataStore::<DigDataStoreMetadata>::from_spend(&mut ctx, launcher_spend, &[])?
                .expect("launcher spend hydrates a datastore");

        assert_eq!(hydrated.info.metadata.root_hash, root);
        assert_eq!(
            hydrated.info.metadata.program_hash,
            Some(program_hash),
            "the program_hash survives the on-chain roundtrip"
        );
        Ok(())
    }

    /// A mint carrying a `size_bucket` validates on the simulator and hydrates back with BOTH the
    /// anchored root and the size bucket preserved (SPEC §2/§5 roundtrip).
    #[test]
    fn mint_with_size_bucket_hydrates() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let root = Bytes32::new([0x5c; 32]);
        let size_bucket = SizeBucket::from_exponent(6).expect("valid bucket");

        let built = mint_datastore(
            owner.coin,
            Owner::Standard(owner.pk),
            root,
            None,
            None,
            None,
            None,
            Some(size_bucket),
            owner_ph,
            vec![],
            0,
        )?;
        let datastore = built.child.clone().expect("mint yields a child datastore");

        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;

        let mut ctx = SpendContext::new();
        let launcher_spend = built
            .coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == datastore.info.launcher_id)
            .expect("launcher-coin spend present");
        let hydrated =
            DataStore::<DigDataStoreMetadata>::from_spend(&mut ctx, launcher_spend, &[])?
                .expect("launcher spend hydrates a datastore");

        assert_eq!(hydrated.info.metadata.root_hash, root);
        assert_eq!(
            hydrated.info.metadata.size_bucket,
            Some(size_bucket),
            "the size bucket survives the on-chain roundtrip"
        );
        Ok(())
    }

    // Arms `drop_launcher_if_armed` for the duration of one test, so the class-level launcher guard
    // can be OBSERVED failing (an assertion never seen to fail is decoration). THREAD-local, never a
    // global: the harness runs tests in parallel, and a global flag would arm the seam under
    // unrelated tests.
    thread_local! {
        static DROP_LAUNCHER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Test-only seam: when armed, strips the launcher `CREATE_COIN` from the built launch
    /// conditions, simulating a future regression in [`override_launcher_hint`] or a new code path
    /// that loses it. Compiled out entirely in release builds.
    pub(super) fn drop_launcher_if_armed(conditions: Conditions) -> Conditions {
        if !DROP_LAUNCHER.with(std::cell::Cell::get) {
            return conditions;
        }
        let mut kept = Conditions::new();
        for condition in conditions {
            let is_launcher = matches!(
                &condition,
                Condition::CreateCoin(cc) if cc.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH
            );
            if !is_launcher {
                kept = kept.with(condition);
            }
        }
        kept
    }

    /// REGRESSION (#2418): `mint_datastore_with_kind` used to DROP the launch conditions for an
    /// [`Owner::Custom`] mint (`context::inner_spend` ignores `conditions` for that variant), so it
    /// returned `Ok` with a bundle that never creates the launcher coin — reported as success after
    /// the caller had already paid for the DID it was rooting from. The caller cannot supply those
    /// conditions: they are produced inside this very call. It must refuse.
    ///
    /// The stand-in for a DID-authorized spend is a caller-built inner spend with EMPTY conditions —
    /// exactly what a caller who cannot see the launch conditions constructs. (`dig-merkle` cannot
    /// depend on `dig-did`: both are `10-primitives`, and a same-level edge is forbidden.)
    #[test]
    fn a_custom_owner_mint_does_not_silently_omit_the_launcher() {
        use chia_wallet_sdk::driver::{SpendWithConditions, StandardLayer};

        let mut ctx = SpendContext::new();
        let (owner_pk, owner_ph) = seeded_owner();
        let prebuilt = StandardLayer::new(owner_pk)
            .spend_with_conditions(&mut ctx, Conditions::new())
            .expect("a caller-built inner spend");
        let parent = Coin::new(Bytes32::new([0x21; 32]), owner_ph, 1_000_000);

        let result = mint_datastore_with_kind(
            StoreKind::File,
            parent,
            Owner::Custom(prebuilt),
            Bytes32::new([0xab; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            1_000,
        );

        assert!(
            matches!(result, Err(MerkleError::UnsupportedOwner(_))),
            "a custom-owner mint must refuse, not return an unlaunchable bundle"
        );
    }

    /// The class-level guard is FALSIFIABLE: with the test seam armed to drop the launcher
    /// `CREATE_COIN`, the builder fails closed instead of handing back an unlaunchable launch.
    #[test]
    fn a_launch_without_the_launcher_coin_fails_closed() {
        let (_owner_pk, owner_ph) = seeded_owner();
        let mut ctx = SpendContext::new();

        DROP_LAUNCHER.with(|armed| armed.set(true));
        let result = mint_datastore_launch_with_kind(
            &mut ctx,
            StoreKind::File,
            Launcher::new(Bytes32::new([0x21; 32]), 1),
            Bytes32::new([0xab; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
        );
        DROP_LAUNCHER.with(|armed| armed.set(false));

        match result {
            Err(MerkleError::Chain(message)) => assert!(
                message.contains("do not create the launcher coin")
                    && message.contains("no staged spend creates it"),
                "the guard must name what it caught, got: {message}"
            ),
            other => panic!("expected a fail-closed Chain error, got {other:?}"),
        }
    }

    /// The unarmed control: the very same call succeeds and DOES carry the launcher, so the test
    /// above observed the guard rather than an unrelated failure.
    #[test]
    fn an_ordinary_launch_carries_the_launcher_coin() {
        let (_owner_pk, owner_ph) = seeded_owner();
        let mut ctx = SpendContext::new();

        let launch = mint_datastore_launch_with_kind(
            &mut ctx,
            StoreKind::File,
            Launcher::new(Bytes32::new([0x21; 32]), 1),
            Bytes32::new([0xab; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
        )
        .expect("an ordinary launch builds");

        assert!(
            launch.parent_conditions.iter().any(|condition| {
                matches!(condition, Condition::CreateCoin(cc) if cc.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH)
            }),
            "the launch conditions create the launcher coin"
        );
    }

    /// The composable path is the SAME path: a caller-composed launch plus an ordinary standard-p2
    /// parent spend produces coin spends BYTE-IDENTICAL to [`mint_datastore_with_kind`]. This is what
    /// makes "one code path" checkable rather than merely claimed.
    #[test]
    fn the_composed_launch_is_byte_identical_to_the_wrapper() {
        let (owner_pk, owner_ph) = seeded_owner();
        let parent = Coin::new(Bytes32::new([0x66; 32]), owner_ph, 1_000_000);
        let root = Bytes32::new([0xab; 32]);
        let fee = 1_000_u64;

        let wrapper = mint_datastore_with_kind(
            StoreKind::File,
            parent,
            Owner::Standard(owner_pk),
            root,
            Some("store".into()),
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            fee,
        )
        .expect("wrapper mint builds");

        // The caller's own composition: one context, launch staged into it, parent spend added, one
        // drain at the end.
        let mut ctx = SpendContext::new();
        let launch = mint_datastore_launch_with_kind(
            &mut ctx,
            StoreKind::File,
            Launcher::new(parent.coin_id(), 1),
            root,
            Some("store".into()),
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
        )
        .expect("composed launch builds");
        let change_hint = ctx.hint(owner_ph).expect("change hint");
        let owner_conditions =
            launch
                .parent_conditions
                .create_coin(owner_ph, parent.amount - (fee + 1), change_hint);
        let owner_spend = inner_spend(&mut ctx, Owner::Standard(owner_pk), owner_conditions)
            .expect("owner spend");
        ctx.spend(parent, owner_spend).expect("parent spend");
        let composed = drain_coin_spends(&mut ctx);

        assert_eq!(
            wrapper.coin_spends, composed,
            "the wrapper is the composed launch plus a standard parent spend, byte for byte"
        );
        assert_eq!(
            wrapper.child.expect("wrapper yields a datastore").info,
            launch.datastore.info,
            "both paths describe the same eve DataStore"
        );
    }

    /// Launches a store from `parent_singleton_coin_id` and returns the built coin spends, using
    /// `launcher_for` to choose the launcher shape. The parent singleton is spent by `spend_parent`,
    /// which folds the launch's `parent_conditions` into the singleton's own recreation.
    ///
    /// Both singleton-parent tests below differ ONLY in the launcher they build, so sharing the rest
    /// makes the negative control a genuine control: nothing else varies.
    fn launch_from_singleton(
        ctx: &mut SpendContext,
        launcher: Launcher,
        owner_ph: Bytes32,
        spend_parent: impl FnOnce(&mut SpendContext, Conditions) -> anyhow::Result<()>,
    ) -> anyhow::Result<DatastoreLaunch> {
        let launch = mint_datastore_launch_with_kind(
            ctx,
            StoreKind::DidProfile,
            launcher,
            Bytes32::new([0x6d; 32]),
            Some("profile".into()),
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
        )?;
        spend_parent(ctx, launch.parent_conditions.clone())?;
        Ok(launch)
    }

    /// LOAD-BEARING (#2418): a store launched from a SINGLETON parent through an intermediate
    /// launcher is ACCEPTED on chain, and the eve store hydrates from the launcher spend.
    ///
    /// This is the composition the composable launch API exists for. The parent here is a DID
    /// singleton (built with the SDK — dig-merkle holds no `dig-did` dependency); the DID's spend
    /// emits its own recreation PLUS the launch's conditions, which create the even-amount
    /// intermediate coin rather than the launcher itself.
    #[test]
    fn a_singleton_parent_launch_via_an_intermediate_validates_on_chain() -> anyhow::Result<()> {
        use chia_wallet_sdk::driver::{IntermediateLauncher, StandardLayer};

        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1_000_000);
        let alice_p2 = StandardLayer::new(alice.pk);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(alice.pk).into();

        let (create_did, did) =
            Launcher::new(alice.coin.coin_id(), 1).create_simple_did(ctx, &alice_p2)?;
        alice_p2.spend(ctx, alice.coin, create_did)?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))?;

        let did_coin_id = did.coin.coin_id();
        let intermediate = IntermediateLauncher::new(did_coin_id, 0, 1);
        let intermediate_coin = intermediate.intermediate_coin();
        let launcher = intermediate.create(ctx)?;
        let launch = launch_from_singleton(ctx, launcher, owner_ph, |ctx, conditions| {
            let _child = did.update(ctx, &alice_p2, conditions)?;
            Ok(())
        })?;

        // The launcher is 1 mojo minted by a ZERO-amount intermediate, so the bundle needs a mojo
        // from somewhere: a funding coin spent to nothing supplies it (Chia balances a bundle in
        // aggregate, not per coin).
        let funder = sim.bls(1);
        StandardLayer::new(funder.pk).spend(ctx, funder.coin, Conditions::new())?;

        let coin_spends = ctx.take();
        sim.spend_coins(coin_spends.clone(), &[alice.sk.clone(), funder.sk.clone()])?;

        // The launcher coin really was created and spent, and the eve store hydrates from it.
        let store_id = launch.datastore.info.launcher_id;
        let launcher_spend = coin_spends
            .iter()
            .find(|spend| spend.coin.coin_id() == store_id)
            .expect("the launcher coin was spent");
        let hydrated = DataStore::<DigDataStoreMetadata>::from_spend(
            &mut SpendContext::new(),
            launcher_spend,
            &[],
        )?
        .expect("launcher spend hydrates a datastore");

        assert_eq!(hydrated.info.metadata.root_hash, Bytes32::new([0x6d; 32]));
        assert_eq!(hydrated.info.launcher_id, store_id);
        assert_eq!(
            launcher_spend.coin.parent_coin_info,
            intermediate_coin.coin_id(),
            "the launcher's parent is the intermediate coin, not the singleton itself"
        );
        assert_eq!(
            intermediate_coin.amount, 0,
            "the coin the singleton emits is EVEN — the reason this composition is legal"
        );
        assert_ne!(
            launcher_spend.coin.parent_coin_info, did_coin_id,
            "the intermediate coin sits between the singleton and the launcher"
        );
        Ok(())
    }

    /// Builds a launch with a caller-supplied launcher, for the legality tests below. Every argument
    /// except the launcher is the same as the accepted reference launch, so the launcher coin is the
    /// only variable.
    fn launch_with(ctx: &mut SpendContext, launcher: Launcher) -> MerkleResult<DatastoreLaunch> {
        let (_owner_pk, owner_ph) = seeded_owner();
        mint_datastore_launch_with_kind(
            ctx,
            StoreKind::File,
            launcher,
            Bytes32::new([0x6d; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
        )
    }

    /// LOAD-BEARING: an EVEN-amount launcher is refused at build time.
    ///
    /// Measured on the simulator: such a bundle is ACCEPTED on chain, and the resulting store is
    /// permanently frozen — the singleton odd-amount rule makes every later `update_root` raise, so
    /// it can never be updated or melted and its mojos are burned. Nothing downstream reports this,
    /// so build time is the only place it is still reversible.
    ///
    /// The reachability guard cannot catch it: the launch conditions are built FROM the launcher's
    /// own amount, so "the conditions create this coin" holds for any amount whatsoever.
    #[test]
    fn an_even_amount_launcher_is_refused() {
        let parent_id = Bytes32::new([0x71; 32]);
        for amount in [0, 2] {
            let result = launch_with(&mut SpendContext::new(), Launcher::new(parent_id, amount));
            assert!(
                matches!(result, Err(MerkleError::Chain(ref message)) if message.contains("even")),
                "an amount-{amount} launcher must be refused as an even singleton amount, got: \
                 {result:?}"
            );
        }
    }

    /// LOAD-BEARING: the frozen-store guard reads the SINGLETON's amount, not the launcher coin's.
    ///
    /// [`Launcher::singleton_amount`] is its own SDK field: it merely DEFAULTS to the launcher coin's
    /// amount and [`Launcher::with_singleton_amount`] overrides it, while the minted singleton's
    /// amount is always `singleton_amount`. A guard reading `launcher.coin().amount` therefore checks
    /// a value that does not decide anything — and this is the bundle it lets through: a legal-looking
    /// 1-mojo launcher minting an EVEN-amount singleton, which is accepted on chain and permanently
    /// frozen.
    #[test]
    fn an_even_singleton_amount_is_refused_even_from_an_odd_launcher() {
        let parent_id = Bytes32::new([0x71; 32]);
        let launcher = Launcher::new(parent_id, 1).with_singleton_amount(2);
        assert_eq!(
            launcher.coin().amount,
            1,
            "the launcher coin itself looks legal"
        );

        let result = launch_with(&mut SpendContext::new(), launcher);

        assert!(
            matches!(result, Err(MerkleError::Chain(ref message)) if message.contains("singleton")),
            "an even SINGLETON amount must be refused however legal the launcher coin looks, got: \
             {result:?}"
        );
    }

    /// LOAD-BEARING, the other direction: the SDK's own documented composition — a ZERO-amount
    /// launcher minting a 1-mojo singleton — is ACCEPTED.
    ///
    /// The launcher coin's amount is not the invariant; 0 is legal for it. A guard that refused this
    /// would reject the legal composition while admitting the illegal one above — the exact signature
    /// of reading the wrong field.
    #[test]
    fn a_zero_amount_launcher_minting_an_odd_singleton_is_accepted() {
        let parent_id = Bytes32::new([0x71; 32]);
        let launcher = Launcher::new(parent_id, 0).with_singleton_amount(1);

        let result = launch_with(&mut SpendContext::new(), launcher);

        assert!(
            result.is_ok(),
            "a 0-amount launcher minting a 1-mojo singleton is the SDK's documented composition and \
             must be accepted, got: {result:?}"
        );
    }

    /// The MEASUREMENT the even-amount guard rests on: an even-amount launch is ACCEPTED on chain,
    /// and the store it produces is permanently frozen.
    ///
    /// The bundle is built straight from the SDK — deliberately NOT through
    /// [`mint_datastore_launch_with_kind`], whose guard exists precisely to refuse it — so this
    /// measures the CHAIN's behaviour rather than this crate's. Two halves, both required:
    ///
    /// - the launch bundle is accepted by the simulator (nothing rejects it at mint time), and
    /// - the very next `update_root` on the resulting store is REJECTED, because the singleton puzzle
    ///   requires an odd amount — so the store can never be updated or melted and its mojos are burned.
    ///
    /// Without the second half the first would only show that a bad mint is quiet; without the first,
    /// the guard could be justified by a failure the chain already catches.
    #[test]
    fn an_even_amount_launch_is_accepted_on_chain_and_freezes_the_store() -> anyhow::Result<()> {
        use chia_wallet_sdk::driver::StandardLayer;

        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();

        // An EVEN-amount launcher — the transposition `Launcher::new(parent, 0)` /
        // `IntermediateLauncher::new(parent, 0, 1)` produces, here at 2 mojos so the bundle balances.
        let (launch_conditions, datastore) = Launcher::new(owner.coin.coin_id(), 2)
            .mint_datastore(
                ctx,
                DigDataStoreMetadata {
                    root_hash: Bytes32::new([0x5a; 32]),
                    ..Default::default()
                },
                owner_ph.into(),
                vec![],
            )?;
        StandardLayer::new(owner.pk).spend(ctx, owner.coin, launch_conditions)?;

        sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))
            .expect("an even-amount launch is ACCEPTED on chain — nothing refuses it at mint time");

        // …and the store is frozen: its first update raises inside the singleton puzzle.
        let update = crate::update_root(
            &datastore,
            Owner::Standard(owner.pk),
            DigDataStoreMetadata {
                root_hash: Bytes32::new([0x77; 32]),
                ..Default::default()
            },
        )?;
        let result = sim.spend_coins(update.coin_spends, std::slice::from_ref(&owner.sk));
        assert!(
            result.is_err(),
            "an even-amount store must be unspendable — every later update raises on the singleton \
             odd-amount rule, so the store is permanently frozen, but got: {result:?}"
        );
        Ok(())
    }

    /// LOAD-BEARING: the ODD amount the caller is told to use is accepted, so the guard above refuses
    /// the illegal amounts rather than the whole argument.
    #[test]
    fn an_odd_amount_launcher_is_accepted() {
        let parent_id = Bytes32::new([0x71; 32]);
        assert!(launch_with(&mut SpendContext::new(), Launcher::new(parent_id, 1)).is_ok());
        assert!(launch_with(&mut SpendContext::new(), Launcher::new(parent_id, 3)).is_ok());
    }

    /// LOAD-BEARING: a launcher coin at any puzzle hash other than the singleton launcher is refused.
    ///
    /// It could never mint a singleton, and [`override_launcher_hint`] matches on that same puzzle
    /// hash — so without this guard the launch would also silently omit the owner-discovery memos
    /// while still reporting success.
    #[test]
    fn a_launcher_coin_at_a_foreign_puzzle_hash_is_refused() {
        let parent_id = Bytes32::new([0x71; 32]);
        let foreign = Coin::new(parent_id, Bytes32::new([0x42; 32]), 1);
        let result = launch_with(
            &mut SpendContext::new(),
            Launcher::from_coin(foreign, Conditions::new()),
        );
        assert!(
            matches!(result, Err(MerkleError::Chain(ref message)) if message.contains("puzzle hash")),
            "a launcher at a foreign puzzle hash must be refused, got: {result:?}"
        );
    }

    /// The memos on the launcher `CREATE_COIN` across `coin_spends`, or `None` when that condition
    /// carries none. Unlike [`launcher_memos`] this does not require memos to be present — it exists
    /// precisely to pin the shape where they are absent.
    fn launcher_memos_if_any(coin_spends: &[crate::types::CoinSpend]) -> Option<Vec<Bytes32>> {
        for spend in coin_spends {
            let mut ctx = SpendContext::new();
            let puzzle = ctx.alloc(&spend.puzzle_reveal).expect("alloc puzzle");
            let solution = ctx.alloc(&spend.solution).expect("alloc solution");
            let output = ctx.run(puzzle, solution).expect("run puzzle");
            let conditions = Vec::<Condition>::from_clvm(&*ctx, output).expect("parse conditions");
            for condition in conditions {
                if let Condition::CreateCoin(cc) = condition {
                    if cc.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH {
                        return match cc.memos {
                            Memos::Some(ptr) => Some(
                                Vec::<Bytes32>::from_clvm(&*ctx, ptr)
                                    .expect("parse launcher memos"),
                            ),
                            Memos::None => None,
                        };
                    }
                }
            }
        }
        panic!("no launcher CREATE_COIN found");
    }

    /// LOAD-BEARING (#2418): the intermediate shape CANNOT carry the launcher memos, so `kind` is
    /// accepted-but-unhonoured there — and the return value says so.
    ///
    /// The launcher `CREATE_COIN` on that path is emitted by the intermediate coin's own fixed
    /// `NftIntermediateLauncherArgs` puzzle, which this crate does not author, so
    /// [`override_launcher_hint`] finds nothing to rewrite. This asserts the limitation rather than
    /// describing it in prose, and pairs it with the DIRECT shape as a truthful control: the ONLY
    /// thing that varies between the two halves is the launcher shape, so a rewrite that silently
    /// stopped firing on the direct path would fail here too.
    ///
    /// It is also why a profile store — which MUST be memo-scannable — launches from an ordinary
    /// even-amount coin created by the DID, never through an intermediate.
    #[test]
    fn the_intermediate_shape_writes_no_launcher_memos_and_reports_it() -> anyhow::Result<()> {
        use chia_wallet_sdk::driver::IntermediateLauncher;

        let (_owner_pk, owner_ph) = seeded_owner();
        let parent_id = Bytes32::new([0x71; 32]);

        // Intermediate shape: the parent's conditions create the even-amount intermediate, which in
        // its own staged spend creates the launcher.
        let ctx = &mut SpendContext::new();
        let launcher = IntermediateLauncher::new(parent_id, 0, 1).create(ctx)?;
        let intermediate_launch = mint_datastore_launch_with_kind(
            ctx,
            StoreKind::DidProfile,
            launcher,
            Bytes32::new([0x6d; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
        )?;
        assert!(
            !intermediate_launch.launcher_memos_written,
            "the intermediate path cannot write the launcher memos, and must not claim it did"
        );
        assert_eq!(
            launcher_memos_if_any(&ctx.take()),
            None,
            "the launcher CREATE_COIN emitted by the fixed intermediate puzzle carries no memos, so \
             neither the owner hint nor the StoreKind discriminator reaches the chain"
        );

        // Control — the SAME call, varying only the launcher shape, does write both memos.
        let ctx = &mut SpendContext::new();
        let direct_launch = mint_datastore_launch_with_kind(
            ctx,
            StoreKind::DidProfile,
            Launcher::new(parent_id, 1),
            Bytes32::new([0x6d; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
        )?;
        assert!(
            direct_launch.launcher_memos_written,
            "the direct shape emits the launcher CREATE_COIN itself, so the rewrite must fire"
        );
        // The direct launcher CREATE_COIN is a PARENT condition rather than a staged spend, so read
        // it there — and confirm it really carries the two-memo hint, not merely some memos.
        let memos = direct_launch
            .parent_conditions
            .iter()
            .find_map(|condition| match condition {
                Condition::CreateCoin(cc) if cc.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH => {
                    Some(cc.memos)
                }
                _ => None,
            })
            .expect("the direct shape emits the launcher CREATE_COIN itself");
        let Memos::Some(ptr) = memos else {
            panic!("the direct shape must carry the owner-discovery memos");
        };
        assert_eq!(
            Vec::<Bytes32>::from_clvm(&**ctx, ptr).expect("parse launcher memos"),
            vec![
                digstore_owner_hint(owner_ph),
                launcher_hint_for(StoreKind::DidProfile)
            ],
            "the direct shape writes BOTH the owner hint and the StoreKind discriminator"
        );
        Ok(())
    }

    /// The NEGATIVE CONTROL for the test above, and the reason the intermediate is not ceremony:
    /// the SAME launch with the launcher parented DIRECTLY to the singleton is REJECTED by the
    /// simulator. A Chia singleton's inner puzzle may emit exactly ONE odd-amount `CREATE_COIN` — its
    /// own successor — so the 1-mojo launcher is a second odd output and the bundle raises.
    ///
    /// The test is a DIFFERENCE of exactly one variable, asserted from both sides: the direct shape
    /// must raise, and the otherwise-identical intermediate shape must be accepted. Both halves are
    /// needed. A bare `is_err()` on the negative half alone also passes on the LEGAL intermediate
    /// shape, reporting "something went wrong" rather than "the chain rejects this shape"; and the
    /// negative half is structurally blind to the funder and the signing keys, because the raise
    /// precedes both checks — only the positive half exercises those.
    #[test]
    fn a_launcher_parented_directly_to_a_singleton_is_rejected_on_chain() -> anyhow::Result<()> {
        use chia_wallet_sdk::clvmr::error::EvalErr;
        use chia_wallet_sdk::driver::{IntermediateLauncher, StandardLayer};
        use chia_wallet_sdk::signer::SignerError;
        use chia_wallet_sdk::test::SimulatorError;

        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1_000_000);
        let alice_p2 = StandardLayer::new(alice.pk);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(alice.pk).into();

        let (create_did, did) =
            Launcher::new(alice.coin.coin_id(), 1).create_simple_did(ctx, &alice_p2)?;
        alice_p2.spend(ctx, alice.coin, create_did)?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))?;

        let did_coin_id = did.coin.coin_id();
        let launcher = Launcher::new(did_coin_id, 1);
        let _launch = launch_from_singleton(ctx, launcher, owner_ph, |ctx, conditions| {
            let _child = did.update(ctx, &alice_p2, conditions)?;
            Ok(())
        })?;

        let funder = sim.bls(1);
        StandardLayer::new(funder.pk).spend(ctx, funder.coin, Conditions::new())?;

        let result = sim.spend_coins(ctx.take(), &[alice.sk.clone(), funder.sk.clone()]);

        // Pin the SPECIFIC failure, never a bare `is_err()`. A generic error assertion also passes on
        // the LEGAL intermediate shape, so it would prove "something went wrong" rather than "the
        // chain rejects THIS shape".
        //
        // The singleton's inner puzzle enforces the one-odd-`CREATE_COIN` rule with a CLVM `(x)`, so
        // the intended rejection surfaces as a raise from the puzzle itself. That is the narrowest
        // pin available: the simulator reports the raise, not which of the puzzle's assertions
        // raised.
        //
        // Note what this half CANNOT see. The raise happens during puzzle evaluation, which precedes
        // both signature verification and the bundle-balance check, so removing the funder spend or
        // a signing key leaves the returned error byte-identical — no assertion on `result`, however
        // narrow, could distinguish them. The positive control below is what makes those inputs
        // load-bearing.
        assert!(
            matches!(
                result,
                Err(SimulatorError::Signer(SignerError::Eval(EvalErr::Raise(_))))
            ),
            "a 1-mojo launcher emitted directly by a singleton is a second odd CREATE_COIN and must \
             be rejected by a CLVM raise from the singleton puzzle, but got: {result:?}"
        );

        // POSITIVE CONTROL, same fixture, ONE variable changed: the identical launch through an
        // even-amount intermediate is ACCEPTED. This is what makes the comparison a difference of
        // launcher shape rather than a difference of "anything at all went wrong" — and, because the
        // accepted bundle genuinely needs the funder mojo and both signatures, it is also what makes
        // those two inputs load-bearing on a test whose negative half is blind to them.
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1_000_000);
        let alice_p2 = StandardLayer::new(alice.pk);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(alice.pk).into();

        let (create_did, did) =
            Launcher::new(alice.coin.coin_id(), 1).create_simple_did(ctx, &alice_p2)?;
        alice_p2.spend(ctx, alice.coin, create_did)?;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))?;

        let launcher = IntermediateLauncher::new(did.coin.coin_id(), 0, 1).create(ctx)?;
        let _launch = launch_from_singleton(ctx, launcher, owner_ph, |ctx, conditions| {
            let _child = did.update(ctx, &alice_p2, conditions)?;
            Ok(())
        })?;
        let funder = sim.bls(1);
        StandardLayer::new(funder.pk).spend(ctx, funder.coin, Conditions::new())?;

        sim.spend_coins(ctx.take(), &[alice.sk.clone(), funder.sk.clone()])
            .expect("the intermediate shape is the legal one and must be accepted");
        Ok(())
    }

    /// Regression (#1227): a `fee == u64::MAX` must fail closed with [`MerkleError::Chain`] rather
    /// than wrap around (which the old `fee + 1` would, silently returning surplus as change).
    #[test]
    fn mint_fee_overflow_fails_closed() {
        let (owner_pk, owner_ph) = seeded_owner();
        let parent = Coin::new(Bytes32::new([0xfe; 32]), owner_ph, 1_000_000);

        let result = mint_datastore(
            parent,
            Owner::Standard(owner_pk),
            Bytes32::new([0x03; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            u64::MAX,
        );

        assert!(
            matches!(result, Err(MerkleError::Chain(_))),
            "fee == u64::MAX must error, not panic or wrap"
        );
    }
}
