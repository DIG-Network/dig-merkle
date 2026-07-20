//! The DataLayer-coin mint builder (SPEC §3.1) — launch a new store singleton anchoring a root.
//!
//! [`mint_datastore`] builds the unsigned coin spends that launch a fresh CHIP-0035 DataLayer
//! singleton whose `launcher_id` becomes the DIG `store_id`. It funds the launcher from a caller-
//! supplied `parent_coin`, curries the store's [`DigDataStoreMetadata`] (the anchored merkle
//! `root_hash` plus optional label/description/bytes/size-proof/program-hash) and delegated-puzzle
//! set, and — the
//! load-bearing detail — overrides the launcher `CREATE_COIN` memos to the two-memo owner-discovery
//! hint so a minted store is byte-identical to the stores chip35_dl_coin and digstore-chain already
//! publish on-chain (SPEC §9).
//!
//! The builder is pure, key-free, and unsigned (INV-1..4): the parent/owner spend it produces
//! requires an `AGG_SIG_ME` over the owner's synthetic key, which the caller obtains via
//! [`crate::required_signatures`] and fulfils with its own signer.

use chia_wallet_sdk::driver::{Launcher, SpendContext};
use chia_wallet_sdk::types::conditions::CreateCoin;
use chia_wallet_sdk::types::{Condition, Conditions};
use hex_literal::hex;

use crate::context::{drain_coin_spends, inner_spend};
use crate::hint::{digstore_owner_hint, DATASTORE_LAUNCHER_HINT};
use crate::metadata::DigDataStoreMetadata;
use crate::size::SizeBucket;
use crate::types::{Bytes32, Coin, DelegatedPuzzle, MerkleCoinSpend, Owner};
use crate::{MerkleError, MerkleResult};

/// The well-known singleton launcher puzzle hash. A `CREATE_COIN` to this puzzle hash mints the
/// store's launcher coin (whose `coin_id == launcher_id == store_id`); it is the memo carrier we
/// override with the owner-discovery hint. Pinned as a literal so the crate self-contains it.
const SINGLETON_LAUNCHER_HASH: Bytes32 = Bytes32::new(hex!(
    "eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9"
));

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
/// dig-merkle never depends on `dig-did`. To root a store in a DID, pass the DID-authorized coin as
/// `parent_coin` with an [`Owner::Custom`] inner spend that satisfies the DID's puzzle — the launcher
/// then descends from the DID coin with no `dig-did` coupling here.
///
/// # Signing
///
/// The returned spends are UNSIGNED. An [`Owner::Standard`] mint requires exactly one `AGG_SIG_ME`
/// over the owner's synthetic key on the parent/owner spend; obtain it via
/// [`crate::required_signatures`].
///
/// # Errors
///
/// Returns [`MerkleError::Driver`](crate::MerkleError::Driver) if the SDK fails to construct the
/// launcher or the owner spend (e.g. an invalid metadata or delegated-puzzle set).
#[allow(clippy::too_many_arguments)]
pub fn mint_datastore(
    parent_coin: Coin,
    owner: Owner,
    root_hash: Bytes32,
    label: Option<String>,
    description: Option<String>,
    bytes: Option<u64>,
    size_proof: Option<String>,
    program_hash: Option<Bytes32>,
    size_bucket: Option<SizeBucket>,
    owner_puzzle_hash: Bytes32,
    delegated_puzzles: Vec<DelegatedPuzzle>,
    fee: u64,
) -> MerkleResult<MerkleCoinSpend> {
    let mut ctx = SpendContext::new();

    // Build the launcher + eve DataStore via the SDK (the byte-source-of-truth, INV-4). The returned
    // `launch_conditions` are what the funding coin must emit to create the launcher coin.
    let (launch_conditions, datastore) = Launcher::new(parent_coin.coin_id(), 1).mint_datastore(
        &mut ctx,
        DigDataStoreMetadata {
            root_hash,
            label,
            description,
            bytes,
            size_proof,
            program_hash,
            size_bucket,
        },
        owner_puzzle_hash.into(),
        delegated_puzzles,
    )?;

    // Override the launcher CREATE_COIN memos to the two-memo owner-discovery hint (SPEC §9). This is
    // the byte-identity requirement: the raw SDK mint emits only a single default hint, which matches
    // no store already on chain.
    let launch_conditions = override_launcher_hint(&mut ctx, launch_conditions, owner_puzzle_hash)?;

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

/// Rewrites the launcher `CREATE_COIN` in `conditions` to carry the two owner-discovery memos.
///
/// The SDK's `mint_datastore` emits the launcher `CREATE_COIN` with a single default hint; every DIG
/// producer replaces it with `[digstore_owner_hint(owner_ph), DATASTORE_LAUNCHER_HINT]` so the store
/// is owner-discoverable and byte-identical on chain (SPEC §9). Every other condition passes through
/// unchanged.
fn override_launcher_hint(
    ctx: &mut SpendContext,
    conditions: Conditions,
    owner_puzzle_hash: Bytes32,
) -> MerkleResult<Conditions> {
    let mut rewritten = Conditions::new();
    for condition in conditions {
        match condition {
            Condition::CreateCoin(create_coin)
                if create_coin.puzzle_hash == SINGLETON_LAUNCHER_HASH =>
            {
                let memos = ctx.memos(&[
                    digstore_owner_hint(owner_puzzle_hash),
                    DATASTORE_LAUNCHER_HINT,
                ])?;
                rewritten = rewritten.with(Condition::CreateCoin(CreateCoin {
                    puzzle_hash: create_coin.puzzle_hash,
                    amount: create_coin.amount,
                    memos,
                }));
            }
            other => rewritten = rewritten.with(other),
        }
    }
    Ok(rewritten)
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
                    if cc.puzzle_hash == SINGLETON_LAUNCHER_HASH {
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
            None,
            owner_ph,
            vec![],
            1_000,
        )
        .expect("mint builds");

        let memos = launcher_memos(&spend.coin_spends);
        assert_eq!(
            memos,
            vec![digstore_owner_hint(owner_ph), DATASTORE_LAUNCHER_HINT],
            "launcher memos must be [owner_hint, launcher_hint] byte-for-byte"
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
            bytes: Some(42),
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
    /// (no `program_hash`), so a byte-identity comparison isolates JUST the metadata type swap.
    #[allow(clippy::too_many_arguments)]
    fn reference_sdk_mint(
        parent_coin: Coin,
        owner_pk: chia_wallet_sdk::prelude::PublicKey,
        root: Bytes32,
        label: Option<String>,
        description: Option<String>,
        bytes: Option<u64>,
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
                    bytes,
                    size_proof,
                },
                owner_puzzle_hash.into(),
                vec![],
            )
            .expect("reference mint builds");
        let launch_conditions =
            override_launcher_hint(&mut ctx, launch_conditions, owner_puzzle_hash)
                .expect("reference hint override");

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
            Some(10),
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
            Some(10),
            None,
            owner_ph,
            1_000,
        );

        assert_eq!(
            dig.coin_spends, reference,
            "a None-program_hash mint must be byte-identical to an SDK-metadata mint"
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
