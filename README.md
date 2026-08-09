# dig-merkle

**The DIG Network canonical CHIP-0035 DataLayer coin expert crate** — a pure, key-free,
network-free `SpendBundle`-builder for the Chia DataLayer singleton that anchors a `.dig` file's
merkle root on-chain.

dig-merkle constructs the exact `CoinSpend`s for every DataLayer-coin lifecycle operation and
reports the exact signatures a caller must produce. It **never holds a secret key, never signs, and
never touches the network**. The consumer signs the reported messages, assembles the `SpendBundle`,
and broadcasts.

```toml
[dependencies]
dig-merkle = "0.2"
```

## What it is

A **DataLayer coin** is a CHIP-0035 singleton whose `launcher_id` IS the DIG `store_id`. Its
metadata (`DigDataStoreMetadata`) carries the anchored `.dig` capsule merkle `root_hash` plus
optional label/description/size-proof, the additive `program_hash` (the CLVM tree-hash of an
associated program/puzzle — stored and echoed, never computed here), and the store size as a
`size_bucket` (a `SizeBucket` — a power-of-2 bucket, `k ∈ 0..=10` ↔ `2^k MB`, 1 MB..1 GB, CLVM key
`sz`) that REPLACES the SDK's exact-byte `"b"` field (dig-merkle never emits `"b"`). With
`size_bucket` and `program_hash` both `None` a mint is byte-identical to a plain DataLayer store. Its
delegated-puzzle list grants admin/writer/oracle
authority. Spending the coin recreates it with a new root, a new delegation set, or a new owner — or
melts it. Publishing a new capsule root IS a DataLayer update. dig-merkle builds each such spend,
**unsigned**.

dig-merkle is the DIG-Network expert wrapper over
[`chia-wallet-sdk`](https://crates.io/crates/chia-wallet-sdk)'s DataLayer primitives (the
byte-source-of-truth): it adds workflow ergonomics and a hard custody boundary, never a
re-implemented puzzle.

## Invariants

- **INV-1 — No network.** No network or chain I/O; every function is a pure transform. The caller
  fetches coins and broadcasts bundles.
- **INV-2 — No keys.** Never accepts, holds, derives, or logs a secret key. It computes what must be
  signed; the caller's signer produces the signatures.
- **INV-3 — Unsigned output.** Every operation returns an unsigned `MerkleCoinSpend` (coin spends +
  the recreated child `DataStore`).
- **INV-4 — SDK byte-source-of-truth.** Every byte comes from `chia-wallet-sdk` (0.34 /
  chia-protocol 0.36.1, `chip-0035` feature); the SDK's DataStore types are re-exported verbatim.

## Consumer pattern

```text
build an unsigned MerkleCoinSpend
  -> required_signatures(&spend.coin_spends, &constants)
  -> caller signs each reported message
  -> assemble SpendBundle
  -> broadcast
```

```rust,ignore
use dig_merkle::{required_signatures, AggSigConstants};
use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;

// (build a MerkleCoinSpend via a mint/update/... operation — see the operation surface below)
let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
let required = required_signatures(&spend.coin_spends, &constants)?;
// sign each `required[i]` under its public key, aggregate, assemble the SpendBundle, broadcast.
# Ok::<(), dig_merkle::MerkleError>(())
```

## Operation surface

Each operation returns an unsigned `MerkleCoinSpend` and states its signing requirement.
**U2 (v0.2.0)** ships the mint builder + the owner-discovery hint on top of the U1 foundation (type
surface, error taxonomy, inner-spend helpers, signing boundary). The remaining operations are the
designed surface; each lands in its own unit.

| Function | Semantics | Signing |
|---|---|---|
| `mint::mint_datastore(parent_coin, owner, root_hash, label, description, size_proof, program_hash, size_bucket, owner_ph, delegated, fee)` | **shipped** — launch a new DataLayer store anchoring a root, byte-identical to on-chain stores | owner's `AGG_SIG_ME` |
| `size::SizeBucket` (`from_exponent`/`for_byte_len`/`exponent`/`megabytes`/`byte_len`) | **shipped** — the canonical `.dig` size-bucket ladder (`k ∈ 0..=10` ↔ `2^k MB`, 1 MB..1 GB); CLVM key `sz`, replaces the exact-byte `"b"` | — |
| `digstore_owner_hint(owner_ph)` / `DATASTORE_LAUNCHER_HINT` / `DIGSTORE_OWNER_HINT_DOMAIN` | **shipped** — the owner-discovery hint (SPEC §9) | — |
| `read::did_ref_from_spend(&coin_spend)` | **shipped** — recognise a DID coin spend, returning its `DidRef { launcher_id }` (a non-DID puzzle is `None`; a reveal the coin did not commit to is `Err(Chain)`) | none |
| `read::resolve_owner_did(store_id, &chain)` | recover the DID that owns a store via a `ChainSource` lineage walk (SPEC §3.7) — *pending `dig-chainsource-interface` crates.io publish* | none |
| `update::update_root(store, owner, new_metadata)` | recreate the coin with a new merkle root | owner or writer/admin `AGG_SIG_ME` |
| `delegation::set_delegated_puzzles(store, owner, set)` | grant/revoke admin/writer/oracle authority (admin-only) | owner or admin `AGG_SIG_ME` |
| `oracle::oracle_spend(store)` | read the coin on-chain for the fixed oracle fee | none (keyless oracle puzzle) |
| `melt::melt(store, owner)` | terminally spend the coin (no child) | owner `AGG_SIG_ME` |
| `read::read(store)` | parse current on-chain state (no spend) | none |
| `hydrate::*` | reconstruct a spendable `DataStore` from a parent spend (fail-closed) | — |
| `lineage::*` | derive the `LineageProof` a child spend needs | — |
| `required_signatures(...)` | **shipped** — the signing boundary (§4) | — |

### The two-memo launcher hint (byte-identity)

`mint_datastore` overrides the launcher `CREATE_COIN` memos to exactly
`[digstore_owner_hint(owner_ph), DATASTORE_LAUNCHER_HINT]` — the first the indexed owner-discovery
hint (`sha256("dig:datastore:owner:v1" ‖ owner_ph)`), the second the global launcher hint
(`sha256("datastore")`). This replicates `chip35_dl_coin` and `digstore-chain` exactly, so a store
minted here is byte-identical to (and interchangeable with) the stores those already publish
on-chain. It is the default behaviour, verified by a golden test.

### DID composition

A DIG store can be rooted in a DID **without a `dig-did` dependency**. The composable path is:

1. Build the launcher for your parent's shape. A DID is a **singleton**, whose inner puzzle may emit
   exactly ONE odd-amount `CREATE_COIN` — its own successor — so it cannot create the 1-mojo launcher
   directly; the bundle would build cleanly and be rejected on chain. Interpose an intermediate coin:
   `IntermediateLauncher::new(did.coin.coin_id(), 0, 1).create(&mut ctx)?`. (An ordinary, non-singleton
   parent uses `Launcher::new(parent_coin.coin_id(), 1)`.) Both are re-exported here.
2. Call `mint_datastore_launch_with_kind(&mut ctx, kind, launcher, ..)` — this stages the launcher and
   eve-DataStore spends into `ctx` and returns a `DatastoreLaunch` whose `parent_conditions` carry the
   `CREATE_COIN` that starts the launch (the intermediate coin, or the launcher itself for a direct
   launch) plus the announcement assertions that the DID-authorized parent spend **must** emit.
3. Build your DID-authorized parent-coin spend on the **same** `ctx`, folding in
   `DatastoreLaunch::parent_conditions`.
4. Drain `ctx` once to get the complete spend bundle.

The launcher is created at 1 mojo by a **zero-amount** intermediate, so the bundle must carry that
mojo from another spend; Chia balances a bundle in aggregate, not per coin.

The two-memo owner-discovery hint lives on the launcher `CREATE_COIN`, which an intermediate launch
emits from its own fixed puzzle — so a store launched this way carries **no launcher memos** and is
not found by a launcher-memo scan. The `kind` discriminator rides on those same memos, so it too is
accepted but not written on this path — the launch reports `launcher_memos_written == false` so a
caller can see it. Such a store is discovered by `resolve_owner_did` instead (below).

**The two shapes trade memo-scannability against lineage-resolvability, and a DID-rooted launch has
to pick one.** The intermediate shape is resolvable by `resolve_owner_did` but writes no memos. The
alternative — `DID coin -> ordinary EVEN-amount coin -> launcher -> store`, where the DID creates an
ordinary even-amount coin and THAT coin launches directly — does write the memos, but is **not**
resolvable: the launcher's creator is an ordinary coin, which is neither a DID nor the recognised
intermediate launcher, so `resolve_owner_did` returns `None` for it today (known gap, **#2463**). The
odd-coin restriction binds the *singleton's* inner puzzle, not an ordinary coin, so both compositions
are legal on chain.

Note also that the owner-discovery memo encodes the **owner puzzle hash**, not a DID — so a memo scan
never yields a DID reference on either path; DID attribution comes only from the lineage walk.

`mint_datastore_with_kind` (the all-in-one wrapper) accepts only `Owner::Standard` and rejects
`Owner::Custom` with `MerkleError::UnsupportedOwner` — use the composable API above for DID-rooted
stores. `update_root` and `melt` reject it for the same reason: each builds the conditions its spend
must emit inside the call, and a pre-built inner spend cannot contain them. In practice `Owner::Custom`
is unusable across the whole public API — a `Spend` holds CLVM node pointers valid only in the
allocator that built them, and no public operation exposes its `SpendContext` for a caller to build one
in. The dependency edge stays one-way (dig-identity → dig-merkle); dig-merkle depends on no
`dig-*` crate except the canonical leaf `dig-chainsource-interface` (a reference-DOWN pure read
interface BELOW dig-merkle, for §3.7 — pending its crates.io publish).

### Owner-DID discovery

A store launched **through an intermediate launcher** (the composable path above) can be traced back
to its owning DID: `resolve_owner_did` walks the store's launcher lineage up — one creator hop, or two
through that intermediate coin — and recognises a DID creator, delegating ALL chain reads to a
caller-supplied `ChainSource` (the canonical `dig_chainsource_interface::ChainSource`), so dig-merkle
stays network-free (INV-1). A store launched directly from an ordinary coin resolves to `None`, even
when a DID created that coin (#2463):

```rust,ignore
use dig_merkle::{did_ref_from_spend, DidRef};
use dig_chainsource_interface::ChainSource; // canonical read interface (pending crates.io publish)

// Implement ChainSource over your own client (RPC / full node / cache):
struct MyChain { /* ... */ }
impl ChainSource for MyChain {
    fn coin_spend(&self, coin_id: Bytes32) -> dig_merkle::MerkleResult<Option<CoinSpend>> {
        // fetch the spend that spent `coin_id`, or None if unknown/unspent
    }
}

// resolve_owner_did walks store_id -> launcher.parent -> creator spend, fail-closed to None:
let owner: Option<DidRef> = resolve_owner_did(store_id, &MyChain { /* ... */ })?;

// The pure detection core ships today (no ChainSource needed):
let did_ref: Option<DidRef> = did_ref_from_spend(&some_coin_spend)?;
# Ok::<(), dig_merkle::MerkleError>(())
```

`resolve_owner_did` lands when `dig-chainsource-interface` publishes to crates.io (dig-merkle allows
no `git` dependencies); `did_ref_from_spend` + `DidRef` are available now.

## Module map

- `types` — `MerkleCoinSpend`, `Owner`, and the re-exported SDK types (`DataStore`,
  `DataStoreMetadata`, `DataStoreInfo`, `DelegatedPuzzle`, `Bytes32`, `Coin`, `CoinSpend`,
  `LineageProof`, `Proof`).
- `metadata` — `DigDataStoreMetadata`, the SDK metadata with `"b"` replaced by `size_bucket` (`"sz"`) + the additive `program_hash` (shipped, SPEC §2).
- `size` — `SizeBucket`, the canonical `.dig` size-bucket ladder (shipped, SPEC §2).
- `error` — `MerkleError` / `MerkleResult` (the error taxonomy, SPEC §6).
- `sign` — `required_signatures` (the signing boundary, SPEC §4).
- `mint` — `mint_datastore` (shipped, SPEC §3.1).
- `hint` — `digstore_owner_hint` + the two hint constants (shipped, SPEC §9).
- `read` — `did_ref_from_spend` + `DidRef` (shipped, SPEC §3.6/§3.7); the `resolve_owner_did`
  `ChainSource` walk is pending the interface's crates.io publish.
- `update` / `delegation` / `oracle` / `melt` / `hydrate` / `lineage` / `fee` — the remaining
  DataLayer operation modules (doc-only stubs; each filled in its own unit).

## Custody guarantee

dig-merkle holds **no key**, signs **nothing**, and does **no network I/O**. A caller cannot leak a
key through this crate because it accepts none. The signing boundary returns only the public
(public-key, message) pairs a signer needs.

## License

Licensed under either of Apache-2.0 or MIT at your option.

See [`SPEC.md`](./SPEC.md) for the full normative contract.
