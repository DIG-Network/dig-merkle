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
dig-merkle = "0.1"
```

## What it is

A **DataLayer coin** is a CHIP-0035 singleton whose `launcher_id` IS the DIG `store_id`. Its
metadata carries the anchored `.dig` capsule merkle `root_hash` (plus optional
label/description/bytes/size-proof), and its delegated-puzzle list grants admin/writer/oracle
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
- **INV-4 — SDK byte-source-of-truth.** Every byte comes from `chia-wallet-sdk` (0.30 /
  chia-protocol 0.26, `chip-0035` feature); the SDK's DataStore types are re-exported verbatim.

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
| `mint::mint_datastore(parent_coin, owner, root_hash, label, description, bytes, size_proof, owner_ph, delegated, fee)` | **shipped** — launch a new DataLayer store anchoring a root, byte-identical to on-chain stores | owner's `AGG_SIG_ME` |
| `digstore_owner_hint(owner_ph)` / `DATASTORE_LAUNCHER_HINT` / `DIGSTORE_OWNER_HINT_DOMAIN` | **shipped** — the owner-discovery hint (SPEC §9) | — |
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

`mint_datastore` takes a **`parent_coin`**, not a full launcher, so a DID-authorized launcher
produced by [`dig-did`](https://crates.io/crates/dig-did) composes here **without a `dig-did`
dependency**: pass the DID coin as `parent_coin` with an `Owner::Custom` inner spend that satisfies
the DID puzzle. The dependency edge is one-way (dig-identity → dig-merkle); dig-merkle never depends
on a `dig-*` crate.

## Module map

- `types` — `MerkleCoinSpend`, `Owner`, and the re-exported SDK types (`DataStore`,
  `DataStoreMetadata`, `DataStoreInfo`, `DelegatedPuzzle`, `Bytes32`, `Coin`, `CoinSpend`,
  `LineageProof`, `Proof`).
- `error` — `MerkleError` / `MerkleResult` (the error taxonomy, SPEC §6).
- `sign` — `required_signatures` (the signing boundary, SPEC §4).
- `mint` — `mint_datastore` (shipped, SPEC §3.1).
- `hint` — `digstore_owner_hint` + the two hint constants (shipped, SPEC §9).
- `update` / `delegation` / `oracle` / `melt` / `read` / `hydrate` / `lineage` / `fee` — the remaining
  DataLayer operation modules (doc-only stubs; each filled in its own unit).

## Custody guarantee

dig-merkle holds **no key**, signs **nothing**, and does **no network I/O**. A caller cannot leak a
key through this crate because it accepts none. The signing boundary returns only the public
(public-key, message) pairs a signer needs.

## License

Licensed under either of Apache-2.0 or MIT at your option.

See [`SPEC.md`](./SPEC.md) for the full normative contract.
