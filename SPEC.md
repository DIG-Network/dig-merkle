# dig-merkle — Normative Specification

This document is the authoritative contract for `dig-merkle`, the DIG Network canonical CHIP-0035
DataLayer coin expert crate. An independent reimplementation could be built against this spec. It is
normative: it states what IS and what an implementation MUST/SHOULD do. Cross-references:
`SYSTEM.md` (cross-repo interaction map) and the docs.dig.net protocol pages.

## 1. Scope & invariants

dig-merkle builds the exact `CoinSpend`s for every lifecycle operation of a Chia CHIP-0035 DataLayer
singleton — the on-chain coin that anchors a `.dig` capsule's merkle root — and reports the exact
signatures a caller must produce. It is a pure library: no keys, no signing, no network.

Four invariants hold across the entire crate:

- **INV-1 — No network.** dig-merkle performs NO network or chain I/O. Every function is a pure
  transform of its inputs. The caller fetches coins and broadcasts bundles.
- **INV-2 — No keys.** dig-merkle never accepts, holds, derives, or logs a secret key. It computes
  what must be signed (`required_signatures`); the caller's signer produces the signatures.
- **INV-3 — Unsigned output.** Every operation returns an unsigned `MerkleCoinSpend` — the coin
  spends plus the recreated child `DataStore`. Signatures are always the caller's responsibility.
- **INV-4 — SDK byte-source-of-truth.** Every puzzle, layer, and coin-spend byte is produced by
  `chia-wallet-sdk` (pinned to the 0.30 / chia-protocol 0.26 family, `chip-0035` feature).
  dig-merkle adds workflow ergonomics on top; it never re-implements a puzzle or hand-rolls a spend
  bundle, and re-exports the SDK's DataStore types verbatim (no shadow copy).

## 2. The DataLayer-coin model

A DataLayer coin is a CHIP-0035 **singleton** (an NFT-state-layer singleton with the DataLayer
metadata updater). Its structure:

- **`launcher_id == store_id`.** The singleton launcher coin id IS the DIG `store_id`. It is
  permanent and uniquely names the store for the coin's entire lineage.
- **`DataStoreMetadata`** carries the anchored state:
  - `root_hash: Bytes32` — the `.dig` capsule's merkle root (the anchored value). REQUIRED.
  - `label: Option<String>`, `description: Option<String>` — human metadata (CLVM keys `l`, `d`).
  - `bytes: Option<u64>` — the store size in bytes (CLVM key `b`).
  - `size_proof: Option<String>` — an optional size attestation (CLVM key `sp`).
- **`delegated_puzzles: Vec<DelegatedPuzzle>`** grants write authority beyond the owner:
  - `Admin(TreeHash)` — full control (may change the delegation set + root).
  - `Writer(TreeHash)` — may update the root but not the delegation set.
  - `Oracle(Bytes32, u64)` — anyone may spend the coin to read it, paying the fixed fee.
- **The owner** is the standard p2 (`Owner::Standard`) or a custom inner puzzle (`Owner::Custom`,
  e.g. a DID-authorized delegated puzzle) that guards spending.

Spending the coin recreates it as its child with a (possibly) new root, delegation set, or owner —
or melts it (no child). This is the DIG anchor: publishing a new capsule root is a DataLayer update
that recreates the singleton with the new `root_hash`.

## 3. Operations catalogue

Every operation returns an unsigned `MerkleCoinSpend { coin_spends, child }` (INV-3) and states its
AGG_SIG requirement. U1 ships the foundation only; the operations below are the designed surface,
each landing in its own unit against the foundation.

### 3.1 mint

```
mint_datastore(parent_coin, owner, root_hash, label, description, bytes, size_proof,
               owner_puzzle_hash, delegated_puzzles, fee) -> MerkleResult<MerkleCoinSpend>
```

Launches a new DataLayer store singleton over `chia_wallet_sdk::driver::Launcher::mint_datastore`
(INV-4). `parent_coin` funds AND parents the launcher: its `coin_id` becomes the launcher's parent,
so `launcher_id == store_id` derives from it. Taking a `parent_coin` (not a full launcher) lets a
DID-authorized launcher built by `dig-did` compose here **without a `dig-did` dependency** — pass the
DID coin as `parent_coin` with an `Owner::Custom` inner spend; the edge stays one-way
(dig-identity → dig-merkle).

The construction, byte-for-byte:

1. `Launcher::new(parent_coin.coin_id(), 1).mint_datastore(ctx, DataStoreMetadata{root_hash, label,
   description, bytes, size_proof}, owner_puzzle_hash, delegated_puzzles)` yields the launch
   conditions + the eve `DataStore`.
2. **Two-memo launcher-hint override (load-bearing).** The raw SDK mint emits only a single default
   launcher hint, which matches NO store already on chain. dig-merkle rewrites the launcher
   `CREATE_COIN` (the one to the singleton launcher puzzle hash
   `eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9`) so its memos are EXACTLY
   `[digstore_owner_hint(owner_puzzle_hash), DATASTORE_LAUNCHER_HINT]` (first = indexed owner
   discovery hint, second = global launcher hint) — replicating chip35_dl_coin `store.rs` and
   digstore-chain `singleton.rs`. This override is the DEFAULT behaviour, not opt-in.
3. Change above `fee + 1` mojos returns to `owner_puzzle_hash`, hinted. The `fee` is paid
   **implicitly** as (coins in − coins out) — there is NO explicit `RESERVE_FEE`, matching the
   on-chain producers.
4. `parent_coin` is spent with `owner`'s inner puzzle (`Owner::Standard` → `StandardLayer`;
   `Owner::Custom` → the caller's pre-built inner spend).

Returns `MerkleCoinSpend { coin_spends: [launcher spend, parent/owner spend], child: Some(eve
DataStore) }`, unsigned (INV-3). **Signing:** an `Owner::Standard` mint requires exactly one
`AGG_SIG_ME` over the owner's synthetic key on the parent/owner spend (never `AGG_SIG_UNSAFE`); a
custom/DID inner owns its own requirement.

**Root encoding.** The anchored `root_hash` is the first atom of the NFT-state-layer metadata CLVM
`(root_hash . (("l" . label)? ("d" . description)? ("b" . bytes)? ("sp" . size_proof)?))`, produced
by `DataStoreMetadata::to_clvm` (never hand-rolled).

### 3.2 update

`update_root(store, owner, new_metadata)` recreates the coin with a new `root_hash` (and optional
metadata), preserving `launcher_id`, delegation set, and owner. Authorized by the owner OR a
`Writer`/`Admin` delegated puzzle. **Signing:** the authorizing inner puzzle's `AGG_SIG_ME`
(`Owner::Standard` → one signature over the owner key; a custom/delegated inner owns its own).

### 3.3 delegation

`set_delegated_puzzles(store, owner, new_delegated_puzzles)` grants/revokes `Admin`/`Writer`/`Oracle`
authority. **Admin-only:** only the owner or an `Admin` delegated puzzle may change the set; a
`Writer` attempt MUST fail with `MerkleError::Permission`. **Signing:** the authorizing inner
puzzle's `AGG_SIG_ME`.

### 3.4 oracle

`oracle_spend(store)` spends the `Oracle` delegated puzzle so any party may read the coin on-chain,
paying the fixed oracle fee to the oracle puzzle hash. **Signing:** none from dig-merkle's owner
(the oracle puzzle is keyless); the caller supplies the fee.

### 3.5 melt

`melt(store, owner)` terminally spends the coin, producing no child (`child == None`). **Signing:**
the owner's `AGG_SIG_ME`.

### 3.6 read

`read(store)` / `parse_coin_spend(...)` parse the current on-chain `DataStoreMetadata` +
delegation set from a coin/puzzle without spending. No signing.

## 4. Signing boundary

`required_signatures(coin_spends, constants) -> MerkleResult<Vec<RequiredSignature>>` is the sole
bridge to a signer. It wraps `chia_sdk_signer::RequiredSignature::from_coin_spends` over a private
`Allocator`, collecting every `AGG_SIG_*` condition each coin spend's puzzle emits and returning the
precise (public key, message) pairs the caller must sign. It is pure and key-free (INV-2); an empty
coin-spend slice yields an empty requirement set (never an error). A puzzle-evaluation failure or an
infinity public key yields `MerkleError::Signer`.

The consumer pattern is fixed:

```text
build MerkleCoinSpend -> required_signatures(&spend.coin_spends, &constants)
  -> caller signs each message -> assemble SpendBundle -> broadcast
```

## 5. Hydration & lineage (fail-closed)

To spend an existing DataLayer coin, a caller reconstructs a spendable `DataStore` from its parent
coin spend (`DataStore::from_spend`) and the `LineageProof` a singleton child requires
(`DataStore::child_lineage_proof`). Hydration is **fail-closed**:

- A coin whose puzzle does not parse as a DataLayer singleton yields `MerkleError::NotDataStore`.
- A missing lineage proof yields `MerkleError::MissingLineage` — dig-merkle never fabricates one.
- A missing required hint memo yields `MerkleError::MissingHint`.

dig-merkle never guesses missing chain state; the caller supplies the real parent spend.

## 6. Error taxonomy

`MerkleError` (all fallible operations return `MerkleResult<T>`):

| Variant | Raised when |
|---|---|
| `Driver(DriverError)` | a chia-wallet-sdk driver op fails (currying, spend, CLVM eval); wrapped verbatim |
| `Signer(String)` | the signing calculator fails (bad puzzle/solution, infinity key) |
| `Parse(String)` | a coin/puzzle/solution is not the expected shape |
| `NotDataStore` | a puzzle parsed but is not a DataLayer singleton |
| `MissingLineage` | hydration lacks the required lineage proof (fail-closed) |
| `MissingHint` | a parsed coin lacks the required hint memo (fail-closed) |
| `Permission(String)` | a delegated-puzzle op lacks its required authority (e.g. writer→admin) |
| `Chain(String)` | a chain-level precondition is violated (e.g. launcher mismatch) |
| `EmptyCoins` | an operation was given an empty coin set |

## 7. Security properties

- **Custody:** dig-merkle holds no key and signs nothing (INV-2). A caller cannot accidentally leak
  a key through this crate because it accepts none. The signing boundary (§4) returns only the
  public data a signer needs.
- **Determinism:** every function is a pure transform (INV-1); given identical inputs it produces
  byte-identical coin spends, so a spend can be independently reproduced and audited.
- **Fail-closed:** hydration and permission checks reject on missing/invalid state (§5, §6) rather
  than producing an unspendable or over-authorized bundle.

## 8. Back-compat (CLAUDE.md §5.1 — additive only)

A `.dig` root coin is a permanent, on-chain-anchored artifact; content published under a store id
stays readable forever. dig-merkle's read/hydrate path MUST therefore be additive and
backward-compatible:

- **Newer readers accept ALL older coins.** The parser dispatches on the on-chain shape and keeps
  handling every prior DataLayer layout — it MUST NOT hard-reject an older coin.
- **The legacy launcher path is retained.** The SDK's `from_memos` / `OldDlLauncherKvList` legacy
  key-value-list launcher parsing MUST remain supported; dig-merkle never drops it.
- **Metadata is additive.** New optional metadata keys may be added; existing keys
  (`root_hash`, `l`, `d`, `b`, `sp`) never change meaning or encoding.
- **Prove it.** The test suite keeps golden coin-spend fixtures of each released layout; every
  format change MUST include a test decoding the older golden fixtures byte-identically. The mint
  golden test (`launcher_carries_the_two_memo_owner_discovery_hint`) pins the launcher `CREATE_COIN`
  memos to `[digstore_owner_hint(owner_ph), DATASTORE_LAUNCHER_HINT]`, and
  `metadata_clvm_encodes_root_as_first_atom` pins the root as the first metadata atom — the proof a
  minted coin matches stores already on chain.

## 9. Conformance

- **Byte-agreement with chip35.** dig-merkle's DataLayer coin MUST be byte-identical to the existing
  DataLayer coin in `chip35_dl_coin` (both build over the same `chia-wallet-sdk` primitives, INV-4).
  A coin dig-merkle mints/updates MUST be spendable by, and produce the same on-chain state as, the
  chip35 implementation.
- **Signature construction** MUST match `chia_sdk_signer::RequiredSignature::from_coin_spends`
  exactly (dig-merkle only wraps it).
- **Owner-hint domain.** The owner/delegation hint-memo domain is the fixed constant
  `DIGSTORE_OWNER_HINT_DOMAIN = b"dig:datastore:owner:v1"` (defined in dig-merkle, not imported), and
  MUST match across every DIG consumer that resolves a DataLayer owner hint.
  `digstore_owner_hint(owner_ph) = sha256(DIGSTORE_OWNER_HINT_DOMAIN ‖ owner_ph)` — byte-identical to
  chip35_dl_coin + digstore-chain.
- **Global launcher hint.** `DATASTORE_LAUNCHER_HINT = sha256("datastore") =
  aa7e5b234e1d55967bf0a316395a2eab6cb3370332c0f251f0e44a5afb84fc68`, emitted as the second launcher
  memo. Byte-identical across all DIG producers.
- **Launcher memos.** A minted store's launcher `CREATE_COIN` carries exactly
  `[digstore_owner_hint(owner_ph), DATASTORE_LAUNCHER_HINT]`, in that order.
- **Root metadata shape.** `root_hash` is the first atom of the metadata CLVM
  `(root_hash . optional-kv-pairs)`; optional keys are `l`/`d`/`b`/`sp`.
- **Dependency layer.** dig-merkle is an L0 crate: it depends ONLY on `chia-wallet-sdk` +
  `chia-protocol`/`chia-puzzle-types`/`clvm-traits`/`chia-sha2` + external utility crates
  (thiserror, hex-literal). It MUST NOT depend on any `dig-*` crate (that would deepen the
  ecosystem crate hierarchy), and MUST NEVER depend on `dig-identity` (the edge is one-way,
  dig-identity → dig-merkle — the reverse is a cycle).
