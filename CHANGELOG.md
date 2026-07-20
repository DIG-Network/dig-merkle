# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - 2026-07-20

### Features
- DataLayer ops `update_root`/`melt`/`hydrate`/`child_lineage_proof` over the chia-wallet-sdk
  chip-0035 DataStore driver — all unsigned (INV-3), fail-closed hydration (#1227)
- `resolve_owner_did<C: ChainSource>` launcher-lineage walk over `dig-chainsource-interface`
  (fail-closed to `Ok(None)`, read-only) (#1227)
- Additive launcher-hint kind split: `StoreKind {File, DidProfile}`, `launcher_hint_for`,
  `from_launcher_hint`, `DID_PROFILE_LAUNCHER_HINT`, and `mint_datastore_with_kind`;
  `mint_datastore` stays byte-identical (File hint) (#1263)

## [0.3.0] - 2026-07-20

### Features
- Size_bucket ("sz") replaces exact-byte size + fee overflow guard + NC-9 docstring (#3)

## [0.2.0] - 2026-07-19

### Features
- Program_hash metadata + owner-DID discovery (byte-identical DataLayer mint) (#1)

## [0.1.0] - 2026-07-19

### Features
- Crate skeleton, SPEC, signing boundary, and CI gate set (U1)


