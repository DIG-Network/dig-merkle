# Development log — dig-merkle

Concise, durable realizations from developing dig-merkle. Context, not a change diary.

## NC-9: a lineage/ownership WALK must bind every hop to the requested identity (fail closed)

`resolve_owner_did` (`src/read.rs`) recovers a store's owning DID by walking the launcher lineage
through an injected `ChainSource`. The `ChainSource` is trusted ONLY to return CONFIRMED on-chain
spends — it is NOT trusted to return the RIGHT coin for a given id. The public `rpc.dig.net` gateway
is attacker-influenceable (§5.3), so a hostile or buggy source can answer `coin_spend(store_id)` with
a DIFFERENT store's valid, DID-rooted launcher (and a valid creator for THAT launcher). Without a
per-hop binding the walk happily attributes the other store's owning DID to `store_id` — a
wrong-answer (NC-9) defect, worse than failing.

The invariant: a walk MUST bind each fetched coin back to the identity it was asked for and fail
CLOSED (`Err`, never a wrong `Some`) on any mismatch. Concretely:
- A DIG store id IS its launcher coin id → assert `launcher_spend.coin.coin_id() == store_id`.
- The creator is the launcher's parent → assert `creator_spend.coin.coin_id() == parent_id` where
  `parent_id == launcher_spend.coin.parent_coin_info`.

Prefer `Err(MerkleError::Chain)` over `Ok(None)` for a mismatch: a substituted answer must be
distinguishable from a genuinely non-DID-owned store (which is the legitimate `Ok(None)`). This is
the same defect class fixed in dig-store `walk_lineage` (#1247) and the pattern already correct in
chia-query's `walk_singleton_lineage`; the ecosystem uses ONE consistent bound-walk shape. Regression
coverage lives in `resolve_owner_did_rejects_a_substituted_launcher` and
`resolve_owner_did_rejects_a_wrong_creator` (#1321).
