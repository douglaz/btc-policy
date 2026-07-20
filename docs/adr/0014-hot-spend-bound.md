# ADR-0014: Hot-spend bound (per-tx cap + velocity ledger)

Status: accepted 2026-07-20 (office-hours design + grill pass; design doc:
`~/.gstack/projects/btc-policy/user-douglaz-design-hot-spend-bound-20260720.md`).
Companion to [ADR-0012](0012-model-b-spend-and-duress-architecture.md) — bounds the
one residual the V0-4b duress arming leaves open. Where DESIGN.md / CONTEXT.md say
"hot wallet is the accepted risk budget," this ADR is what makes that an *enforced*
bound rather than an assumption.

## Context

Two-model review of the V0-4b duress arming (2026-07-20) established that the
arming is theft-safe for a spend submitted *with* the duress pin (the release-gate
+ signer/partial coupling of ADR-0012 invariant vii — no honest node ever releases
a coerced partial), and that ONE residual remains: a post-wrench compromised
coordinator can **censor the duress freeze** from a sub-quorum of honest nodes, so a
Hot spend already pending in its Hold at those nodes can complete. That residual is
only acceptable — the "hot wallet is the risk budget" residual — if the amount that
can complete this way is **bounded**. It was NOT: nothing in `policy-core` or
`vault-node` caps a hot spend's amount or rate (the allowlist bounds the
*destination*, not the *amount*; the only limits are the pin-attempt budget and the
10% fee guard). So a single coerced hot spend could pay the entire vault to the hot
wallet — turning an accepted censorship residual into an unbounded vault drain.

## Decision

Enforce a **Hot budget** on Hot-class outflow, at each Node, at ingress, before
signing:

1. **A per-transaction cap `hot_max_per_tx`** AND **a rolling-window velocity cap
   `hot_max_per_window`** — both; either alone is unbounded in the number of spends.
2. **Accounting = pending + settled (registered outflow):** the window counts every
   hot spend a Node has ACCEPTED (signed at ingress) within the window, pending or
   broadcast — so the bound is aggregate and real (an attacker cannot queue several
   large hot spends in one Hold and have them all clear; the 2nd+ exceed the cap at
   ingress and every Node refuses).
3. **Single window cap with `hot_window_secs ≥ max_commitment_age_secs`** (config-
   enforced, sibling to `hold_secs < max_commitment_age_secs`): the window always
   covers every still-completable spend, so one cap bounds both in-flight and rate.
4. **`HotBudgetLedger`** (RAMDISK, two hooks on the existing candidate lifecycle):
   `reserve(commitment_id, outflow)` at accept (idempotent per commitment_id;
   refuse if over per-tx or over window); `release(commitment_id)` when the candidate
   reaches a terminal state **without having broadcast** (expired-unbroadcast, or
   superseded/frozen pre-fire). A broadcast candidate holds its reservation until
   age-out; **eviction/re-org is deliberately not tracked** (over-counting a
   broadcast-then-vanished spend can only refuse a later spend, never admit an
   over-budget one — the safe direction; matches V0-8b "mempool-presence = settled").
5. **Outflow = sum of outputs to non-vault (non-change) destinations; fee excluded**
   (goes to miners, not attacker-extractable, already bounded by the 10% guard). A
   hot-class spend pays only hot + vault change (mixed hot+escape is already
   `PSBT_INCONSISTENT`), so outflow = the hot-wallet payment.
6. **Federation-uniform:** `hot_max_per_tx`, `hot_max_per_window`, `hot_window_secs`
   agreed at sealed setup and pinned in the Manifest preimage (a Node whose caps ≠
   the sealed manifest fails startup) — a non-uniform cap is only as strong as the
   laxest node.
7. **Hot-class only:** Escape (pays the user's own escape wallet) and Refresh (stays
   in the vault) are not losses → never consume the budget.
8. **Risk model = per-window cap + rotate-on-compromise:** the cap bounds loss to
   ~one window's budget; the lifetime defense is detection (the Watchtower surfacing
   anomalous hot outflow) + Recovery, not the cap.

Refusals: `HOT_BUDGET_EXCEEDED` (per-tx) / `HOT_VELOCITY_EXCEEDED` (window), sibling
to `DEST_NOT_ALLOWED`. The per-tx amount check lives in `policy-core`'s hot-class
`evaluate()` (pure, chain-view-free); the velocity check needs Node state, so it
lives in `vault-node` at ingress.

## Consequences

- **Bound (grilled):** each Node caps its own reservations at `V`; a completing hot
  spend needs ≥ t signers who each reserved it, so total completable hot outflow per
  window ≤ `(n/t)·V = (2 − 1/t)·V < 2V` (for `n = 2t−1`), even under full duress-
  freeze censorship. The per-node velocity loosens the exact-`V` bound by < 2×
  (tightening to `V` would need cross-node velocity gossip — not worth it). **Operator
  sizing: set `hot_max_per_window ≈ (tolerable per-window loss) / 2`.**
- **Composition:** the reserve refusal is amount-based (pin-uniform), so it fires
  before signing AND the duress arm still fires + propagates on the refusal path — an
  over-cap coerced spend still freezes the federation, it just also can't complete.
  Silence holds (reserve at ingress is pin-independent; release runs off the `/sign`
  path).
- **Cost:** a burst of large legitimate hot spends is throttled to `V` per window; a
  cancelled/failed hot spend frees its budget immediately via `release` (Approach B,
  chosen over pure age-out for exactly this usability).
- **Non-goals:** tiered / per-destination budgets, dynamic caps (the ledger leaves
  room; v0 ships the single per-tx + per-window pair). No durable ledger — RAMDISK
  only; the long-horizon bound is detection + Recovery.
- **Reconciles:** DESIGN.md + CONTEXT.md ("Hot wallet", "Hot budget") now cite the
  enforced caps; ADR-0012's residual ledger cites this bound.
