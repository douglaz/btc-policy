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
only acceptable — the "hot wallet is the risk budget" residual — if the amount newly
admitted to completion per window is **bounded**. It was NOT: nothing in `policy-core` or
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
   enforced, sibling to `hold_secs < max_commitment_age_secs`): the window covers
   every candidate throughout its node-authorized completion lifetime, so one cap
   bounds both newly admitted in-flight outflow and rate. Two coherence checks are
   fatal at load beside it: **both caps must be non-zero** (a zero either way refuses
   every hot spend of even one satoshi, silently reducing the vault to
   escape-and-refresh-only — "disable the hot wallet" is an empty allowlist, not a
   budget setting), and **`hot_max_per_tx ≤ hot_max_per_window`** (the ledger reserves
   the whole outflow at ingress, so a larger per-tx cap can never be reached and the
   effective per-transaction bound would silently be `min` of the two, misreading the
   operator sizing below). Equality is the intended "one maximal spend may consume the
   whole window".
4. **`HotBudgetLedger`** (RAMDISK, two hooks on the existing candidate lifecycle):
   `reserve(commitment_id, outflow)` at accept (idempotent per commitment_id;
   refuse if over per-tx or over window); `release(commitment_id)` when the candidate
   reaches a terminal state **without having released its partial or broadcast**
   (expired-unbroadcast, or superseded/frozen pre-fire). The predicate is
   `hot && !released && !broadcast`: a released partial is already in peer hands and
   could still be combined into a completing spend, so it meters exactly as a
   broadcast one does. Either way the reservation is held until age-out;
   **eviction/re-org is deliberately not tracked** (over-counting a
   broadcast-then-vanished spend can only refuse a later spend, never admit an
   over-budget one — the safe direction; matches V0-8b "mempool-presence = settled").
   The window ages against a **MONOTONIC** clock (elapsed process time), not wall
   time: a reservation's lifetime is a pure local duration, unlike every other
   deadline in the Node, which is compared against a coordinator-signed absolute
   instant. Wall time here would let a forward clock step — an NTP correction, a VM
   restore — destroy live reservations and free a whole window's budget while its
   spends were still broadcastable. (The coordinator nonce log's high-water mark
   does not cover this: it guards clock ROLLBACK, so a forward reading passes
   through it.) A suspend makes a monotonic clock lag real time, which over-counts —
   again the safe direction.
   That monotonic clock is only HALF of a reservation's lifetime, because the two
   lifetimes it must dominate are anchored to two different clocks: the reservation
   is a local duration, while the candidate it meters dies at the absolute wall
   instant its coordinator signed (`prune` keeps a candidate while `expiry >= now`,
   the fire window opens while `now <= deadline <= expiry`, both against raw wall
   time). Any wall adjustment moves one and not the other — a BACKWARD step stretches
   the candidate's real lifetime past where the monotonic window closes, and a
   FORWARD excursion at ingress buys the accepted commitment an expiry an excursion's
   width beyond it (the nonce log's high-water guards rollback only, and the
   `expiry <= now + max_commitment_age_secs` retention cap is applied against the
   stepped reading). So a reservation is held while EITHER clock still calls the
   spend live and is dropped only when both agree it is dead. The union can only
   over-count, which refuses a later hot spend but never admits an over-budget one,
   and it costs nothing under a coherent clock: with `hot_window_secs ≥
   max_commitment_age_secs` (§3) the wall term already sits inside the monotonic one.
5. **Outflow = sum of outputs to neither the vault nor the escape wallet; fee
   excluded** (the fee goes to miners, so it is burn rather than attacker-extractable
   outflow — this bound is scoped to extraction). Burn keeps its ADR-0006 defenses,
   which is why it needs no metering here: the 10% guard caps any single transaction,
   and the Hold plus the PIN — not the per-tx guard — are what bound burn ACROSS
   transactions, the axis this section's window cap otherwise covers. (Refresh needed
   its own interval and feerate bounds precisely because it is pin-less and instant
   and so has neither, ADR-0012; hot-class has both.) Vault outputs are change and escape outputs pay the
   user's own wallet (§7) — neither is a loss, so the two exclusions are what make
   "hot-class only" fall out of the definition instead of needing a class argument. A
   hot-class spend pays only hot + vault change (mixed hot+escape is already
   `PSBT_INCONSISTENT`), so outflow = the hot-wallet payment.
6. **Federation-uniform:** `hot_max_per_tx`, `hot_max_per_window`, `hot_window_secs`
   agreed at sealed setup and pinned in the Manifest preimage (a Node whose caps ≠
   the sealed manifest fails startup). The canonical Hot allowlist, Escape
   descriptor, and `max_derivation_index` are pinned beside them, for two distinct
   reasons: the Escape descriptor and `max_derivation_index` are what `hot_outflow`
   skips and scans, so a Node with either different METERS the same output
   differently; the Hot allowlist feeds no metering at all, but decides
   ADMISSIBILITY, so a Node with a wider one signs spends its peers refuse outright.
   Either way, a non-uniform cap or classifier is only as strong as the laxest Node.
   The pinned Hot allowlist is the Node allowlist MINUS the Escape descriptor (the
   Escape wallet must be allowlisted so its sweep passes the destination check, but
   is never a hot destination).
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

- **Admission bound (grilled):** each honest Node caps its own reservations at `V`.
  With `c < t` compromised signer Nodes able to sign without executing the ledger,
  a newly completable hot spend consumes reservations at ≥ `t−c` honest Nodes.
  Across the `n−c` honest ledgers, newly completable hot outflow admitted per window
  is therefore ≤ `((n−c)/(t−c))·V`. Every production vault runs in channel mode,
  whose startup invariant requires exactly `n = 2t−1` (ADR-0013 §1). In the pure
  duress-censorship residual (`c = 0`) this is `(2 − 1/t)·V < 2V`; under the full
  soft-vault tolerance `c = t−1`, it reaches `tV`. The per-node velocity loosens the
  exact-`V` bound by this routing factor (tightening to `V` would need cross-node
  velocity gossip — not worth it). Age-out does not invalidate a previously exposed
  Bitcoin signature; this is a rolling admission/rate bound, while §8's detection +
  Recovery bounds lifetime exposure. **Operator sizing across the full stated
  compromise tolerance: set `hot_max_per_window ≤ tolerable per-window loss ÷ t`;
  use the smaller `c` formula only when the deployment explicitly assumes fewer
  compromised signer Nodes.**
- **Composition:** the reserve refusal is amount-based (pin-uniform), so it fires
  before signing AND the duress arm still fires + propagates on the refusal path — an
  over-cap coerced spend still freezes the federation, it just also can't complete.
  Silence holds (reserve at ingress is pin-independent; release runs off the `/sign`
  path).
- **Cost:** a burst of large legitimate hot spends is throttled to `V` per window; a
  hot spend cancelled or expired **while still unexposed** gives its budget back via
  `release` (Approach B, chosen over pure age-out for exactly this usability). "Frees
  it immediately" is only true of that unexposed case, and the freeze path frees it at
  the expiry sweep that collects the frozen candidate rather than at the arm — the arm
  deliberately mutates no map, because a mutation that happened only under duress
  would reintroduce the timing signal ADR-0012 spent the most effort removing.
- **Non-goals:** tiered / per-destination budgets, dynamic caps (the ledger leaves
  room; v0 ships the single per-tx + per-window pair). No durable ledger — RAMDISK
  only; the long-horizon bound is detection + Recovery. **Conflicting replacements are
  not netted:** an RBF fee-bump or a re-issued spend of the same vault UTXO is a fresh
  commitment (the log is keyed by content, never by outpoint set) and takes its own
  full reservation, while the original keeps metering to age-out if its partial has
  already left this node. Two conflicting txs can never both confirm, so `k` bumps over-count
  `k`× — but netting them would mean releasing on same-input conflict, and if the
  original is the one that confirms while the replacement never propagates, that
  release admits an over-budget spend. Over-counting refuses a legitimate spend;
  netting can admit a coerced one. This ADR takes the availability cost and keeps the
  safe direction; the escape sweep, not a fee-bump, is the way out of a stuck vault.
- **Reconciles:** DESIGN.md + CONTEXT.md ("Hot wallet", "Hot budget") now cite the
  enforced caps; ADR-0012's residual ledger cites this bound.
