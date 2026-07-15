# v0 core — decomposition into bounded rb-lite runs

first-light is merged to `main` (commit 5dd3945). v0 is the full core the
"core proven" gate sits behind (DESIGN.md Next Steps step 1). It is too large
for one rb-lite run, so it is split into the tasks below. Each is one branch,
one rb-lite run, one merge to `main`. Task files live in `.rb-lite/tasks/`.

Dependency order (→ = depends on). DONE: V0-1, V0-2, V0-3, V0-5.

```
V0-1  sighash + real user-sig verification      DONE (b5a4247)
V0-2  commitment struct + anti-replay log        DONE (ce932fa)
V0-3  the Hold (two-phase signing)               DONE (8678a45)
V0-5  verified change + consistency + descriptor allowlist  DONE (a9d57e9)
V0-6  chain backend + watchtower classification + /events + broadcast  DONE (595c338, primitives)
V0-6b drive the watchtower scan in the node daemon        DONE (2ce2933)
V0-8  node-to-node assembly + node broadcast; coordinator → relay  NEXT (the spine)
V0-4a dual PINs + deferred lockdown + persistence (node-local; no channel)  → parallel to V0-8
V0-4b duress escape (rides V0-8's assembly+broadcast; pin decides + delayed) → V0-8, V0-4a
V0-7  proptest + full test matrix + hold-clawback demo  → all
```

**MODEL B PIVOT (2026-07-15, user; ADR-0010/0011).** The coordinator is now an
untrusted relay; nodes assemble + broadcast every spend over an authenticated
node-to-node channel. This reverses "coordinator trusted in MVP" and revises
"no intra-node comms" (nodes stay policy-isolated, not network-isolated). It
makes the node-assembly channel the v0 spine and reshapes the normal spend path
(first-light/demo included). What's UNAFFECTED: all node-local validation
(V0-1 sighash, V0-2 commitment/replay, V0-3 Hold, V0-5 descriptor policy) and
the watchtower (V0-6/6b) — those are validation, which stays node-local. What
changes: who assembles + broadcasts (coordinator → nodes).

## V0-8 — node-to-node assembly + node broadcast (NEXT, the spine)
**Spec: [ADR-0012](adr/0012-model-b-spend-and-duress-architecture.md) — the source of truth. Full Model B locked (not hybrid).**
The founding rework. Design the node channel in detail first (ADR-0011 is a
sketch): node identity + mutual auth (deploy-time keys), transport (v1 Tor),
and the request-scoped partial-signature exchange + combine + broadcast. Then:
each node builds the tx from relayed intent + its own chain view, validates,
signs, gathers the other partials over the channel, combines, and broadcasts via
its V0-6 chain backend. The coordinator (vault-cli) stops combining/finalizing/
broadcasting — it relays {intent, user_sigs, pin} and pulls alerts. Rework the
demo so nodes broadcast. Big; likely splits into V0-8a (channel: identity/auth/
transport/exchange) and V0-8b (node-side assemble+broadcast + spend-path/demo
rework). Keeps policy node-local; the channel carries no policy.

**Reorder (2026-07-14):** V0-6 now precedes V0-4. The duress redesign (no-abort,
node-distributed delayed broadcast — ADR-0008) means duress can't be built until
nodes can broadcast, which V0-6's chain backend provides.

**Deferred perf item (from V0-5):** `derives_within` re-derives scripts per
`/sign` request over the bounded index range; a reviewer flagged the per-request
cost. Rejected as V0 over-specification (the scan is bounded by
`max_derivation_index`; correctness is unaffected). Revisit as a v0.x/v1
optimization: precompute the allowlist/descriptor address set at node startup.

## V0-1 — sighash enforcement + real user-signature verification
Replace first-light's presence-only user-sig check with cryptographic
verification against the node's own recomputed sighash for the primary spend
branch; enforce SIGHASH_ALL. Subsumes the "output mutation after authorization"
check (DESIGN.md Policy model). policy-core + vault-node. Sharpest security gap
in first-light — do first.

## V0-2 — transaction commitment + anti-replay log
vault-proto: the full commitment struct (wallet_id, outpoints, outputs, fee,
expiry, policy_version) with canonical byte-identical serialization (T4).
vault-node: record commitments keyed by commitment hash; expiry pruning;
node-capped expiry via max_commitment_age_secs. The log is the Hold timer's
substrate. Idempotency/audit, never blocks RBF (DESIGN.md).

## V0-3 — the Hold (two-phase signing)
Per-destination-class routing: hot = hold_secs pending then sign on
re-submission; escape/refresh = instant. Pending state on the commitment log.
Escape sweep double-spends a pending spend's inputs (implicit cancel). ADR-0004.

**Decide here (carried from V0-2):** whether the commitment must bind the full
unsigned transaction — `version`, `nLockTime`, per-input `nSequence` — not just
outpoints/outputs/fee. In V0-2 it does NOT (design-defined field set;
SIGHASH_ALL binds them for the *signature*, and only commitment-determined
verdicts are cached, so a collision is provably harmless there). Under the Hold,
a *pending* spend is identified by commitment across two submissions, so a
collision between two economically-identical txs that differ only in
locktime/sequence becomes load-bearing (which one is "the" pending tx, which one
the escape sweep cancels). Resolve: either bind those fields into the commitment
(and update DESIGN.md's commitment field list + the gstack design-of-record), or
document why pending-identity is safe without them.

## V0-6b — drive the watchtower scan in the node daemon (NEXT, small)
V0-6 delivered the watchtower as a caller-driven `watchtower_tick` pass; in the
running daemon nothing calls it, so `GET /events` is always empty in production
(a gap in the V0-6 task spec — the node-side scan driver belongs in the daemon,
not the coordinator). This task adds the minimal driver:
- A node-config field for the chain-backend endpoint (bitcoind RPC URL); the demo
  wires each node's config to the regtest node.
- A minimal periodic scan thread in the daemon that calls `watchtower_tick`,
  tracking the last-scanned height (advance the cursor; don't re-scan from 0) so
  overlapping scans and the dedup set behave. Keep it a thin loop, not a
  scheduler.
- Test: the daemon, given a mock/regtest backend, drives a scan and a spend shows
  up via `GET /events` without an explicit test call.
Independent of V0-4 (which needs only the broadcast primitive, already done); run
before the core-proven gate so the watchtower is real before real sats.

## V0-4 — dual PINs + duress response + lockdown (after V0-6)
Design LOCKED 2026-07-14; full detail in ADR-0008. Build after V0-6 (needs node
broadcast). **The mechanism is now fully specified in [ADR-0012](adr/0012-model-b-spend-and-duress-architecture.md) — the source of truth; the earlier bullets here (coordinator-assembled escape) are SUPERSEDED.** Locked shape (per ADR-0012):
- Full Model B: nodes assemble + broadcast EVERY spend over the node channel;
  coordinator is a pure relay (trusted until the wrench, never persists the pin).
- Dual PINs every spend (ephemeral, never logged — the substitution defense).
- Escape is deterministic, **node-built** (parameterless full-sweep), user-signed,
  stored as a refreshed standby. The coordinator never touches it.
- Duress state machine: arm (+propagate to peers +persist) → armed (silent,
  freezes hot-class completion) → fire at T (broadcast + re-broadcast) → lockdown
  (terminal, recovery-path exit). `duress_delay_secs` is the hostage-safety window.
- No abort. Accepted residuals: total coordinator censorship, sustained fee spike,
  compromised-node duress detection (silence model A). All are denial, never theft.

## V0-5 — verified change + PSBT consistency + descriptor allowlist
policy-core: verified-change via own-descriptor re-derivation at bounded index;
PSBT global/input/output consistency; allowlist entries become descriptors with
a bounded index (not baked scriptPubKeys). Reuses one re-derivation primitive
for input ownership, change, and allowlist (DESIGN.md Policy model).

## V0-6 — chain-backend seam + watchtower + GET /events + node broadcast (NEXT)
vault-node: chain-backend trait (trust-PSBT impl behind it — T6 seam only), and
a **broadcast capability** on that trait (needed by V0-4's node-distributed
duress broadcast — ADR-0008); watchtower scan for recovery-path spends and
un-co-signed vault spends; GET /events pull API (cursor). vault-cli: coordinator
pull loop + sign-log reconciliation. ADR-0001/0002. Keep the trait's real
network impls minimal (a regtest/bitcoind-RPC impl is enough for v0); the
Core/Electrum/BIP158 choice and lying-coordinator enforcement stay v1 (T6).

## V0-7 — proptest + full test matrix + demo act two
proptest over PSBT mutation (no mutated tx passes an authorization bound to the
original); the full D8 test matrix; upgrade `demo` to the two-act story
(refusal + theft caught mid-Hold, clawed back by escape sweep).

## Core-proven gate (after V0-7)
Full test matrix green + a confirmed signet spend through the federation + one
external review — before any deployer/sealing/Tor/mTLS work (DESIGN.md 2.5).
