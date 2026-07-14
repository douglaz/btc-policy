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
V0-6  chain-backend seam + watchtower + /events + node broadcast  NEXT
V0-4  dual PINs + duress + lockdown              → V0-6 (needs node broadcast), V0-3, V0-2
V0-7  proptest + full test matrix + hold-clawback demo  → all
```

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

## V0-4 — dual PINs + duress response + lockdown (after V0-6)
Design LOCKED 2026-07-14; full detail in ADR-0008. Build after V0-6 (needs node
broadcast). Summary of the locked shape:
- Dual PINs on every `/sign` (second factor; wire-identical duress vs normal;
  deliberately distinct, enforced at enrollment).
- Duress is **silent + deferred**: the PIN schedules escape sweep + lockdown to
  fire together after `duress_delay_secs` (separate from `hold_secs`; `0`
  allowed = instant). Nothing observable at entry; nodes behave normally during
  the window; lockdown fires at T+delay to preserve silence.
- **Sign now, broadcast later**: coordinator assembles the fully-signed escape tx
  at entry and distributes the complete tx to all n nodes; each node broadcasts
  via its V0-6 chain backend at T+delay. Robust — coordinator not needed after
  entry; all n nodes must be suppressed to stop it.
- **No abort**: nothing halts it once entered (max coercion-resistance). Accepted
  cost: a mis-entered duress PIN is unstoppable → funds to escape (recoverable).
- Lockdown persisted on disk, survives restart, no reset on sealed nodes (exit =
  recovery path). FRAUD_SUSPECTED refusals as cover story.
- Two escape timings coexist: duress = delayed/silent; manual rotate / watchtower
  race = instant.

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
