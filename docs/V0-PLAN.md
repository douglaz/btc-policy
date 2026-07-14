# v0 core — decomposition into bounded rb-lite runs

first-light is merged to `main` (commit 5dd3945). v0 is the full core the
"core proven" gate sits behind (DESIGN.md Next Steps step 1). It is too large
for one rb-lite run, so it is split into the tasks below. Each is one branch,
one rb-lite run, one merge to `main`. Task files live in `.rb-lite/tasks/`.

Dependency order (→ = depends on):

```
V0-1  sighash + real user-sig verification      (independent)
V0-2  commitment struct + anti-replay log        (independent)
V0-5  verified change + consistency + descriptor allowlist  (independent)
V0-3  the Hold (two-phase signing)               → V0-2
V0-4  dual PINs + duress + lockdown              → V0-3, V0-2
V0-6  chain-backend seam + watchtower + /events  (independent-ish)
V0-7  proptest + full test matrix + hold-clawback demo  → all
```

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

## V0-4 — dual PINs + duress response + lockdown
**BLOCKED pending duress-redesign decisions (2026-07-14 conversation).** Do not
launch until resolved and ADR-0008 is updated.

Emerging redesign (supersedes ADR-0008's instant sweep + instant lockdown):
- **Duress is silent and deferred.** An observable countermeasure endangers a
  hostage, so the duress PIN does nothing observable at entry — it *schedules*
  the escape sweep AND lockdown to fire together after a delay, invisible on
  chain until then. Buys the person time to reach safety.
- **Two escape timings, by threat model:** *race/rotate* (remote attacker, no
  hostage — watchtower or manual) stays **instant**; *duress* (hostage present)
  is **delayed + silent**. Same destination, opposite timing.
- **Abortable during the window** via the normal PIN — safe because the response
  is silent (attacker doesn't know there's anything to force a stand-down of),
  and in the sweep case the funds haven't moved yet either.
- Known limit to document: under duress the attacker may control the coordinator
  (the victim's laptop), which can decline to broadcast a scheduled sweep —
  a v1 untrusted-coordinator / node-driven-broadcast concern, not solved in MVP.

Open decisions before this can be specced:
1. Duress delay = reuse `hold_secs`, or a separate `duress_delay_secs` (rec:
   separate, same default — the escape-to-safety horizon ≠ the fraud-notice
   horizon).
2. Confirm the delayed+silent-duress vs instant-race split.
3. Plain `lockdown` mode (no sweep): instant freeze (funds unprotected during any
   delay) vs the hostage-silence tension — pick per threat model.

Still in scope regardless: dual PINs (second factor on every spend, wire-
identical duress vs normal), lockdown persisted on disk surviving restart,
FRAUD_SUSPECTED refusals as cover story.

## V0-5 — verified change + PSBT consistency + descriptor allowlist
policy-core: verified-change via own-descriptor re-derivation at bounded index;
PSBT global/input/output consistency; allowlist entries become descriptors with
a bounded index (not baked scriptPubKeys). Reuses one re-derivation primitive
for input ownership, change, and allowlist (DESIGN.md Policy model).

## V0-6 — chain-backend seam + watchtower + GET /events
vault-node: chain-backend trait (trust-PSBT impl behind it — T6 seam only);
watchtower scan for recovery-path spends and un-co-signed vault spends;
GET /events pull API (cursor). vault-cli: coordinator pull loop + sign-log
reconciliation. ADR-0001/0002.

## V0-7 — proptest + full test matrix + demo act two
proptest over PSBT mutation (no mutated tx passes an authorization bound to the
original); the full D8 test matrix; upgrade `demo` to the two-act story
(refusal + theft caught mid-Hold, clawed back by escape sweep).

## Core-proven gate (after V0-7)
Full test matrix green + a confirmed signet spend through the federation + one
external review — before any deployer/sealing/Tor/mTLS work (DESIGN.md 2.5).
