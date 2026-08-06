# v0 core — decomposition into bounded rb-lite runs

first-light is merged to `main` (commit 5dd3945). v0 is the full core the
"core proven" gate sits behind (DESIGN.md Next Steps step 1). It is too large
for one rb-lite run, so it is split into the tasks below. Each is one branch,
one rb-lite run, one merge to `main`. Task files live in `.rb-lite/tasks/`.

Dependency order (→ = depends on). DONE: V0-1, V0-2, V0-3, V0-5.

```
V0-1  sighash + real user-sig verification      DONE (b5a4247)
V0-2  commitment struct + anti-replay log        DONE (ce932fa)
V0-2b commitment MIGRATION: bind version/nLockTime/per-input nSequence  → feeds V0-8 (ADR-0012/0013 §2)
V0-3  the Hold (two-phase signing)               DONE (8678a45)
V0-5  verified change + consistency + descriptor allowlist  DONE (a9d57e9)
V0-6  chain backend + watchtower classification + /events + broadcast  DONE (595c338, primitives)
V0-6b drive the watchtower scan in the node daemon        DONE (2ce2933)
V0-8  node-to-node assembly + node broadcast; coordinator → relay  NEXT (the spine)
V0-4a dual PINs + deferred lockdown, RAMDISK state (reboot-death/tmpfs, 2026-07-16; node-local; no channel)  → parallel to V0-8
V0-4b duress escape (rides V0-8's assembly+broadcast; pin decides + delayed) → V0-8, V0-4a
V0-7  proptest + full test matrix + hold-clawback demo  → all
V0-9  provisioning: manifest + config schema + coord auth-key backup  → feeds V0-8 (ADR-0013 §4/§5/§7)
V0-10 recovery-path construction + operations  (was OUTSIDE the graph — ADR-0013 open item)
```

**MODEL B PIVOT (2026-07-15, user; authoritative spec: [ADR-0012](adr/0012-model-b-spend-and-duress-architecture.md)).** The coordinator is a relay, **trusted until the wrench attack, untrusted after** (never persists the pin); nodes assemble + broadcast every spend over an authenticated node-to-node channel, and nodes **validate** the coordinator-composed, user-signed txs rather than building them. This reverses "coordinator trusted in MVP" and revises "no intra-node comms" (nodes stay policy-isolated, not network-isolated). The full duress architecture + all re-review resolutions live in ADR-0012. It
makes the node-assembly channel the v0 spine and reshapes the normal spend path
(first-light/demo included). What's UNAFFECTED: node-local validation
(V0-1 sighash, V0-5 descriptor policy) and
the watchtower (V0-6/6b) — those are validation, which stays node-local. What
changes: who assembles + broadcasts (coordinator → nodes). **Correction
(ADR-0012/0013 §2): the earlier "V0-2 commitment/replay is unaffected by Model B"
claim is now FALSE — the commitment must additionally bind `version`, `nLockTime`,
and every input `nSequence`, which V0-2 did not. A migration is required, tracked
as V0-2b below.** **Correction (ADR-0012 "Model-B Hold lifecycle"): the earlier
"V0-3 Hold is unaffected by Model B" claim is now FALSE too** (same shape as the
V0-2 correction above, so V0-3 Hold is removed from the UNAFFECTED list). Under
Model B the Hold is **node-driven**: each node **signs its partial at INGRESS**
(pin-independent) and **combines + broadcasts at Hold-expiry with NO coordinator
re-submission** — NOT V0-3's re-submit-to-sign two-phase shape. V0-3's Hold
*duration + pending/first-seen accounting* survive, but its **signing shape is
reworked in V0-8 (spine) / V0-4 (duress)**; ADR-0004 is bannered accordingly.

## V0-8 — node-to-node assembly + node broadcast (NEXT, the spine)
**Spec: [ADR-0012](adr/0012-model-b-spend-and-duress-architecture.md) + [ADR-0013](adr/0013-concrete-protocol-schemas.md) — the source of truth. Full Model B + the duress architecture are in HARDENING (2026-07-15): four adversarial rounds + a fresh-eyes whole-spec pass established no theft path and (after this pass's fixes) no silence break; a final fresh-eyes re-review gates the lock.**
**Split confirmed — start with V0-8a (the channel), then V0-8b (node-side assemble+broadcast + spend-path/demo rework). V0-4's duress state machine rides on V0-8b and carries the adversarial regtest harness that empirically verifies ADR-0012's denial residuals (toxic-parent, in-flight-refresh, two-spend-probe, escape-class+refresh).**
The founding rework. Design the node channel in detail first (ADR-0011 is a
sketch): node identity + mutual auth (**RAM-only channel keys re-derived at
startup from the wskdf preimage — no at-rest channel secret — each endorsed by
that node's Bitcoin signing key; ADR-0012 channel identity / ADR-0013 §4**),
transport (v1 Tor),
and the request-scoped partial-signature exchange + combine + broadcast. Then:
each node VALIDATES the coordinator-composed, user-signed tx against its own chain view + policy (it does NOT build it — ADR-0012),
signs, gathers the other partials over the channel, combines, and broadcasts via
its V0-6 chain backend. The coordinator (vault-cli) stops combining/finalizing/
broadcasting — it relays the **coordinator-SIGNED tagged request**
(`SpendRequest{spend, escape, escape_bumps, pin, nonce, expiry, policy_version}` or
`RefreshRequest{refresh, nonce, expiry, policy_version}` — escape mandatory,
coordinator signature over a fresh nonce + expiry; ADR-0013 §2) and pulls
alerts. Rework the
demo so nodes broadcast. Big; likely splits into V0-8a (channel: identity/auth/
transport/exchange) and V0-8b (node-side assemble+broadcast + spend-path/demo
rework). Keeps policy node-local; the channel carries no policy.

**Newly-specified mechanisms to build here (fresh-eyes review; ADR-0012/0013):**
- **Pin-independent ingress** (identical per-request work: validate both spend + escape, sign both
  partials, record in RAMDISK state (reboot-death/tmpfs, 2026-07-16 — no persisted partials), propagate to all peers; pin sets only an internal fire bit; **combine-at-broadcast**,
  no pre-assembled escape on the response path) — the silence-load-bearing ingress shape every request
  rides. Shared with V0-4. (ADR-0012.)
- **Per-vault manifest + full node config schema** — the immutable, hash-pinned manifest (ADR-0013 §4:
  wallet_id, canonical descriptor, `coordinator_auth_pubkey`, per-node signing+channel pubkeys with
  endorsements, t/n, allowlist, escape descriptor) and the security-load-bearing config
  superset (ADR-0013 §5). The channel-identity auth + coord-sig freshness check both read from it. Shared
  with provisioning (V0-9).

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

**Follow-up — per-node pin-attempt budget (ADR-0013 §7; shared with V0-4).** The
pin hash-compare (constant-time) lives alongside user-sig verification; guard online
guessing with a **per-node** budget: failed-compare count over `window_secs`,
`backoff_schedule`, then `lockout_secs` (RAMDISK/node-lifetime — the tmpfs deployment
means a reboot destroys the budget AND the signing key alike, so no reset-by-reboot;
reboot-death/tmpfs, 2026-07-16). No cross-node
accounting (the channel forbids shared mutable state); per-node suffices because the
pin is the same value everywhere. Lockout is a transient rate-limit, **not** Lockdown.

## V0-2 — transaction commitment + anti-replay log
vault-proto: the full commitment struct (wallet_id, outpoints, outputs, fee,
expiry, policy_version) with canonical byte-identical serialization (T4).
vault-node: record commitments keyed by commitment hash; expiry pruning;
node-capped expiry via max_commitment_age_secs. The log is the Hold timer's
substrate. Idempotency/audit, never blocks RBF (DESIGN.md).

**MIGRATION REQUIRED — see V0-2b (ADR-0012/0013 §2).** V0-2 bound only the
design-era field set (wallet_id, outpoints, outputs, fee, expiry, policy_version).
Model B requires the commitment to bind the **exact unsigned transaction** —
additionally `version`, `nLockTime`, and **every input `nSequence`** — so two
distinct txs can never share a commitment id (else the channel could gather
non-combinable partials, and pending-spend identity under the Hold is ambiguous).
The earlier claim that "commitment/replay is unaffected by Model B" is therefore
false; this is a follow-up, not covered by the original DONE.

## V0-2b — commitment migration: bind version/nLockTime/per-input nSequence (follow-up to V0-2)
The parked V0-2/V0-3 "must the commitment bind the full unsigned tx?" question is
now **RESOLVED: yes** (ADR-0012 "commitment binds the exact unsigned transaction";
ADR-0013 §2). Extend the vault-proto commitment struct + its canonical byte-identical
serialization to include `version`, `nLockTime`, and per-input `nSequence`; update the
anti-replay/Hold log and every place that computes or compares a commitment id; update
DESIGN.md's commitment field list + the gstack design-of-record. Needed before V0-8 so
the node channel never gathers non-combinable partials for two txs sharing an id.

## V0-3 — the Hold (two-phase signing)
Per-destination-class routing: hot = hold_secs pending then sign on
re-submission; escape/refresh = instant. Pending state on the commitment log.
Escape sweep double-spends a pending spend's inputs (implicit cancel). ADR-0004.

**Follow-up — refresh bounds (ADR-0013 §6; shared with V0-5).** Refresh is pin-less +
instant, so it has neither the Hold nor the pin that ADR-0006's burn defense assumed;
replace that with two node-enforced limits: a per-coin **minimum refresh interval**
(`refresh_min_interval_secs`, ~30d default — well under the ~90d cadence) and a **tight
refresh fee cap** (`refresh_max_feerate`, a normal feerate, NOT the 10% `max_fee_pct`).
Refreshes stay subordinate to pending spends (ADR-0012) and pin-less.

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

**RESOLVED (2026-07-15, ADR-0012/0013 §2): bind them.** The commitment MUST include
`version`, `nLockTime`, and per-input `nSequence`. Tracked as the V0-2b migration above.

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
Design in HARDENING (2026-07-15; full detail in ADR-0012/0013, superseding ADR-0008; a final fresh-eyes re-review gates the lock). Build after V0-6 (needs node
broadcast). **The mechanism is now fully specified in [ADR-0012](adr/0012-model-b-spend-and-duress-architecture.md) — the source of truth; the earlier bullets here (coordinator-assembled escape) are SUPERSEDED.** Locked shape (per ADR-0012):
- Full Model B: nodes assemble + broadcast EVERY spend over the node channel;
  coordinator is a pure relay (trusted until the wrench, never persists the pin).
- Dual PINs every spend (ephemeral, never logged — the substitution defense).
- Escape is **coordinator-composed + user-signed, mandatory in every request**;
  nodes **VALIDATE** it (destination = escape descriptor, value-coverage ≥
  threshold, feerate ≥ floor) — they do NOT build it, and there is NO stored
  standby (per ADR-0012 — this line previously described the superseded design).
- Duress state machine: record intent + propagate to peers (RAMDISK state — reboot-death/tmpfs, 2026-07-16) → arm on
  t-of-n confirmation (V0-4b §0; ingress itself never arms) → armed (silent,
  freezes hot-class completion) → **unconditional lockdown at T** (terminal,
  recovery-path exit), **THEN a best-effort sweep** (combine + re-broadcast; may
  fail → funds stay frozen → recovery). `duress_delay_secs` is the hostage-safety window.
- No abort. Accepted residuals: total coordinator censorship, sustained fee spike,
  compromised-node duress detection (silence model A). All are denial, never theft.

**Newly-specified mechanisms to build (fresh-eyes review; ADR-0012/0013):**
- **Pin-independent ingress** (silence-load-bearing) — every request, normal or duress, does
  identical observable work: coord-auth + freshness, validate BOTH the spend and the always-present
  escape, sign both partials, record in RAMDISK state (reboot-death/tmpfs, 2026-07-16), and propagate to all peers; the pin (constant-time hash-compare)
  flips only an **internal** fire bit. **Combine-at-broadcast** (do not pre-assemble the escape on the
  response path). Shared with V0-8. (ADR-0012.)
- **Node-derived transaction-class predicate + reject-mixed (ADR-0013 §3; shared with V0-5)** — class
  comes from the spend's **outputs**, never a coordinator label. Vault change is permitted in every
  class and excluded from classification: escape-class iff every *destination* output pays the escape
  descriptor, refresh-class iff every output pays the vault descriptor, and hot-class iff every
  *destination* output pays a hot-allowlist descriptor; **mixed → reject (`PSBT_INCONSISTENT`)**
  (closes the 99%-hot + dust-to-escape bypass).
- **RAMDISK ARMING state + unconditional Lockdown-at-T on every failure branch** (reboot-death/tmpfs,
  2026-07-16) — hold the armed bit + `T` in RAMDISK node state, no persistence: a rebooted armed node is
  DEAD and contributes no partial; if ≥ t remain, the surviving armed set attempts the best-effort
  sweep at `T`; below quorum or on any fire-time failure, it is lockdown-only → recovery (ADR-0007).
  Enter Lockdown at `T` even if fire/broadcast fails (not only after
  confirm); the pin is **never persisted in the envelope** (ADR-0012 duress state machine).
- **Two-track duress state machine — the arm VERDICT is keyed on the valid DURESS PIN ALONE**
  (chain-view-independent), and the arm is **COMMITTED at t-of-n confirmation** (V0-4b §0): a valid
  coordinator-authenticated duress pin decides the verdict with **NO** coverage / feerate /
  `testmempoolaccept` / mempool judgment at arm at all — so backend chain-view skew (tip lag, reorg,
  propagation) cannot split the armed set below `t` (this is the arm-split conditional-theft fix) — but the
  **freeze of hot-class finalization + lockdown-at-T commit only once ≥ t nodes are confirmed to hold the
  request**, on the `/channel` receipt path and off the `/sign` response path. Ingress records intent and
  propagates; it never arms. **What actually makes the freeze un-splittable is the signer/partial coupling +
  release-gate (ADR-0012 correction 2026-07-20), NOT the confirmation count** — with `n=2t−1` a `t`-count
  can't prove `t` honest froze; the count schedules timing, the release-gate (no honest node releases a
  coerced partial) is the safety, and the pending-spend-censorship residual is bounded by the Hot budget
  (ADR-0014). A coordinator that keeps a carrier from reaching `t` nodes achieves censorship (an accepted,
  Hot-budget-bounded residual), never an unbounded one-armed split. Escape admissibility (class-aware coverage, feerate floor,
  package `testmempoolaccept`) is **ENTIRELY a fire-time check** that gates only whether the best-effort
  sweep fires; a sweep that fails still leaves the node frozen + locked down → recovery. See ADR-0012
  "Duress state machine (per node) — normative".
- **Per-node pin-attempt budget protocol** (RAMDISK/node-lifetime count/window/backoff/lockout —
  reboot-death/tmpfs, 2026-07-16; no cross-node accounting; lockout ≠ Lockdown) — shared with V0-1
  (ADR-0013 §7).

## V0-5 — verified change + PSBT consistency + descriptor allowlist
policy-core: verified-change via own-descriptor re-derivation at bounded index;
PSBT global/input/output consistency; allowlist entries become descriptors with
a bounded index (not baked scriptPubKeys). Reuses one re-derivation primitive
for input ownership, change, and allowlist (DESIGN.md Policy model).

**Newly-specified work (fresh-eyes review; ADR-0013):**
- **Node-derived transaction-class predicate + reject-mixed (ADR-0013 §3; shared with V0-4).** Reuse
  V0-5's own-descriptor re-derivation to classify the spend from its **outputs**. Vault change is
  permitted in every class and excluded from classification: escape-class iff every *destination*
  output pays the escape descriptor, refresh-class iff every output pays the vault descriptor, and
  hot-class iff every *destination* output pays a hot-allowlist descriptor; **reject mixed
  (`PSBT_INCONSISTENT`)**. Never trust a coordinator label.
- **Refresh min-interval + tight fee cap (ADR-0013 §6; shared with V0-3).** Enforce
  `refresh_min_interval_secs` and `refresh_max_feerate` on refresh-class spends.

## V0-6 — chain-backend seam + watchtower + GET /events + node broadcast (NEXT)
vault-node: chain-backend trait (trust-PSBT impl behind it — T6 seam only), and
a **broadcast capability** on that trait (needed by V0-4's node-distributed
duress broadcast — ADR-0008); watchtower scan for recovery-path spends and
vault spends the node never **validated** (ADR-0012 watchtower revision:
recognition = the **validated-request** set, NOT the co-signed set — co-signing
false-alarms on the n−t legitimate non-signers); GET /events pull API (cursor). vault-cli: coordinator
pull loop + sign-log reconciliation. ADR-0001/0002. Keep the trait's real
network impls minimal (a regtest/bitcoind-RPC impl is enough for v0); the
Core/Electrum/BIP158 choice and lying-coordinator enforcement stay v1 (T6).

## V0-7 — proptest + full test matrix + demo act two
proptest over PSBT mutation (no mutated tx passes an authorization bound to the
original); the full D8 test matrix; upgrade `demo` to the two-act story
(refusal + theft caught mid-Hold, clawed back by escape sweep).

## V0-9 — provisioning: per-vault manifest + config schema + coordinator auth-key backup (NEW — fresh-eyes review)
> **DELIVERED 2026-07-25, bead btc-policy-9y5.5** — `btc-vault setup` (`crates/vault-cli/src/setup.rs`),
> procedure in [`docs/SETUP-CEREMONY.md`](SETUP-CEREMONY.md). On-device node keygen (no machine holds two
> node secrets), the `node_seckey`-at-rest field retired for an in-RAM wskdf derivation, a MANDATORY
> `expected_manifest_hash`, ceremony-time key-independence refusal with written evidence, and the
> descriptor/manifest/auth-key artifacts plus backups. `demo` and `attack` drive this same ceremony.

The manifest is the **root of channel + coordinator trust**, so it is load-bearing, not deploy glue
(previously only DESIGN's T1). Build:
- **Per-vault manifest (ADR-0013 §4):** written once at setup, hash-pinned, distributed to every node +
  backed up with the descriptor; **immutable** (any change = a new vault). Fields: wallet_id, canonical
  `vault_descriptor`, policy_version, `coordinator_auth_pubkey`, per-node {signing_pubkey, channel_pubkey,
  transport_endpoints}, t/n, recovery_timelock, hot_allowlist, escape_descriptor,
  `escape_feerate_floor`, `escape_coverage_pct`. Each
  `channel_pubkey` **endorsed by that node's Bitcoin signing key** over a domain-separated tuple (ADR-0012
  channel identity) so the coordinator cannot mint/impersonate a node. Shared with V0-8.
- **Full node config schema (ADR-0013 §5):** the security-load-bearing superset of DESIGN's TOML — pin
  hashes, `duress_delay_secs`, `escape_coverage_pct`, `escape_feerate_floor`, `epsilon_secs`,
  `refresh_min_interval_secs`, `refresh_max_feerate`, `pin_attempt_budget`, `coordinator_auth_pubkey`,
  `manifest_hash`, channel peers/quotas. All node-enforced. Shared with V0-8.
- **Coordinator auth-key backup (ADR-0012/0013 §7):** back up the coord auth key at setup, **separately**
  from the descriptor backup. **Loss with no backup bricks the normal path** (the manifest pins the pubkey
  → recovery-timelock exit only). **Rotation = a new vault** (immutable manifest); no in-place rotation in
  v0. State this loudly in the ceremony UX.

## V0-10 — recovery-path construction + operations (NEW — was OUTSIDE the V0 task graph; ADR-0013 open item)
ADR-0013 flags the recovery path as currently outside the V0 graph — add it. The recovery branch
(`and(older(TIMELOCK), thresh(2, REC_A, REC_B, REC_C))`; `TIMELOCK` a BIP68 512-second `older(...)`,
180-day default = 30375 units — ADR-0013 §1) is the **sole exit from Lockdown** and the backstop for
federation/user-key loss, yet nothing in V0 builds or exercises it. Scope: construct + sign a
recovery-branch spend (2-of-3 recovery keys after the relative timelock matures), the operations/runbook
for using it, and a regtest exercise of the full path. Watchtower **detection** of a recovery-path spend
(branch-identifiable on-chain — the alarm for *stolen* recovery keys) already exists (V0-6) and is
unaffected.

## Core-proven gate (after V0-7)
Full test matrix green + a confirmed signet spend through the federation + the FREEZE
(`btc-policy-gbw`, prerequisite `btc-policy-9yf`) — before any deployer/sealing/Tor/mTLS work
(DESIGN.md 2.5).

**AMENDED by [ADR-0017](adr/0017-one-external-review-at-stage-9.md):** the external review is NO
LONGER part of this gate. It moved to Rollout stage 9, and leaving it here would deadlock the
ladder — sealing is required to REACH stage 9, so blocking sealing on a stage-9 review makes both
unreachable.
