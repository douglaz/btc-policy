# Concrete protocol schemas (requests, commitment, classes, manifest, config)

Status: accepted 2026-07-15 (spec-hardening pass after the fresh-eyes whole-spec review). Companion to [ADR-0012](0012-model-b-spend-and-duress-architecture.md), which holds the architecture and its rationale; this ADR holds the **implementation contracts** the fresh-eyes review found under-specified. Where an earlier doc (DESIGN.md, CONTEXT.md, TEST-PLAN.md, ADR-0001/0002/0011) states an older shape for any item here, **this ADR + ADR-0012 win**; those docs carry banners. Wire/encoding details are greenfield until v1 (same workspace ships coordinator + nodes).

## 1. Vault descriptor template (fixed, hand-written, rust-miniscript-authoritative)

The vault is a **fixed template, not a policy engine** (resolves the DESIGN "compiled" vs "hand-written" ambiguity — it is **hand-written**, keys substituted at setup; rust-miniscript is *not* used as a runtime policy compiler). Policy:

```
or( and( pk(USER), thresh(t, NODE_1, …, NODE_n) ),          # normal branch
    and( older(TIMELOCK), thresh(2, REC_A, REC_B, REC_C) ) ) # recovery branch
```

- Wrapped `wsh(...)`, P2WSH, SIGHASH_ALL. `t`-of-`n` default **3-of-5**; permitted `n` ∈ [3, 15], `t` ∈ [2, n] (bounded so the witness stays standard). Recovery is fixed **2-of-3**.
- `TIMELOCK` is a **BIP68 relative** `older(...)` value in **512-second units** (not "days"); the **180-day default** = `⌈180·86400 / 512⌉ = 30375` (the descriptor stores the exact integer, never an approximation). This is the recovery-branch relative-lock; it is unrelated to (and must stay ≫) the ~90-day refresh cadence, so a coin is always re-armed well before its recovery branch matures.
- The **canonical descriptor string (with checksum) is frozen in the per-vault manifest** (§4). Every node parses it with rust-miniscript and asserts its own derived descriptor equals the manifest's **byte-for-byte**; a mismatch is a fatal config error, not a refusal. rust-miniscript is authoritative for parsing, satisfaction (witness construction), and branch recognition; the per-node PSBT checks (policy-core) are hand-rolled scriptPubKey re-derivation, **not** miniscript satisfaction.
- Setup **rejects any descriptor outside this template** (exactly one `USER` key on the normal branch, one `thresh` of node keys, one recovery branch of the fixed shape). Key order is canonical (lexicographic by compressed pubkey hex within each `thresh`), origins/derivation-paths required, wildcard `/*` ranged.

## 2. Tagged request schema (resolves "every request has an escape" vs pin-less refresh)

Requests are a **tagged union**, all variants coordinator-authenticated. The coordinator signs `sig = sign(coord_key, canonical_bytes(request))`; nodes reject any request not validly coord-signed and fresh (`nonce` unseen, `expiry` in the future, capped by `max_commitment_age_secs`).

```
SpendRequest  { spend: Psbt, escape: Psbt, pin: Pin, nonce, expiry, policy_version }
RefreshRequest{ refresh: Psbt,             /* no escape, NO pin */ nonce, expiry, policy_version }
```

- **SpendRequest**: both PSBTs user-signed; `escape` mandatory (a missing escape ⇒ reject, closing escape-stripping). The node derives the spend's **class** from its outputs (§3); the pin selects the internal fire decision (ADR-0012 pin-independent ingress). This subsumes the old `{psbt, escape_psbt, pin}` `/sign` body — which had no coord-sig/nonce/expiry and is superseded.
- **RefreshRequest**: `refresh` user-signed, every output pays the vault descriptor (§3); no escape, no pin. Subject to the **minimum refresh interval** and the **tight refresh fee cap** (§6). An implementation must accept this as a first-class variant (not reject it as a malformed SpendRequest).
- Both are node-fanned to **all n** (watchtower recognition + duress propagation ride the same identical per-request path).

## 3. Transaction-class predicate (node-derived, normative)

Computed by each node from the **spend transaction's outputs**, never from a coordinator label (the envelope `spend_purpose` is a non-authoritative hint):

- **escape-class** iff **every** output pays the escape descriptor (bounded index).
- **refresh-class** iff **every** output pays the vault descriptor.
- **hot-class** otherwise (any output to a hot-allowlist descriptor; vault change permitted alongside).
- **Mixed classes are rejected** (`PSBT_INCONSISTENT`). In particular a spend mixing hot + escape outputs is *not* escape-class — it is rejected — closing the 99%-to-hot + dust-to-escape misclassification duress-bypass.

Class → behavior: hot = Hold then sign; escape = complete immediately under either pin (+ duress also schedules lockdown + residual sweep at T); refresh = instant, pin-less, bounded (§6).

## 4. Per-vault manifest (immutable; the root of channel + coord trust)

Written once at setup, hash-pinned, distributed to every node and backed up with the descriptor. Immutable — any change is a new vault.

```
Manifest {
  wallet_id,                       # = hash of the canonical vault descriptor
  vault_descriptor,                # canonical string with checksum (§1)
  policy_version,
  coordinator_auth_pubkey,         # pins the coord auth key (§2, §7)
  nodes: [ { node_id, signing_pubkey, channel_pubkey, transport_endpoints } ],
  t, n, recovery_timelock,
  hot_allowlist: [descriptor…], escape_descriptor,
  config_hash,                     # binds the policy config (§5)
}
manifest_hash = H(canonical_bytes(Manifest))
```

Each node's `channel_pubkey` is **endorsed by that node's Bitcoin signing key** over a domain-separated `(wallet_id, manifest_hash, node_id, channel_pubkey, protocol_version, transport_endpoints)` (ADR-0012 channel identity), so peers accept a channel identity only if a federation signing key vouches for it and the coordinator cannot mint/impersonate a node. The channel key itself is RAM-only, re-derived at startup (ADR-0007); the manifest pins only its public half.

## 5. Policy config schema (per node, immutable; superset of DESIGN's TOML)

Adds the security-load-bearing fields DESIGN's sample omitted. All node-enforced.

```
listen_port, node_seckey (v0 only; T1 removes at-rest keys), descriptor, policy_version,
hot_allowlist = [descriptor…], escape_descriptor,
max_derivation_index, max_commitment_age_secs,
hold_secs,                         # hot-class Hold (default 86400)
max_fee_pct,                       # hot-class fee cap (default 10)
pin_normal_hash, pin_duress_hash,
duress_delay_secs,                 # hostage window; 0 allowed
escape_coverage_pct,               # e.g. 95 — §6
escape_feerate_floor,              # panic feerate floor — §6
epsilon_secs,                      # T-margin ε — §6
refresh_min_interval_secs,         # e.g. 2_592_000 (~30d) — §6
refresh_max_feerate,               # tight refresh fee cap — §6
pin_attempt_budget { max_attempts, window_secs, backoff_schedule, lockout_secs },  # §7
coordinator_auth_pubkey, manifest_hash,
channel { peers: [{node_id, channel_pubkey, endpoints}], per_peer_quota, session_deadline_secs, max_msg_bytes },
[chain_backend] rpc_addr, auth
```

## 6. Precise numeric definitions

- **Coverage**: measured as **Σ input value swept to the escape descriptor** (value leaving the vault into escape), as a fraction of the node's own **confirmed + vault-authorized-unconfirmed** vault balance (ADR-0012 build-over-mempool). Threshold `escape_coverage_pct` (default 95). **Arm keys off coverage of the CONFIRMED set alone** (deterministic — ADR-0012 arm-on-validity); unconfirmed value is a fire-time best-effort add.
  - *Class-aware*: hot-class ⇒ escape supersedes the frozen spend, coverage = escape alone; escape-class ⇒ escape inputs **disjoint** from the completed spend, coverage = (completed escape-class spend ∪ residual escape).
- **Feerate floor** (`escape_feerate_floor`): a **static** sats/vB value in config (not a live estimate — static keeps the arm predicate deterministic across nodes; ADR-0012 defers the live/mempool feerate to fire-time). The fixed-panic-fee rebroadcast loop uses the escape's own (≥ floor) feerate.
- **ε** (`epsilon_secs`): a small bounded margin (default e.g. 60) subtracted in `T = min(first_seen + duress_delay_secs, earliest pending hot Hold-expiry − ε)`, so the escape fires strictly before a frozen spend would settle even under per-node clock skew.
- **Refresh min interval** (`refresh_min_interval_secs`): per-coin minimum time between refreshes (default ~30d). **Refresh fee cap** (`refresh_max_feerate`): a normal feerate (small multiple of the node's estimate), *not* `max_fee_pct` — a legitimate self-spend never pays near 10%.

## 7. Attempt budget (per-node) and coordinator auth-key lifecycle

- **Pin-attempt budget (per-node, ADR-0012)**: each node counts failed pin compares against durable state keyed loosely (not per-request, to bound online guessing); on exceeding `max_attempts` within `window_secs` it applies `backoff_schedule`, then `lockout_secs`. No cross-node accounting. Lockout is *not* Lockdown (it is a transient rate-limit, not the terminal duress state); persisted so a reboot cannot reset it.
- **Coordinator auth-key**: backed up at setup (separately from the descriptor backup; e.g. a sealed offline copy). **Loss with no backup ⇒ the normal path is bricked** (manifest pins the pubkey) → recovery-timelock exit only. **Rotation ⇒ new vault** (immutable manifest); there is no in-place rotation in v0. State this loudly in the ceremony UX.

## Open (tracked to V0-8/V0-4, not blockers here)
Node-channel wire format + combine algorithm (ADR-0011 is a sketch; V0-8a); the fresh-escape-across-the-Hold rebinding rule (a deposit during a hot spend's Hold vs the pre-signed escape's coverage — resubmission may pair the pending spend with a freshly user-signed escape, binding the pair for the Hold); the recovery-path construction + operations (currently outside the V0 task graph — add).
