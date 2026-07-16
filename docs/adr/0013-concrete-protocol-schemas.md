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
- The policy form above is not itself the on-chain script. The **exact `wsh(<typed miniscript>)` string is produced once at setup by a PINNED construction** — compiling the fixed template above with a **pinned rust-miniscript version**, which chooses the concrete `and_v`/`or_*`/`thresh`/`multi` fragments and wrappers deterministically — and that exact string (with checksum) is **frozen in the per-vault manifest** (§4). This is not a *runtime* policy compiler (the compile happens once, at setup, and the output is frozen); "fixed hand-written template" and "compiled once at setup" are the same artifact — the point is the fragment is **pinned and identical for all nodes**, never re-derived per-node. Every node parses the frozen string with the same pinned rust-miniscript and asserts its own derived descriptor equals the manifest's **byte-for-byte**; a mismatch is a fatal config error, not a refusal. rust-miniscript is authoritative for parsing, satisfaction (witness construction), and branch recognition; the per-node PSBT checks (policy-core) are hand-rolled scriptPubKey re-derivation, **not** miniscript satisfaction. The setup reference records the exact fragment string for the default 3-of-5/2-of-3/180d template so it is reproducible.
- Setup **rejects any descriptor outside this template** (exactly one `USER` key on the normal branch, one `thresh` of node keys, one recovery branch of the fixed shape). **Key order is canonical: lexicographic over the full key-EXPRESSION string** (`[origin]xpub.../path/*`, byte-wise on the exact frozen-descriptor substring) within each `thresh` — **NOT** by "compressed pubkey" (2026-07-16 fix: the keys are origin'd ranged xpubs, and derived compressed pubkeys are not stable across derivation indices, so a pubkey-based order is ill-defined and index-dependent). Origins/derivation-paths required, wildcard `/*` ranged. **`node_id` = the node key's 0-based position in this frozen canonical order** — a total, deterministic bijection to descriptor keys that every party (setup and each node) computes identically from the frozen descriptor string alone.

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

Computed by each node from the **spend transaction's outputs**, never from a coordinator label (the envelope `spend_purpose` is a non-authoritative hint). **Vault-change outputs** (outputs paying the vault descriptor) are permitted in every class and are *excluded* from classification; the class is decided by the **destination** (non-vault-change) outputs:

- **refresh-class** iff **every** output pays the vault descriptor (a pure self-spend, no destination output at all).
- **escape-class** iff every *destination* output pays the escape descriptor (vault change allowed alongside).
- **hot-class** iff every *destination* output pays a hot-allowlist descriptor (vault change allowed).
- **Mixed → rejected** (`PSBT_INCONSISTENT`): destination outputs spanning more than one of {hot, escape} — closing the 99%-to-hot + dust-to-escape misclassification duress-bypass — and any destination output matching *no* allowlisted descriptor (that is the ordinary allowlist refusal).
- **A SpendRequest whose spend classifies refresh-class is rejected** (`PSBT_INCONSISTENT`) — a pure self-spend belongs in a pin-less `RefreshRequest` (§2), not a pinned SpendRequest; this removes the "SpendRequest that is really a refresh — honor the pin? ignore it?" ambiguity.

Class → behavior: hot = **sign at ingress, hold the partial, combine + broadcast at Hold expiry** (Model-B sign-at-ingress, ADR-0012 — NOT "Hold then sign"); escape = complete immediately under either pin (+ duress also schedules lockdown + residual sweep at T); refresh = instant, pin-less, bounded (§6).

## 4. Per-vault manifest (immutable; the root of channel + coord trust)

Written once at setup, hash-pinned, distributed to every node and backed up with the descriptor. Immutable — any change is a new vault.

Two-pass, endorsement-free hashing (the `manifest_hash` a channel endorsement
signs cannot itself contain the endorsements):

```
BaseManifest {                     # everything EXCEPT endorsements and config_hash
  wallet_id,                       # = hash of the canonical vault descriptor
  vault_descriptor,                # canonical string with checksum (§1)
  policy_version,
  protocol_version,                # pinned; the channel envelope check compares against this (ADR-0012)
  coordinator_auth_pubkey,         # pins the coord auth key (§2, §7)
  nodes: [ { node_id, signing_pubkey, channel_pubkey, transport_endpoints } ],
  t, n, recovery_timelock,
  hot_allowlist: [descriptor…], escape_descriptor,
}
manifest_hash = H(canonical_bytes(BaseManifest))
# THEN: each node's channel_endorsement is computed OVER manifest_hash and
# attached alongside (never inside BaseManifest). The distributed Manifest =
# BaseManifest + { node_id → channel_endorsement }.
```

**`config_hash` is NOT in `BaseManifest`** (2026-07-16 fix — it would form a
cycle: the §5 config binds `manifest_hash`, so a `config_hash` inside the
manifest is uncomputable). The config→manifest binding is one-directional: the
§5 config carries `manifest_hash`, and sealing (ADR-0005) provisions both
together; `node_id` = the node's 0-based position in the descriptor's canonical
key order (§1).

Each node's `channel_pubkey` is **endorsed by that node's Bitcoin signing key** over a domain-separated `(wallet_id, manifest_hash, node_id, channel_pubkey, protocol_version, transport_endpoints)` (ADR-0012 channel identity), so peers accept a channel identity only if a federation signing key vouches for it and the coordinator cannot mint/impersonate a node. The channel key itself is RAM-only, re-derived at startup (ADR-0007); the manifest pins only its public half. `node_id` = the node's 0-based index in the descriptor's canonical (lexicographic) node-key order — derivable from the descriptor, so the node_id → descriptor-key mapping is definitionally total (2026-07-16). **Endpoints are deliberately pinned** (anti-redirection: nobody, including a compromised coordinator or a later config writer, can repoint one node's view of a peer): v0 endpoints are localhost and never change; **v1 onion addresses must be derived deterministically from node key material** — like the channel key — so they are known at the setup ceremony and stable for the node's lifetime; clearnet dynamic-IP topologies are unsupported by design (2026-07-16).

**Trust establishment (the root — re-review: this was undefined).** The manifest is not *signed* by an external authority; it is **agreed at the setup ceremony** and then frozen. Concretely: setup collects each node's signing pubkey + channel-key endorsement and the coordinator auth pubkey, assembles the `Manifest`, computes `manifest_hash`, and **provisions every node with that exact `manifest_hash`** as sealed config (ADR-0005 sealing). Thereafter a node trusts the coordinator auth key **because** its pubkey is in the manifest whose hash the node was sealed with, and trusts a peer channel identity **because** it is endorsed by a signing key in that same manifest. The manifest_hash is the single root every other trust decision chains to; it is included in the config (`manifest_hash`, §5) and in every channel endorsement's domain separator, so a manifest from a different vault cannot be substituted. Backed up alongside the descriptor (public-ish; needed to reconstruct/verify, not secret).

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
channel { peers: [{node_id, signing_pubkey, channel_pubkey, channel_endorsement, endpoints}], per_peer_quota, per_send_deadline_secs, max_msg_bytes },   # v0-provisional to V0-9; NO session (per-message signed envelopes) — hence per-send, not session, deadline (2026-07-16)
[chain_backend] rpc_addr, auth
```

## 6. Precise numeric definitions

- **Coverage**: measured as **Σ OUTPUT value paying the escape descriptor** — what actually *lands in the escape wallet*, NOT input value (re-review fix: input-value coverage would let a hostile-at-wrench coordinator pass a 95%-of-inputs escape that burns most of it to fee and delivers little to escape). As a fraction of the node's own **confirmed + vault-authorized-unconfirmed** vault balance (ADR-0012 build-over-mempool). Threshold `escape_coverage_pct` (default 95). Measuring on *outputs* **implicitly caps the escape fee** at `(100 − escape_coverage_pct)%` of the swept value (since Σescape-outputs + fee = Σinputs), so no separate escape fee-ceiling is needed — the ≥95% output-coverage IS the ≤5% fee cap. **Coverage is NOT an arm gate** (ADR-0012 arm-on-duress-pin-alone); it is a **fire-time** check that only determines whether the sweep succeeds. Any escape rejected on coverage still leaves the node frozen + locked down at T (funds → recovery).
  - *Class-aware*: hot-class ⇒ escape supersedes the frozen spend, coverage = escape alone; escape-class ⇒ escape inputs **disjoint** from the completed spend, coverage = (completed escape-class spend ∪ residual escape).
- **Feerate floor** (`escape_feerate_floor`): a **static** sats/vB value in config (not a live estimate — static keeps **fire-time sweep admissibility** deterministic across nodes so the sweep doesn't split; ADR-0012 makes feerate a **fire-time sweep check, never an arm gate**). The fixed-panic-fee rebroadcast loop uses the escape's own (≥ floor) feerate.
- **ε** (`epsilon_secs`): a small bounded margin (default e.g. 60) subtracted in `T = min(first_seen + duress_delay_secs, earliest pending hot Hold-expiry − ε)`, so the escape fires strictly before a frozen spend would settle even under per-node clock skew.
- **Refresh min interval** (`refresh_min_interval_secs`): per-coin minimum time between refreshes (default ~30d). **Refresh fee cap** (`refresh_max_feerate`): a normal feerate (small multiple of the node's estimate), *not* `max_fee_pct` — a legitimate self-spend never pays near 10%.

## 7. Attempt budget (per-node) and coordinator auth-key lifecycle

- **Pin-attempt budget (per-node, ADR-0012)**: each node counts failed pin compares in RAMDISK/node-lifetime state keyed loosely (not per-request, to bound online guessing); on exceeding `max_attempts` within `window_secs` it applies `backoff_schedule`, then `lockout_secs`. No cross-node accounting. Lockout is *not* Lockdown (it is a transient rate-limit, not the terminal duress state). **Not durable across reboot, and it does not need to be** (reboot-death/tmpfs, ADR-0007, 2026-07-16): a reboot wipes the whole installed system including the signing key, so it cannot be used to reset the budget while retaining the ability to sign guesses — the rebooted machine is bare, not a fresh-budget signer.
- **Coordinator auth-key**: backed up at setup (separately from the descriptor backup; e.g. a sealed offline copy). **Loss with no backup ⇒ the normal path is bricked** (manifest pins the pubkey) → recovery-timelock exit only. **Rotation ⇒ new vault** (immutable manifest); there is no in-place rotation in v0. State this loudly in the ceremony UX.

## Open (tracked to V0-8/V0-4, not blockers here)
Node-channel wire format + combine algorithm (ADR-0011 is a sketch; V0-8a); the fresh-escape-across-the-Hold rebinding rule (a deposit during a hot spend's Hold vs the pre-signed escape's coverage) — **this item is currently self-contradictory and must be resolved in V0-4**: it previously proposed rebinding via **re-submission** (pairing the pending spend with a freshly user-signed escape for the Hold), but the Model-B Hold lifecycle **removed re-submission** (sign once at ingress — ADR-0012), so any rebinding mechanism must be **sign-at-ingress-compatible**; the funds-safe fallback if none is adopted is that **a deposit arriving during a hot spend's Hold is a straggler → recovery** (swept by the next escape / recoverable via the timelock). The recovery-path construction + operations (currently outside the V0 task graph — add).
