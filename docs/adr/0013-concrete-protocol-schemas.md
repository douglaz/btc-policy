# Concrete protocol schemas (requests, commitment, classes, manifest, config)

Status: accepted 2026-07-15 (spec-hardening pass after the fresh-eyes whole-spec review). Companion to [ADR-0012](0012-model-b-spend-and-duress-architecture.md), which holds the architecture and its rationale; this ADR holds the **implementation contracts** the fresh-eyes review found under-specified. Where an earlier doc (DESIGN.md, CONTEXT.md, TEST-PLAN.md, ADR-0001/0002/0011) states an older shape for any item here, **this ADR + ADR-0012 win**; those docs carry banners. Wire/encoding details are greenfield until v1 (same workspace ships coordinator + nodes).

## 1. Vault descriptor template (fixed, hand-written, rust-miniscript-authoritative)

The vault is a **fixed template, not a policy engine** (resolves the DESIGN "compiled" vs "hand-written" ambiguity — it is **hand-written**, keys substituted at setup; rust-miniscript is *not* used as a runtime policy compiler). Policy:

```
or( and( pk(USER), thresh(t, NODE_1, …, NODE_n) ),          # normal branch
    and( older(TIMELOCK), thresh(2, REC_A, REC_B, REC_C) ) ) # recovery branch
```

- Wrapped `wsh(...)`, P2WSH, SIGHASH_ALL. `t`-of-`n` default **3-of-5**; permitted `n` ∈ [3, 15], `t` ∈ [2, n] (bounded so the witness stays standard), and — for any vault provisioned with the `[channel]` block, i.e. every production vault — additionally **exactly `n = 2t − 1`** (so `n` is odd and `t = (n+1)/2`; the permitted channel-mode shapes are 2-of-3, 3-of-5, 4-of-7, … up to 8-of-15). Recovery is fixed **2-of-3**. *(**2026-07-19, V0-4b §0; tightened from the `2t > n` first draft.** The exact-shape rule is new and narrows the earlier `t ∈ [2, n]`. It is the conjunction of TWO requirements, and only stating both gives the right constraint. **(a) No unfrozen signing quorum outside an armed set** — confirmation-gated arming admits a carrier through a PIN-INDEPENDENT delivery-horizon gate evaluated against each node's own clock, so at the boundary a subset may admit and arm while the rest refuse before recording an intent; without quorum intersection the unarmed complement can itself sign, e.g. a 2-of-5 vault where two nodes arm leaves three unfrozen nodes able to finalize a pending coerced hot spend. That requirement alone gives `2t > n`. **(b) Tolerate every minority smaller than `t` withholding propagation** — a compromised node can process a carrier and simply not relay it, and `spawn_fan_out` carries no acknowledgement back, so the honest remainder must still reach `t` by itself: `n − (t − 1) ≥ t`. That gives `2t ≤ n + 1`. Together, `n = 2t − 1` exactly. Merely intersecting shapes fail (b): in 4-of-5, three withholding nodes leave the two honest nodes below the arm threshold while those same three plus one honest partial can finalize the coerced spend. `Node::from_toml_str` enforces the exact shape as a fatal config error; the descriptor is immutable, so a vault sealed at any other shape cannot be migrated in place — it must be re-provisioned. Channel-less fixtures are exempt (no peers, no confirmation path, so they can never arm).)*
- `TIMELOCK` is a **BIP68 relative TIME-based** lock. The 180-day default is `⌈180·86400 / 512⌉ = 30375` **units of 512 seconds**, but the miniscript `older(n)` argument is the **RAW consensus `nSequence`** with the BIP68 type-flag (bit 22) set — rust-miniscript does NOT add the flag: `n = 30375 | (1 << 22) = 4224679 = 0x004076a7` (2026-07-17 correction). So the frozen descriptor contains **`older(4224679)`** (construct via `Sequence::from_512_second_intervals(30375)`); `older(30375)` would be a 30375-BLOCK height lock — the wrong policy. This is the recovery-branch relative-lock; it is unrelated to (and must stay ≫) the ~90-day refresh cadence, so a coin is always re-armed well before its recovery branch matures.
- The policy form above is not itself the on-chain script. The **exact `wsh(<typed miniscript>)` string is produced once at setup by a PINNED construction** — compiling the fixed template above with a **pinned rust-miniscript version**, which chooses the concrete `and_v`/`or_*`/`thresh`/`multi` fragments and wrappers deterministically — and that exact string (with checksum) is **frozen in the per-vault manifest** (§4). This is not a *runtime* policy compiler (the compile happens once, at setup, and the output is frozen); "fixed hand-written template" and "compiled once at setup" are the same artifact — the point is the fragment is **pinned and identical for all nodes**, never re-derived per-node. Every node parses the frozen string with the same pinned rust-miniscript and asserts its own derived descriptor equals the manifest's **byte-for-byte**; a mismatch is a fatal config error, not a refusal. rust-miniscript is authoritative for parsing, satisfaction (witness construction), and branch recognition; the per-node PSBT checks (policy-core) are hand-rolled scriptPubKey re-derivation, **not** miniscript satisfaction. The setup reference records the exact fragment string for the default 3-of-5/2-of-3/180d template so it is reproducible.
- Setup **rejects any descriptor outside this template** (exactly one `USER` key on the normal branch, one `thresh` of node keys, one recovery branch of the fixed shape). **Key order is canonical: lexicographic over the full key-EXPRESSION string** (`[origin]xpub.../path/*`, byte-wise on the exact frozen-descriptor substring) within each `thresh` — **NOT** by "compressed pubkey" (2026-07-16 fix: the keys are origin'd ranged xpubs, and derived compressed pubkeys are not stable across derivation indices, so a pubkey-based order is ill-defined and index-dependent). **`node_id` = the node key's 0-based position in this frozen canonical order** — a total, deterministic bijection to descriptor keys that every party (setup and each node) computes identically from the frozen descriptor string alone.

  *(**REVISED 2026-07-25, bead btc-policy-9y5.5 — the VAULT descriptor is DEFINITE.** The original text ended "Origins/derivation-paths required, wildcard `/*` ranged", i.e. production vault keys were to be origin'd ranged xpubs. That is now **rejected at template parse**: every vault key — user, node, recovery — is exactly ONE concrete compressed pubkey, in production as in the regtest demo. `policy_core::parse_vault_template` refuses any key with a derivation path, so setup cannot seal such a vault and no node can be handed one. Three reasons, in the order they bite. (1) **It never worked.** Every node parses the frozen descriptor as a concrete `Descriptor<PublicKey>` at startup — for the witness script, the user key, and the sighash — so a ranged vault descriptor does not load at all; accepting one at setup would seal a vault no node can ever boot against, which under static-policy-forever + sealed hosts is a permanent, unfixable brick. (2) **There is nothing left for a range to express.** The setup ceremony (§4, and `btc-vault setup node-keygen`) has each node birth ONE key on its own host; a node does not have an xpub range to publish. (3) **It removes the caveat this very paragraph was written for.** The "lexicographic over the key-EXPRESSION string, NOT by compressed pubkey" rule exists because derived pubkeys of a ranged key are index-dependent and so ill-defined as an ordering. With definite keys the expression IS the pubkey, so the canonical order is well-defined with no index to disambiguate — the rule above still holds verbatim, it just no longer has a trap under it. **This is the vault descriptor ONLY.** The destination allowlist wallets — hot and escape — stay ranged, origin'd, and bounded by `max_derivation_index`; they legitimately derive a fresh address per spend, and nothing here touches them.)*

## 2. Tagged request schema (resolves "every request has an escape" vs pin-less refresh)

Requests are a **tagged union**, all variants coordinator-authenticated. The coordinator signs `sig = sign(coord_key, tagged_hash(COORD_REQUEST_TAG, wallet_id ‖ canonical_bytes(request)))`; nodes reject any request not validly coord-signed and fresh (`nonce` unseen, `expiry` in the future, capped by `max_commitment_age_secs`). **`wallet_id` is a signing DOMAIN SEPARATOR bound into the digest but NEVER transmitted** (holistic v0 audit H2, 2026-07-22): the coordinator supplies its vault's `wallet_id = H(canonical descriptor)`, each node verifies against its own, so a coordinator signature is valid ONLY at nodes of the same vault — a coordinator-auth key reused across two vaults cannot authorize a request cross-vault (defense in depth; the per-node input-ownership check refuses it too).

```
SpendRequest  { spend: Psbt, escape: Psbt, escape_bumps: [Psbt], pin: Pin, nonce, expiry, policy_version }
RefreshRequest{ refresh: Psbt,             /* no escape, NO pin */ nonce, expiry, policy_version }
```

- **SpendRequest**: both PSBTs user-signed; `escape` mandatory (a missing escape ⇒ reject, closing escape-stripping). `escape_bumps` (bead btc-policy-9y5.7) is the escape's OPTIONAL **fee-bump ladder**: 0..=3 additional user-signed escape variants, ascending by fee, from which the Firing job picks the rung it broadcasts at `T` (§6). Empty is the pre-9y5.7 shape and is omitted from the JSON body entirely (so a request that never bumps carries no new field); the coordinator-auth PREIMAGE still writes the ladder's length unconditionally, so a ladder-less request's digest differs from a pre-9y5.7 one — coordinator signatures are not cross-version compatible, and a vault is sealed to one coordinator and one policy version anyway. Each rung is validated and signed at ingress exactly as `escape` is — pin-independent, both PINs identical — and must spend the SAME inputs in the same order, pay the SAME output scripts in the same order (a bump changes the fee, never what is swept), pay a strictly higher fee than the rung below it, and carry `nSequence = 0xfffffffd` with `nLockTime == 0` on the whole ladder including the base. A ladder on a SELF-PAIRED request is rejected — note self-pairing is NOT the shape of a valid escape-class spend, which must carry a DISTINCT, DISJOINT residual Escape (`escape_class_residual` refuses the equal-commitment shape outright); a refresh is not self-paired either — a `RefreshRequest` carries a SINGLE PSBT, no Escape and no ladder, and never reaches `ensure_escape_ladder`; `register_pair` collapses it to one candidate internally, which is an implementation detail of registration, not a request shape. The ladder is inside the coordinator-auth preimage — the length AND every rung's full bytes, each length-prefixed (`CoordRequest::canonical_bytes`), so neither a drop nor a same-count substitution survives — meaning a relay WITHOUT the auth key can neither append nor drop a rung — but the Coordinator itself holds that key, so post-wrench it can drop rungs and re-sign the shortened request; this is not an integrity guarantee against the actor that matters (ADR-0016). The node derives the spend's **class** from its outputs (§3); the pin selects the internal fire decision (ADR-0012 pin-independent ingress). This subsumes the old `{psbt, escape_psbt, pin}` `/sign` body — which had no coord-sig/nonce/expiry and is superseded.
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
  protocol_version,                # MANIFEST SCHEMA REVISION (2), not transport v1; the channel
                                   # envelope check compares against this same pinned value.
                                   # Node configs declare it and a startup preflight reads it
                                   # BEFORE the current schema, so an old manifest fails as a
                                   # version error rather than a missing field or a hash mismatch.
  coordinator_auth_pubkey,         # pins the coord auth key (§2, §7)
  nodes: [ { node_id, signing_pubkey, channel_pubkey, transport_endpoints } ],
  t, n, recovery_timelock,
  max_msg_bytes,                   # V0-4b §0 — see below; federation-UNIFORM
  hot_max_per_tx, hot_max_per_window, hot_window_secs,  # ADR-0014 Hot budget — see below; federation-UNIFORM
  hot_allowlist: [descriptor…], escape_descriptor, max_derivation_index,
  escape_feerate_floor, escape_coverage_pct, escape_bump_max_fee_pct,
  network,                         # the sealed vault chain: bitcoin | signet | regtest
}
manifest_hash = H(canonical_bytes(BaseManifest))
# canonical_bytes preimage — REVISION 2 AUTHORITATIVE (vault-node `base_manifest_bytes`);
# reimplement from THIS list + order, NOT a naive serialization of every field above:
#   `escape_bump_max_fee_pct` (u8) landed in the preimage with `protocol_version = 1`, in the one
#   change ADR-0016 §3a requires: appending it moves `manifest_hash` for otherwise-identical
#   inputs, so shipping it while still declaring 0 would produce exactly the opaque hash mismatch
#   §3a exists to prevent. `network` (u8) landed the same way at `protocol_version = 2` and is
#   now the final field before the node count. Its codes are EXPLICIT — 1 bitcoin, 2 default
#   PUBLIC signet, 3 regtest — never an enum ordinal: rust-bitcoin inserted `Testnet4` mid-enum,
#   which would have renumbered signet and regtest and moved every sealed vault's hash.
#   EVERY variable-length run is LENGTH-PREFIXED u32. Both counts below were missing from earlier
#   drafts of this list; omitting either yields a different hash and WRONG_MANIFEST on every node.
#   docs/PROTOCOL-VECTORS.md encodes this SAME contract with a worked byte vector and had both
#   counts right while this list did not. The two MUST agree; if they ever diverge again, the
#   vector wins, because it is executable against the code.
#   wallet_id ‖ protocol_version(u32) ‖ coordinator_auth_pubkey ‖ max_msg_bytes(u64)
#   ‖ hot_max_per_tx(u64) ‖ hot_max_per_window(u64) ‖ hot_window_secs(u64)
#   ‖ hot_allowlist(u32 COUNT ‖ each descriptor, sorted+deduped)
#   ‖ escape_descriptor ‖ max_derivation_index(u32) ‖ escape_feerate_floor(u64)
#   ‖ escape_coverage_pct(u8) ‖ escape_bump_max_fee_pct(u8) ‖ network(u8)
#   ‖ nodes(u32 COUNT ‖ [ node_id(u16), signing_pubkey(33B compressed SEC1),
#     channel_pubkey(33B compressed SEC1), endpoints(u32 COUNT ‖ each u32-len-prefixed UTF-8) ]…)
# NOT serialized separately (bound TRANSITIVELY via wallet_id = H(canonical descriptor)):
#   vault_descriptor, t, n, recovery_timelock. NOT manifest-pinned at all: policy_version — it is
#   enforced per-request (commitment + request.policy_version), so it is absent from the preimage.
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

**`max_msg_bytes` IS in `BaseManifest`** (2026-07-19, V0-4b §0 — new preimage
field). It is also a `[channel]` config knob (§5), but confirmation-gated arming
needs "this carrier is deliverable to ME" to imply "deliverable to EVERY peer": a
hostile-at-wrench coordinator could otherwise size a duress carrier to fit the
node it delivers to while exceeding a peer's heterogeneous cap, so the peer
rejects it, t-confirmation becomes reachable at some nodes and not others, and the
arm splits. Hashing the cap into the manifest makes disagreement a **startup**
failure rather than a runtime split: a node whose configured `max_msg_bytes`
differs computes a different `manifest_hash`, fails its sealed
`expected_manifest_hash` check, and is rejected as `WRONG_MANIFEST` by every peer.
At run time the value is therefore provably identical federation-wide. Note this
CHANGES `manifest_hash` for a given federation — a vault sealed under the earlier
preimage does not load against this build and must be re-provisioned (greenfield
until v1; the workspace ships both ends together).

**The `Hot budget` triple IS in `BaseManifest`** (2026-07-20, [ADR-0014](0014-hot-spend-bound.md)
§6 — three new preimage fields, encoded as three `u64`s immediately after
`max_msg_bytes` and before the node count, so the V0-9 prefix keeps its byte
offsets). `hot_max_per_tx`, `hot_max_per_window`, and `hot_window_secs` are also
`[channel]`-adjacent config knobs (§5), and they are hashed here for the same
reason `max_msg_bytes` is: a federation-uniform cap is only as strong as its
laxest node. If one node's `hot_max_per_window` exceeded its peers', a coordinator
would simply route coerced hot spends at that node's rate, and ADR-0014's routing
bound would not hold. With `c < t` compromised signer Nodes able to bypass their
ledgers, the bound is `((n−c)/(t−c))·V`; manifest uniformity proves that every honest
signer in that argument reserves against the *same* `V`. Hashing all three makes
disagreement a **startup** failure rather than a silently weaker vault, by exactly
the mechanism above. This likewise CHANGES `manifest_hash` for a given federation.
The canonical hot-allowlist descriptors, escape descriptor, and
`max_derivation_index` are hashed beside the triple: they decide whether a given
output consumes the cap, so uniform numbers with non-uniform classification inputs
would still be a non-uniform budget.

Each node's `channel_pubkey` is **endorsed by that node's Bitcoin signing key** over a domain-separated `(wallet_id, manifest_hash, node_id, channel_pubkey, protocol_version, transport_endpoints)` (ADR-0012 channel identity), so peers accept a channel identity only if a federation signing key vouches for it and the coordinator cannot mint/impersonate a node. The channel key itself is RAM-only, re-derived at startup (ADR-0007); the manifest pins only its public half. `node_id` = the node's 0-based index in the descriptor's canonical (lexicographic) node-key order — derivable from the descriptor, so the node_id → descriptor-key mapping is definitionally total (2026-07-16). **Endpoints are deliberately pinned** (anti-redirection: nobody, including a compromised coordinator or a later config writer, can repoint one node's view of a peer): v0 endpoints are localhost and never change; **v1 onion addresses must be derived deterministically from node key material** — like the channel key — so they are known at the setup ceremony and stable for the node's lifetime; clearnet dynamic-IP topologies are unsupported by design (2026-07-16).

**Trust establishment (the root — re-review: this was undefined).** The manifest is not *signed* by an external authority; it is **agreed at the setup ceremony** and then frozen. Concretely: setup collects each node's signing pubkey + channel-key endorsement and the coordinator auth pubkey, assembles the `Manifest`, computes `manifest_hash`, and **provisions every node with that exact `manifest_hash`** as sealed config (ADR-0005 sealing). Thereafter a node trusts the coordinator auth key **because** its pubkey is in the manifest whose hash the node was sealed with, and trusts a peer channel identity **because** it is endorsed by a signing key in that same manifest. The manifest_hash is the single root every other trust decision chains to; it is included in the config (`manifest_hash`, §5) and in every channel endorsement's domain separator, so a manifest from a different vault cannot be substituted. Backed up alongside the descriptor (public-ish; needed to reconstruct/verify, not secret).

## 5. Policy config schema (per node, immutable; superset of DESIGN's TOML)

Adds the security-load-bearing fields DESIGN's sample omitted. All node-enforced.

```
listen_port, node_key_salt + node_key_ops + node_key_mem_kib (the PUBLIC wskdf derivation; NO key at rest — see below), descriptor, policy_version,
hot_allowlist = [descriptor…], escape_descriptor,
                                   # their extended-key FLAVOUR is bound to `network` below: main-kind (`xpub`) for `bitcoin`, test-kind (`tpub`) for signet and regtest — that two-valued kind is all an extended key encodes, so signet-vs-regtest stays the backend chain/challenge check rather than a prefix. ONE validator states the relation (`policy_core::check_descriptor_network_kind`), and setup's `assemble`, setup's `finalize` and this node's load each run it INDEPENDENTLY, because a matching `manifest_hash` proves the federation received identical strings and never that the two agree. It is NOT a preimage field and adds no byte: a revision-2 set whose flavour disagrees is REFUSED rather than re-hashed, and the remedy is a new ceremony (bead btc-policy-descriptor-network-kind-x00)
max_derivation_index, max_commitment_age_secs,
hold_secs,                         # hot-class Hold (default 86400)
# NO fee-cap field. The 10% guard is `MAX_FEE_PERCENT`, a const in policy-core applying to ALL classes (ADR-0006) — it was listed here as `max_fee_pct` while DESIGN's sample still had one, but `ConfigFile` is `#[serde(deny_unknown_fields)]`, so a config written from this schema carrying that key is a FATAL startup error. A fee cap that is not configurable cannot be made non-uniform by a config writer, which is why it needs no manifest pin either.
hot_max_per_tx, hot_max_per_window, hot_window_secs,  # ADR-0014 Hot budget. MANDATORY, no defaults, all three ALSO manifest preimage fields (§4) — a default would silently restore unbounded hot outflow for a config that forgot the field, and a non-uniform cap is only as strong as the laxest node. `hot_max_per_tx` (sats) caps ONE hot spend's outflow (Σ outputs to non-vault, non-escape destinations; fee excluded — it pays miners, not the coercer, and the 10% guard already bounds it) and is enforced in policy-core's pure `evaluate` as `HOT_BUDGET_EXCEEDED`. `hot_max_per_window` (sats) caps the SUM of hot outflow this node has ACCEPTED within `hot_window_secs`, pending AND broadcast, and is enforced by vault-node's `HotBudgetLedger` at ingress BEFORE signing as `HOT_VELOCITY_EXCEEDED` — so an over-cap coerced spend yields no partial anywhere. Both are needed: a per-tx cap alone is unbounded in the NUMBER of spends, a window cap alone lets one spend take the whole window. `hot_window_secs` must satisfy `hot_window_secs ≥ max_commitment_age_secs` (fatal at load, sibling to `hold_secs < max_commitment_age_secs`): a window shorter than the commitment lifetime lets a reservation age out while its spend can still combine and broadcast, and the aggregate bound stops binding. Both checks are amount-based and PIN-INDEPENDENT — they never read the pin, so ADR-0012's constant-observable ingress survives and an over-cap duress carrier still stages, arms, and propagates on the refusal path (the freeze fires federation-wide; the coerced spend just cannot complete)
pin_normal_hash, pin_duress_hash,
duress_delay_secs,                 # hostage window; 0 allowed
escape_coverage_pct,               # e.g. 95 — §6
escape_feerate_floor,              # panic feerate floor — §6
protocol_version,                  # the manifest schema revision this config was written for. MANDATORY, no default: a startup preflight reads it before the rest of the schema, so a config written for an older revision fails as a version error instead of a missing field or a `manifest_hash` mismatch (ADR-0016 §3a). Validated against the pinned const and then never stored — the const is the one runtime version source
escape_bump_max_fee_pct,           # the sealed escape-ladder ceiling (ADR-0016 §2). MANDATORY, no default, and ALSO a manifest preimage field (§4). The no-default rule here is for DIAGNOSTIC CLARITY, and it is NOT the ADR-0014 Hot-budget reason: a defaulted ceiling would NOT boot against a manifest sealed to a different one, because `ChannelState::build` would hash the default and fail the sealed anchor — which is exactly what `escape_coverage_pct`/`escape_feerate_floor` do, and those two DO carry serde defaults. What no-default buys is that an omitted field is reported as an omitted field instead of as an opaque `manifest_hash` mismatch. Nodes never ENFORCE it (ADR-0016 §4a) — the ceremony bounds it and the signer checks composed ladders against it; the node only proves it federation-uniform
network,                           # the sealed vault chain, as one of exactly `bitcoin`, `signet` (the DEFAULT PUBLIC signet) or `regtest`. MANDATORY, no default, and ALSO a manifest preimage field (§4): a defaulted network would let a config that never names a chain boot against whichever one the default happened to be. Parsed ONCE here into `bitcoin::Network`; no other spelling exists in runtime state. Testnet3, testnet4, aliases (`main`) and custom signets are refused with the allowed set. It is also compared against the backend's own `getblockchaininfo` chain identity — and, on signet, its `signet_challenge` — before the node serves anything
epsilon_secs,                      # T-margin ε — §6
delivery_horizon_secs,             # V0-4b §0 pre-PIN carrier margin: a SpendRequest is refused (EXPIRY_TOO_SHORT / check `delivery_horizon`) unless `expiry ≥ now + delivery_horizon_secs`, so a carrier this node accepts can still reach and be processed by every peer before it lapses. Default 60; must satisfy `1 ≤ delivery_horizon_secs < max_commitment_age_secs`. Per-node (NOT a manifest field, unlike `max_msg_bytes`): a heterogeneous horizon — or the same horizon read off slightly different clocks — can remove nodes before they record an intent, so the admitting set may be a proper subset of the honest nodes that saw the carrier. Theft safety there does NOT come from counting admitters (a receipt authenticates its SENDER, never that the sender processed anything, so the tolerated `t − 1` compromised nodes can always emit `t − 1` of them); it comes from the fact that this refusal, like `EXPIRY_TOO_SHORT`, still fans the carrier out. Every node that signs and every node that refuses on its own clock forwards it, so each honest signer counts the whole honest set that saw the carrier: either that set reaches `t` and they all freeze — leaving only the `≤ t − 1` compromised partials, below quorum — or fewer than `t` nodes ever signed and no quorum of partials exists. `n = 2t − 1` (§1) is what guarantees `t` honest nodes remain after every tolerated withholder. A proper subset of honest nodes arming is still possible (an admitter plus forged receipts); that is fund-identical to the coordinator's accepted censorship and lands on the two-track residual — Lockdown at `T` → recovery, never theft. Skipped entirely in absent-channel mode, like the `max_msg_bytes` precondition — no peers, nothing to protect, and the `1 ≤ delivery_horizon_secs < max_commitment_age_secs` bound is likewise not enforced at startup there
refresh_min_interval_secs,         # e.g. 2_592_000 (~30d) — §6
refresh_max_feerate,               # tight refresh fee cap — §6
pin_attempt_budget { max_attempts, window_secs, backoff_schedule, lockout_secs },  # §7
coordinator_auth_pubkey, manifest_hash,
[channel] {                        # OPTIONAL block (2026-07-16 codex audit): ABSENT ⇒ absent-channel mode — /channel not mounted, no manifest/bijection/endorsement invariants run, node behaves as pre-channel (so `demo first-light`, which does not use the channel, passes channel-less WITHOUT editing the demo). PRESENT ⇒ all invariants apply and /channel is mounted. v0-provisional to V0-9. NO session (per-message signed envelopes) — per-send, not session, deadline.
  node_id,                         # this node's id
  nodes: [{node_id, signing_pubkey, channel_pubkey, channel_endorsement, endpoints}],  # FULL membership, all n, INCLUDING self (manifest hash needs all n; self-inclusion removes "does peers contain me?"). `endpoints` is plural (a node may advertise clearnet + onion) — matches the endorsement/manifest `transport_endpoints`; the config field is the same plural list, not a singular `endpoint`.
  max_active_candidates,           # default 1024
  max_candidate_store_bytes,       # default 67_108_864 (64 MiB)
  per_peer_quota_per_min,          # default 600
  max_concurrent_channel_requests, # pre-auth global bound, default 64
  max_msg_bytes,                   # default 1_048_576 (1 MiB)
  max_response_bytes,              # outbound read bound, default 65_536
  per_send_deadline_secs },        # default 5
[chain_backend] rpc_addr, auth
```

**No signing key at rest** (2026-07-25, bead btc-policy-9y5.5 — this REPLACES the
`node_seckey` field, which carried a hex secret key and was marked "v0 only; T1
removes at-rest keys"). The config now names the DERIVATION and never the secret:
`node_key_salt`, `node_key_ops`, and `node_key_mem_kib` are the public parameters
of a wskdf (Argon2id) pass, and the node derives its federation signing key in RAM
at startup from them plus an **operator-held preimage read from stdin**. The
preimage is generated ON THE NODE by `btc-vault setup node-keygen`, printed once
for the operator to carry, and never written by the daemon. Fail-closed: the
derived key must be one of the frozen descriptor's federation node keys, or
startup is a fatal error — a node holding a key no descriptor names would validate
and "sign" every request while producing partials that can never combine.

This also RESOLVES ADR-0005's open note that "sealing conflicts with in-memory
wskdf keys on reboot (no SSH to re-enter the preimage)". There is no reboot to
re-enter anything for: under ADR-0007 a node starts exactly once in its life, at
provisioning, before the host is sealed. A reboot leaves a bare machine — no
config, no key, and no way to ask for a preimage — which is node death, as
intended. The preimage's entropy is wskdf's maximum (63 bits) precisely because
recovery is NOT wanted here: a lost preimage is a dead node, the federation
absorbs it, and capacity is restored by rotating to a successor vault.

**`expected_manifest_hash` is MANDATORY** (same bead). It was optional and enforced
only when present, so a hand-written config could omit the immutable federation
anchor entirely and boot with no cross-check that the federation ever agreed to its
coordinator key, membership, `max_msg_bytes`, or Hot budget. An absent hash is now a
fatal startup error. (Such a node could never talk to correctly-sealed peers — they
answer `WRONG_MANIFEST` — but that is a liveness symptom found at run time by
whoever is watching, and it says nothing at all in a federation whose configs were
ALL written without the anchor.)

## 6. Precise numeric definitions

- **Coverage**: measured as **Σ OUTPUT value paying the escape descriptor** — what actually *lands in the escape wallet*, NOT input value (re-review fix: input-value coverage would let a hostile-at-wrench coordinator pass a 95%-of-inputs escape that burns most of it to fee and delivers little to escape). As a fraction of the node's own **confirmed + vault-authorized-unconfirmed** vault balance (ADR-0012 build-over-mempool). Threshold `escape_coverage_pct` (default 95). For a full protected-set escape, conservation is `Σescape-outputs + Σvault-change-outputs + fee = Σinputs`; because the escape outputs themselves must be at least `escape_coverage_pct` of that protected input value, change plus fee together are at most `(100 − escape_coverage_pct)%`, and fee alone is no larger. Thus the default ≥95% escape-output coverage implies a ≤5% fee cap without pretending vault change is absent. **Coverage is NOT an arm gate** (ADR-0012: the arm VERDICT is the duress pin alone, and the arm COMMIT is t-of-n carrier confirmation — neither consults the chain); it is a **fire-time** check that only determines whether the sweep succeeds. Any escape rejected on coverage still leaves the node frozen + locked down at T (funds → recovery). ADR-0012's named stage-1 composer narrowing does not alter this denominator and is blocked from the release freeze by `btc-policy-w2b`.
  Finite confirmed-parent/UTXO-fragmentation handling is separately blocked from the same release freeze by `btc-policy-yw4`; neither follow-up may weaken this denominator.
  - *Class-aware*: hot-class ⇒ escape supersedes the frozen spend, coverage = escape alone; escape-class ⇒ escape inputs **disjoint** from the completed spend, coverage = (completed escape-class spend ∪ residual escape).
- **Feerate floor** (`escape_feerate_floor`): a **static** sats/vB value in config (not a live estimate — static keeps **fire-time sweep admissibility** deterministic across nodes so the sweep doesn't split; ADR-0012 makes feerate a **fire-time sweep check, never an arm gate**). The rebroadcast loop uses the escape's own (≥ floor) feerate.
- **Bump target** (bead btc-policy-9y5.7, no config knob): when the request carried an `escape_bumps` ladder (§2), the Firing job fires the CHEAPEST rung whose feerate — measured at the rung's MAXIMUM finalized vsize, so it still holds once the missing signatures land — reaches `max(bump target, escape_feerate_floor)`; clamps that choice to the highest rung the coverage guard admits, so a bump can never cross the ≤5% fee cap; and raises it to a monotone per-candidate latch, so a bump is never walked back and the number of bumps is bounded by the ladder. The **bump target** is the median feerate of the block at `tip − (tip mod 6)`, quantized DOWN to 5 sat/vB — down, because rounding up would make any block with a median of at least 1 sat/vB demand a whole step, bumping an escape already composed at the chain's own median a full rung for pressure that does not exist. Every input is consensus-observable and both axes are quantized for the same reason the floor is static: honest nodes that disagreed would sign different transactions and no rung would reach `t`. **No mempool reading may enter it** — `mempoolminfee`, `estimatesmartfee`, and local eviction history are exactly the per-node state that would split the federation. A backend that reports no reading means no observed pressure: the base escape fires, unbumped. **Residual (Fable 9y5.7 review), degradation NEVER theft:** the target is only as honest as the block at the anchor height. A wrench attacker colluding with a miner who mines a near-empty block landing on a multiple-of-6 height inside `[T, T+combine_slack]` makes every honest node read a ~0 median → target 0 → the base rung fires, while the attacker keeps the real mempool above the base feerate to keep it unconfirmed; the sweep then exits through Recovery. This is exactly the pre-9y5.7 fixed-panic-fee outcome (frozen → Recovery, the designed fail-safe), needs a sustained miner-plus-fee-spam spend, and the inverse push (a stuffed anchor block forcing an over-target) is still capped at the highest user-pre-signed rung the ≥95% coverage guard admits. It is inherent to ANY single consensus-observable fee signal — the alternative (per-node mempool reads) would split the federation, which is the worse failure — so it is accepted, not closed.
- **ε** (`epsilon_secs`): a small bounded margin (default e.g. 60) subtracted in `T = min(first_seen + duress_delay_secs, earliest pending hot Hold-expiry − ε)`, so the escape fires strictly before a frozen spend would settle even under per-node clock skew.
- **Refresh min interval** (`refresh_min_interval_secs`): per-coin minimum time between refreshes (default ~30d). **Refresh fee cap** (`refresh_max_feerate`): a normal feerate (small multiple of the node's estimate), *not* the fixed 10% `MAX_FEE_PERCENT` guard — a legitimate self-spend never pays near 10%.

## 7. Attempt budget (per-node) and coordinator auth-key lifecycle

- **Pin-attempt budget (per-node, ADR-0012)**: each node counts failed pin compares in RAMDISK/node-lifetime state keyed loosely (not per-request, to bound online guessing); on exceeding `max_attempts` within `window_secs` it applies `backoff_schedule`, then `lockout_secs`. No cross-node accounting. Lockout is *not* Lockdown (it is a transient rate-limit, not the terminal duress state). **Not durable across reboot, and it does not need to be** (reboot-death/tmpfs, ADR-0007, 2026-07-16): a reboot wipes the whole installed system including the signing key, so it cannot be used to reset the budget while retaining the ability to sign guesses — the rebooted machine is bare, not a fresh-budget signer.
- **Coordinator auth-key**: backed up at setup (separately from the descriptor backup; e.g. a sealed offline copy). **Loss with no backup ⇒ the normal path is bricked** (manifest pins the pubkey) → recovery-timelock exit only. **Rotation ⇒ new vault** (immutable manifest); there is no in-place rotation in v0. State this loudly in the ceremony UX.

## Open (tracked to V0-8/V0-4, not blockers here)
Node-channel wire format + combine algorithm (ADR-0011 is a sketch; V0-8a); the fresh-escape-across-the-Hold rebinding rule (a deposit during a hot spend's Hold vs the pre-signed escape's coverage) — **this item is currently self-contradictory and must be resolved in V0-4**: it previously proposed rebinding via **re-submission** (pairing the pending spend with a freshly user-signed escape for the Hold), but the Model-B Hold lifecycle **removed re-submission** (sign once at ingress — ADR-0012), so any rebinding mechanism must be **sign-at-ingress-compatible**; the funds-safe fallback if none is adopted is that **a deposit arriving during a hot spend's Hold is a straggler → recovery** (swept by the next escape / recoverable via the timelock). The recovery-path construction + operations (currently outside the V0 task graph — add).
