# Federated Policy Vault

Self-hosted Bitcoin custody: a user hardware key plus a t-of-n federation of policy-enforcing signer nodes, with a timelocked recovery path. This glossary is the ubiquitous language; the design doc lives in-repo at [`docs/DESIGN.md`](docs/DESIGN.md), and [ADR-0012](docs/adr/0012-model-b-spend-and-duress-architecture.md) + [ADR-0013](docs/adr/0013-concrete-protocol-schemas.md) are the authoritative spec for the spend path + duress.

## Language

**Vault**:
The primary store of funds — one wallet with two spend paths (Normal path, Recovery path) defined by a single Miniscript descriptor.
_Avoid_: wallet (alone), safe, cold storage

**Normal path**:
The vault spend path requiring the User key plus a Quorum of node signatures; every spend through it is policy-checked.
_Avoid_: primary path, spend branch

**Recovery path**:
The vault spend path requiring 2-of-3 Recovery keys after a relative timelock. The **fallback exit**: taken for loss / inheritance / a stuck vault, and after a failed Escape sweep + terminal Lockdown (ADR-0008). It is not the first-line answer to an *active* attack — that is the Normal path + the Escape sweep — but it IS how funds re-emerge once a locked-down vault is the only state left (freeze + Lockdown → recovery).
_Avoid_: emergency path, backup path

**Federation**:
The set of n Vault nodes collectively. Nodes coordinate signature assembly + broadcast over the Node channel (ADR-0011/0012) but share no Policy state — policy-isolated, not network-isolated.
_Avoid_: cluster, cosigners

**Vault node**:
A daemon holding exactly one federation key and one policy engine; independently validates each PSBT against the Policy checks before signing or refusing, and performs Watchtower duty against its own chain view.
_Avoid_: signer (alone), server, peer

**Node id**:
A Vault node's 0-based position in the vault descriptor's canonical node-key order — **lexicographic over the full key-expression string** (`[origin]xpub/path/*`), NOT by derived compressed pubkey (which is index-dependent; ADR-0013 §1). Computed identically by every party from the frozen descriptor string alone, so the node-id → descriptor-key mapping is a total, unambiguous bijection — never a separate table, never a human label. Appears in the Manifest, in every channel endorsement, and in every channel envelope.
_Avoid_: node name, node index (alone — say which order), peer id

**Quorum**:
Any t of the n Vault nodes (default 3-of-5). Every quorum has run the policy checks by construction.
_Avoid_: majority, threshold (as a noun for the group)

**Coordinator**:
The vault-cli process. A relay, **trusted until the wrench attack, untrusted after** (ADR-0010/0012): it operates the User key, composes normal-spend txs (frozen by the user's signature), relays coordinator-signed `{pin, spend tx, escape tx}` to the nodes, and pulls Alerts. It does NOT assemble signatures, finalize, or broadcast — the Nodes do. A post-wrench Coordinator can censor or selectively deliver, never steal or control broadcast; a *pre-wrench-compromised* one can substitute the pin (Direction-3 residual). Never persists the pin.
_Avoid_: server, orchestrator, wallet app, assembler

**Node channel**:
The authenticated node-to-node channel (ADR-0011) over which Nodes exchange partial signatures and coordinate broadcast. Carries signatures and assembly only — never Policy. Revises the former "no intra-node communication" rule: Nodes are policy-isolated, not network-isolated.
_Avoid_: gossip, mesh (implies shared state), p2p

**User key**:
The user's own key, mandatory on every Normal-path spend (hardware-backed in real use; software in the regtest demo).
_Avoid_: owner key, master key

**Policy**:
Ambiguous on its own — always qualify. Three distinct meanings exist: Spending policy, Policy checks, Policy config.
_Avoid_: unqualified "policy"

**Spending policy**:
The on-chain rules expressed in the vault's Miniscript descriptor — a **fixed, hand-written template** (keys substituted at setup; ADR-0013 §1), enforced by Bitcoin consensus. rust-miniscript parses and satisfies the descriptor but is **not** a runtime policy compiler.
_Avoid_: script (alone), contract, compiled (the descriptor is hand-written, not policy-compiled)

**Policy checks**:
The off-chain PSBT checks every Vault node runs before signing (allowlist, fee cap, input ownership, sighash, consistency). Implemented by policy-core; unrelated to rust-miniscript's `policy` module.
_Avoid_: rules, validation (alone)

**Policy config**:
The per-node TOML file parameterizing the Policy checks. Written once at setup, immutable forever; changing it means a new Vault.
_Avoid_: settings, policy file

**Manifest**:
The immutable per-vault record, written once at setup, hash-pinned, distributed to every Node and backed up with the Descriptor backup (ADR-0013 §4). Pins the canonical vault descriptor, the Coordinator auth pubkey, and every Node's channel identity (signing pubkey, channel pubkey, transport endpoints) — the root of both channel and coordinator trust. Immutable: any change is a new Vault.
_Avoid_: config (use Policy config), registry, membership file

**Allowlist**:
The Policy config's set of permitted destination wallets — descriptors with a bounded index, never fixed addresses. Contains at minimum the Hot wallet and the Escape wallet.
_Avoid_: whitelist, address list

**Hot wallet**:
The user's day-to-day spending wallet; an allowlisted destination and the accepted risk budget.
_Avoid_: spending wallet, mobile wallet

**Escape wallet**:
A single-sig offline cold wallet, allowlisted at setup, whose only job is receiving incident sweeps (Rotate, races). Keys independent of every other component.
_Avoid_: cold wallet (alone), backup wallet, panic wallet

**Recovery keyset**:
The 2-of-3 cold keys that can spend the Recovery path. Not a funded wallet — an alternate spend path over the vault's own coins. Distributed socially/geographically; doubles as the inheritance mechanism.
_Avoid_: recovery wallet, cold keys (alone)

**Duress PIN**:
The second of two enrolled PINs; submitting it with any spend triggers the vault's duress response — a **two-track mechanism** (ADR-0012). The **safety track** silently **arms** — freezes hot-class finalization and schedules **unconditional Lockdown at T** — while the **sweep track** is **best-effort**. The arm VERDICT is keyed on the valid duress pin **alone** (never on any chain-view judgment — coverage, feerate, and `testmempoolaccept` are fire-time only, so backend skew cannot split the armed set); the arm is COMMITTED only once ≥ t nodes are confirmed to hold the request (V0-4b §0, confirmation-gated arming), which is what makes it un-splittable. Ingress records intent and propagates but never arms. The node holds silently through `[arm, T]` (refusing any hot-class spend in that window); at T it **enters Lockdown unconditionally**, then attempts a best-effort sweep of the always-present, user-signed Escape. The sweep **may not fire** (coverage / feerate / `testmempoolaccept` checked at fire-time can fail) — funds then stay frozen and exit via the Recovery path. Safety (freeze + Lockdown → recovery) never depends on the sweep. Looks identical to normal authorization; presented externally as automated fraud prevention, never as a duress signal.
_Avoid_: panic code, secondary PIN

**Pin-independent ingress**:
The silence-load-bearing rule that **every** request — normal or duress — makes a Node do **identical observable work** (coordinator-auth + freshness check, validate both the spend and the mandatory escape, sign both partials, record in RAMDISK state, propagate to peers); the pin only flips an **internal** fire bit — *which* transaction eventually broadcasts and *when* (ADR-0012). Because latency, peer-visible "seen this request" state, and telemetry are identical under both PINs, an attacker holding no compromised Node cannot read the duress bit.
_Avoid_: constant-time path, duress branch (there is no separate duress branch)

**Lockdown**:
The state in which every node refuses all signing (`FRAUD_SUSPECTED`), persisted for the node's lifetime (RAMDISK — never durable disk; reboot-death, 2026-07-16), with no reset on Sealed nodes — the only exit is the Recovery path. Needs no reboot survival: reboot = node death, strictly stronger than Lockdown. `/unseal` is rejected (ADR-0007), so no durable lockdown flag exists anywhere.
_Avoid_: freeze (alone), pause

**Sealed**:
The post-setup state of a node host: SSH uninstalled, no administrative access; only the node API and its chain backend remain. Changes to a sealed federation mean rotating to a new Vault.
_Avoid_: locked (use Lockdown for signing state), hardened

**Hold**:
The per-destination-class node-driven waiting period between a spend's first submission and its **combine + broadcast** (hot wallet: D, default 24h; Escape wallet and Refresh: none). Under Model B the node **signs its partial at ingress** (pin-independent); the Hold delays combine + broadcast, **not** signing (ADR-0012 Model-B Hold lifecycle). Off-chain, enforced independently by each node against its own clock. Not the Recovery-path timelock.
_Avoid_: delay, timelock (for this), cooldown

**Transaction class**:
The category a Node derives locally from a spend's **outputs**, never trusted from a Coordinator label (ADR-0013 §3). **escape-class** = *every* output pays the Escape descriptor; **refresh-class** = every output pays the vault descriptor; **hot-class** = anything else (any output to the Hot allowlist, vault change permitted alongside). Mixed-class spends are **rejected** (`PSBT_INCONSISTENT`) — closing the 99%-to-hot + dust-to-escape misclassification. Class drives behavior: hot = sign at ingress, hold the partial, combine + broadcast at Hold expiry (Model-B, ADR-0012); escape = complete immediately (under either pin); refresh = instant, pin-less, bounded.
_Avoid_: destination type, output kind, spend purpose (the non-authoritative coordinator hint)

**Pending spend**:
A Commitment a node has recorded and **already signed at ingress** (Model B) — scheduled, its partial **held**, not yet combined + broadcast — waiting out its Hold; visible to the Coordinator via pull. Cancelled implicitly by any confirmed conflicting spend (in anger: the escape sweep).
_Avoid_: queued transaction, unconfirmed spend

**Commitment**:
The exact-transaction binding a node evaluates and signs against: wallet id, version, outpoints, per-input nSequence, outputs, fee, nLockTime, expiry, policy version — the version, nLockTime, and every input's nSequence are bound too, so two distinct transactions can never share a commitment id (ADR-0012 / ADR-0013 §2). Defined in vault-proto.
_Avoid_: authorization, intent, summary

**Alert**:
A structured event a Vault node queues locally (Watchtower hit or Refusal) for the Coordinator to pull and surface to the user. Nodes never push.
_Avoid_: notification, log line

**Refusal**:
A node's structured decision not to sign, carrying a machine-readable code and reason. A policy outcome, never a transport error.
_Avoid_: rejection, error (for policy outcomes)

**Refresh**:
A Normal-path self-spend (vault → vault) that resets a coin's recovery timelock. Carries **no pin** (not a duress surface) and is **subordinate to pending spends** — while any Normal-path spend is pending, a refresh queues behind it (ADR-0012). Requires the User key; the Coordinator only prepares it.
_Avoid_: rollover, renewal

**Rotate**:
The incident response: sweep everything through the Normal path to the Escape wallet, then fund a successor Vault.
_Avoid_: key rotation (alone), migration

**Watchtower**:
A monitoring role performed by every Vault node (ADR-0001/0012): alerts on any Recovery-path spend (branch-identifiable on-chain) and any vault spend the node never **validated AND policy-ACCEPTED** (authorized / would-authorize — added or would have added its partial) — NOT merely "saw and policy-checked" (a spend a node policy-*refused* was checked but must NOT count as recognized, or a theft fanned to honest nodes would suppress its own alert), and NOT "never co-signed" (in t-of-n, n−t nodes legitimately don't sign each spend). Continues during Lockdown. A rebooted node is **permanently dead for that vault** (tmpfs reboot-death, ADR-0007 — it never rejoins the immutable Manifest); watchtower coverage is simply carried by the surviving nodes, and restoring a lost node means rotating to a successor vault, not resurrecting it.
_Avoid_: co-sign check, monitors (alone)
_Avoid_: monitor (alone), watchtower service

**Soft vault**:
This design's honest trust boundary: t compromised nodes plus the User key equals theft. Stated and demoed openly.
_Avoid_: covenant vault, trustless vault

**Descriptor backup**:
The full vault descriptor (all public keys), backed up promiscuously. Without it even valid Recovery keys cannot locate or spend the coins.
_Avoid_: wallet backup, seed backup
