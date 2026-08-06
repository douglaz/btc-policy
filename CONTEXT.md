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
The vault-cli process. A relay, **trusted until the wrench attack, untrusted after** (ADR-0010/0012): it operates the User key, composes normal-spend txs (frozen by the user's signature), relays coordinator-signed requests — including each SpendRequest's spend, mandatory Escape, and optional pre-signed Escape fee ladder — to the nodes, and pulls Alerts. It does NOT assemble signatures, finalize, or itself broadcast — the Nodes do. A post-wrench Coordinator can censor or selectively deliver, strip fee-ladder rungs and re-sign, or swap an escape-class spend/residual pair; it can thereby suppress or downgrade the `T`-time sweep and choose which already-user-signed leg releases immediately. It cannot cause arbitrary transaction bytes or redirected outputs to be broadcast, and cannot steal. A *pre-wrench-compromised* one can substitute the pin (Direction-3 residual). Never persists the pin.
_Avoid_: server, orchestrator, wallet app, assembler

**Node channel**:
The authenticated node-to-node channel (ADR-0011) over which Nodes exchange partial signatures and coordinate broadcast. Carries signatures and assembly only — never Policy. Revises the former "no intra-node communication" rule: Nodes are policy-isolated, not network-isolated.
_Avoid_: gossip, mesh (implies shared state), p2p

**User key**:
The user's own key, mandatory on every Normal-path spend (hardware-backed in real use; software in the regtest demo).
_Avoid_: owner key, master key

**Operator**:
The human who runs a sealed Vault: funds it, authorizes spends, watches Alerts, and drives Recovery if it comes to that. Distinct from the User key they hold, and from the Coordinator, which is infrastructure rather than a person — and which is trusted until the wrench, untrusted after (see its own entry; do not read this as untrusted throughout). The Operator is who the Ceremony's questions are addressed to and who the operations runbook instructs.
_Avoid_: user (when the human rather than the key is meant), admin (a Sealed host has no administrative access), owner

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
The user's day-to-day spending wallet; an allowlisted destination and the accepted risk budget, bounded by the **Hot budget**.
_Avoid_: spending wallet, mobile wallet

**Hot budget**:
The enforced ceiling on Hot-class outflow — a per-transaction cap and a rolling-window velocity cap on the sum of a spend's outputs to neither the vault nor the escape wallet (ADR-0014); vault change, escape outputs, and the fee are all excluded. Federation-uniform (the caps plus the hot/escape descriptors and derivation bound are pinned in the Manifest); enforced by each Node at ingress before signing; window ≥ `max_commitment_age_secs` so no candidate ages out while the Node still authorizes its completion. This is what makes the Hot wallet's "risk budget" a real bound, not an assumption: with `c < t` compromised signer Nodes, the newly completable outflow admitted per window is at most `((n−c)/(t−c))` × the per-Node window cap. For production `n = 2t−1`, that is `(2 − 1/t)` × the cap (<2×) in the pure Duress-censorship residual (`c = 0`), and at most `t` × the cap under the full `c = t−1` soft-vault tolerance. Lifetime exposure is bounded by detection + Recovery, not the cap. Escape and Refresh are not Hot-class → never consume it.
_Avoid_: spend limit, rate limit (that's the pin-attempt budget)

**Escape**:
The mandatory second transaction in every `SpendRequest` (a `RefreshRequest` is also Normal-path but intentionally carries none): a user-signed sweep of the vault to the Escape wallet, carried whether or not anything is wrong. It is what lets the duress response fire without any FRESH authorization — the federation cannot author an Escape without the user key or alter its SIGHASH_ALL-bound bytes, so the only sweep that can exist at `T` is one the user already signed. It still spends the vault's normal branch, so firing it needs `t` federation partials like any other spend; what makes that safe is the release gate, not the Escape. Below the HTTP body-size cap, a missing Escape is an HTTP 400 at body decode; an empty or otherwise undecodable Escape reaches its HTTP 400 only after earlier ingress gates, which can reject first. An escape-class spend completes at ingress rather than waiting for `T`, but it still carries its own mandatory Escape, and that Escape must be a DISTINCT, DISJOINT residual candidate for the `T`-time sweep — a request whose spend and Escape are the same transaction is refused (`escape_class_residual`).
_Avoid_: panic tx, sweep (alone), escape wallet (that is where it pays, not what it is)

**Escape fee ladder**:
The optional bounded set of pre-signed, higher-fee alternatives to a request's mandatory Escape (wire field `escape_bumps`, ADR-0013 §2) — same inputs, same output scripts, strictly ascending fee, all BIP125-replaceable. When bumps are present, the node numbers the mandatory base Escape as **rung 0** and the alternatives as the higher rungs. The ladder exists because the Escape is user-signed SIGHASH_ALL over its exact bytes: the federation holds no key that can raise a fee, so the only bump that can exist is one the user authorized when they signed the Escape. At `T` each node picks the cheapest admissible rung whose feerate reaches `max(bump target, feerate floor)`, clamped to the highest rung the coverage guard admits and never below a monotone per-candidate latch. With no bumps, there is no fee-ladder choice: the mandatory base Escape fires at its own fee if it is admissible. The **bump target** is the median feerate of the block at `tip − (tip mod 6)` quantized down to 5 sat/vB: consensus-observable and quantized, because nodes that disagreed would sign different transactions and no rung would reach `t`. A spike above the cap is not overpaid — the sweep tops out and, unconfirmed, falls to the Recovery path.
Selection is cheapest-at-or-above-target, but it FALLS BACK: if coverage filtering leaves no admissible rung that reaches the target, `select_escape_rung` broadcasts the most expensive rung that IS admissible — which may be BELOW target — and never nothing. So a laddered sweep can confirm under-target rather than not confirm at all; if no rung is admissible, nothing fires and the coins exit via Recovery.
_Avoid_: fee estimation, RBF policy, panic fee (that is the *base* rung's fee)

**Rung**:
One indexed candidate in a laddered Escape: the mandatory base Escape is rung 0, and each higher-numbered rung is the same Escape at a strictly higher fee, separately user-signed over its own exact bytes. The higher rungs are DERIVED from the base rather than composed by hand; one that would exceed the composing tool's fee ceiling, leave a dust output, or fail to clear the relay increment is simply not offered. At `T` each node selects among the base and higher rungs when the request carries bumps; a ladderless request has no such choice and fires its mandatory base Escape if admissible. (That ceiling is a coordinator-side constant today; ADR-0016 decides to seal it per vault: btc-policy-mby adds the sealed field, btc-policy-sqn wires the composing tool to read it.)
_Avoid_: bump (alone), replacement, retry

**Escape wallet**:
A single-sig offline cold wallet, allowlisted at setup, whose only job is receiving incident sweeps (Rotate, races). Keys independent of every other component.
_Avoid_: cold wallet (alone), backup wallet, panic wallet

**Recovery keyset**:
The 2-of-3 cold keys that can spend the Recovery path. Not a funded wallet — an alternate spend path over the vault's own coins. Distributed socially/geographically; doubles as the inheritance mechanism.
_Avoid_: recovery wallet, cold keys (alone)

**Duress PIN**:
The second of two enrolled PINs; submitting it with any spend triggers the vault's duress response — a **two-track mechanism** (ADR-0012). The **safety track** silently **arms** — freezes hot-class finalization and schedules **unconditional Lockdown at T** — while the **sweep track** is **best-effort**. The arm VERDICT is keyed on the valid duress pin **alone** (never on any chain-view judgment — coverage, feerate, and `testmempoolaccept` are fire-time only). What makes the freeze **un-splittable** is NOT a count of confirmations (a receipt proves a peer relayed the carrier, not that it froze — and with n=2t−1 a t-count can't prove t honest nodes froze): it is the **signer/partial coupling + release-gate** (ADR-0012 invariant vii). Every gate that blocks arming also blocks *signing* at ingress, and a hot partial releases only when NOT frozen — the freeze bit is set over all hot candidates under the same store lock that would release. So **no honest node ever releases a coerced partial** → only ≤ t−1 compromised can → never a signing quorum. Ingress records intent + propagates but never arms (the async confirmation just schedules *when* the freeze/sweep commit — timing, not safety). Residual: a coordinator censoring the carrier from a sub-quorum can let a *pre-pending* hot spend there complete, bounded by the **Hot budget** (ADR-0014), never a coerced-with-duress-pin spend. The node holds silently through `[arm, T]` — it does not *refuse* hot-class spends in that window, it **accepts and freezes** them: ingress is unchanged (validate, sign, register, propagate) and the arm bit only suppresses partial RELEASE, so a hot candidate accepted while armed is registered and never becomes due. Refusing at ingress would be the very pin-dependent observable **Pin-independent ingress** below forbids. At T it **enters Lockdown unconditionally** — unconditional in the sense ADR-0012 means it: no chain-view, escape-confirmation, or fire-failure branch can skip it, and the deadline driver attempts the transition on every tick. It is **not** a bound on WHEN. `enter_lockdown` needs the one `/sign` lock, `std::sync::Mutex` offers no fairness, and `/sign` has no admission control, so a coordinator minting validly-signed requests can defer the acquisition **with no finite bound** — a semaphore would bound *simultaneous* jobs, not *successive* ones. What bounds the CONSEQUENCES of that delay is the **signer/partial coupling + release-gate** below plus expiry-bounded arming, never the promptness of the transition. Then it attempts a best-effort sweep of the always-present, user-signed Escape. The sweep **may not fire** (coverage / feerate / `testmempoolaccept` checked at fire-time can fail) — funds then stay frozen and exit via the Recovery path. Safety (freeze + Lockdown → recovery) never depends on the sweep. Looks identical to normal authorization; presented externally as automated fraud prevention, never as a duress signal.
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

**Ceremony**:
The one-time setup that produces a Vault and ends with its hosts Sealed: keys generated and distributed, policy fixed, manifest and descriptor written. Its decisions are permanent — a value the Ceremony did not record cannot be added afterwards, only re-created as a new Vault — so every question it asks is asked exactly once, and asked of the Operator.
_Avoid_: setup (when the sealed event rather than the command is meant), provisioning, onboarding

**Hold**:
The per-destination-class node-driven waiting period between a spend's first submission and its **combine + broadcast** (hot wallet: D, default 24h; Escape wallet and Refresh: none). Under Model B the node **signs its partial at ingress** (pin-independent); the Hold delays combine + broadcast, **not** signing (ADR-0012 Model-B Hold lifecycle). Off-chain, enforced independently by each node against its own clock. Not the Recovery-path timelock.
_Avoid_: delay, timelock (for this), cooldown

**Transaction class**:
The category a Node derives locally from a spend's **outputs**, never trusted from a Coordinator label (ADR-0013 §3). Vault-change outputs are permitted in every class and excluded from classification: **escape-class** = every *destination* output pays the Escape descriptor (vault change permitted alongside); **refresh-class** = every output pays the vault descriptor; **hot-class** = every *destination* output pays a Hot-allowlist descriptor (vault change permitted alongside). Mixed-class spends are **rejected** (`PSBT_INCONSISTENT`) — closing the 99%-to-hot + dust-to-escape misclassification. Class drives behavior: hot = sign at ingress, hold the partial, combine + broadcast at Hold expiry (Model-B, ADR-0012); escape = complete immediately (under either pin); refresh = instant, pin-less, bounded.
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

## Rollout language

Added 2026-07-29 after a state review found two milestones fused under one name.

**Core-proven**:
The milestone the V0 plan gates ops work behind: full test matrix green, the Path suite driven on signet, and the **Freeze** of the protocol core. It means the protocol works — NOT that the system is deployable, and NOT that anyone outside this project has read it. Reached at Rollout stage 1. (Until ADR-0017 this also required an external review; that moved to stage 9.)
_Avoid_: v0 done, production-ready, launch-ready, audited

**Freeze**:
Stopping churn in a named artifact set — interfaces, threat model, ceremony and runbooks, protocol vectors, SBOM and dependency policy, upgrade/rotation policy, reproducible release — so later work builds on something stable. It is DISCIPLINE, not assurance: a freeze says the target stopped moving, never that anyone validated it. Owned by `btc-policy-gbw` at stage 1.
_Avoid_: review, sign-off, audit, approval

**External review**:
One independent human security review, at Rollout stage 9, gating the lift of the dust caps. Singular since ADR-0017. It is the only assurance in this project that is not automated, and by construction it cannot be satisfied by this repo's own codex/Fable panels — those are CORRELATED automated review, and two models agreeing is not corroboration.
_Avoid_: review #1 / #2 (there is one), AI review, panel, audit (unless a paid professional audit is meant)

**Production-ready**:
A separate, later milestone: the system is safe to hold meaningful savings. Requires an independently deployed Federation, a real Operator path, a resolved Node lifecycle, and a reviewed frozen release. Reached no earlier than Rollout stage 9.
_Avoid_: core-proven, v0 done

**Rollout ladder**:
The ten-stage deployment sequence from five daemons on one machine to public alpha, varying FOUR axes — host distribution (one machine → many machines, one provider → many providers), host hardening (open → Sealed host), network (signet → mainnet), and **value-at-risk** (dust → meaningful, which moves LAST and is not implied by reaching mainnet). The axes are not varied one-at-a-time between consecutive rungs; read the ladder as a test matrix with a funding policy. Each rung is a Stage. See `docs/ROLLOUT-PLAN.md` and ADR-0015.
_Avoid_: roadmap, phases, milestones (alone)

**Stage**:
One rung of the Rollout ladder. A stage is complete when its Path suite has run against both of its vaults — never when its code merely compiles.
_Avoid_: phase, milestone, step

**Path suite**:
The set of vault behaviours a Stage must exercise: honest hot spend, Refresh, theft refusal (destination allowlist and Hot budget), Clawback, and — destructively — a duress arm through Lockdown, then Recovery. Split across two vaults because the last two are terminal.
_Avoid_: test suite (that is the unit/integration suites), smoke test

**Survivor vault**:
The Stage vault that exercises only non-destructive paths and stays funded and running afterwards. It is what stage 8's long observation run watches.
_Avoid_: main vault, primary vault

**Sacrificial vault**:
The Stage vault deliberately driven to its terminal end: duress arm → Lockdown → Recovery. Ends dead by design, because after Lockdown the Recovery path is the only exit — so the sequence rehearses the real incident rather than simulating it.
_Avoid_: test vault, throwaway vault

**Sealed host**:
A node host with ADR-0005 applied in full: SSH uninstalled, no administrative path, no reset, no reconfiguration, no upgrade-in-place; a reboot kills the node (ADR-0007). "Locked" in rollout discussion means this. Consequence: patching a node means Rotating the vault, and node attrition has no remedy — which is precisely what stages 4 and 7 exist to measure before mainnet funds sit behind it.
_Avoid_: hardened host (weaker claim), locked-down (that is Lockdown, a duress state)
