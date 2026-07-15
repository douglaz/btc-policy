# Federated Policy Vault

Self-hosted Bitcoin custody: a user hardware key plus a t-of-n federation of policy-enforcing signer nodes, with a timelocked recovery path. This glossary is the ubiquitous language; the design doc lives at `~/.gstack/projects/btc-policy/user-unknown-design-20260713-004036.md`.

## Language

**Vault**:
The primary store of funds — one wallet with two spend paths (Normal path, Recovery path) defined by a single Miniscript descriptor.
_Avoid_: wallet (alone), safe, cold storage

**Normal path**:
The vault spend path requiring the User key plus a Quorum of node signatures; every spend through it is policy-checked.
_Avoid_: primary path, spend branch

**Recovery path**:
The vault spend path requiring 2-of-3 Recovery keys after a relative timelock. Used for loss and inheritance only — never as a response to an attack.
_Avoid_: emergency path, backup path

**Federation**:
The set of n Vault nodes collectively. Nodes coordinate signature assembly + broadcast over the Node channel (ADR-0011/0012) but share no Policy state — policy-isolated, not network-isolated.
_Avoid_: cluster, cosigners

**Vault node**:
A daemon holding exactly one federation key and one policy engine; independently validates each PSBT against the Policy checks before signing or refusing, and performs Watchtower duty against its own chain view.
_Avoid_: signer (alone), server, peer

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
The on-chain rules compiled into the vault's Miniscript descriptor, enforced by Bitcoin consensus.
_Avoid_: script (alone), contract

**Policy checks**:
The off-chain PSBT checks every Vault node runs before signing (allowlist, fee cap, input ownership, sighash, consistency). Implemented by policy-core; unrelated to rust-miniscript's `policy` module.
_Avoid_: rules, validation (alone)

**Policy config**:
The per-node TOML file parameterizing the Policy checks. Written once at setup, immutable forever; changing it means a new Vault.
_Avoid_: settings, policy file

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
The second of two enrolled PINs; submitting it with any spend triggers the vault's duress response (Lockdown or escape sweep + Lockdown) while looking identical to normal authorization. Presented externally as automated fraud prevention, never as a duress signal.
_Avoid_: panic code, secondary PIN

**Lockdown**:
The state in which every node refuses all signing (`FRAUD_SUSPECTED`), persisted on disk, surviving reboots, with no reset on Sealed nodes — the only exit is the Recovery path.
_Avoid_: freeze (alone), pause

**Sealed**:
The post-setup state of a node host: SSH uninstalled, no administrative access; only the node API and its chain backend remain. Changes to a sealed federation mean rotating to a new Vault.
_Avoid_: locked (use Lockdown for signing state), hardened

**Hold**:
The per-destination-class waiting period between a spend's first submission and node signing (hot wallet: D, default 24h; Escape wallet and Refresh: none). Off-chain, enforced independently by each node. Not the Recovery-path timelock.
_Avoid_: delay, timelock (for this), cooldown

**Pending spend**:
A Commitment a node has recorded but not yet signed, waiting out its Hold; visible to the Coordinator via pull. Cancelled implicitly by any confirmed conflicting spend (in anger: the escape sweep).
_Avoid_: queued transaction, unconfirmed spend

**Commitment**:
The exact-transaction binding a node evaluates and signs against: wallet id, outpoints, outputs, fee, expiry, policy version. Defined in vault-proto.
_Avoid_: authorization, intent, summary

**Alert**:
A structured event a Vault node queues locally (Watchtower hit or Refusal) for the Coordinator to pull and surface to the user. Nodes never push.
_Avoid_: notification, log line

**Refusal**:
A node's structured decision not to sign, carrying a machine-readable code and reason. A policy outcome, never a transport error.
_Avoid_: rejection, error (for policy outcomes)

**Refresh**:
A Normal-path self-spend that resets a coin's recovery timelock. Requires the User key; the Coordinator only prepares it.
_Avoid_: rollover, renewal

**Rotate**:
The incident response: sweep everything through the Normal path to the Escape wallet, then fund a successor Vault.
_Avoid_: key rotation (alone), migration

**Watchtower**:
A monitoring role performed by every Vault node (ADR-0001/0012): alerts on any Recovery-path spend (branch-identifiable on-chain) and any vault spend the node never **validated** (saw and policy-checked the request) — NOT "never co-signed" (in t-of-n, n−t nodes legitimately don't sign each spend). Continues during Lockdown and on keyless-rebooted nodes.
_Avoid_: monitor (alone), watchtower service

**Soft vault**:
This design's honest trust boundary: t compromised nodes plus the User key equals theft. Stated and demoed openly.
_Avoid_: covenant vault, trustless vault

**Descriptor backup**:
The full vault descriptor (all public keys), backed up promiscuously. Without it even valid Recovery keys cannot locate or spend the coins.
_Avoid_: wallet backup, seed backup
