# Threat model

Part of the core-proven gate's artifact set (bead `btc-policy-9y5.8` deliverable 2), and the
document an **external human reviewer** should read first. It states what this vault protects,
who it protects against, what it deliberately does *not* protect against, and which invariants
the whole design rests on — so a reviewer can attack the claims rather than reconstruct them.

The decisions themselves live in `docs/adr/`; this synthesizes them into one attack-facing view
and is deliberately explicit about residual risk. **Nothing here should be taken on trust — every
claim below is meant to be falsifiable against the code.**

## 1. What is being protected

A single-user, self-custodied Bitcoin vault holding meaningful savings. The protected asset is
**the coins**, and the protected property is:

> A spend happens only when the user genuinely wants it, and a spend the user does not want can
> be stopped before it settles — including when the user is being physically coerced.

Secondary assets: the node signing keys, the two PIN digests, the coordinator auth key, the
escape and recovery keys, and the operator preimages that derive node keys.

## 2. The vault, in one paragraph

Coins sit in a P2WSH descriptor with two branches: **3-of-5 federation signatures plus the user
key**, or — after a ~180-day relative timelock — a **2-of-3 recovery** branch. Five independent
`vault-node` daemons each hold one federation key. A spend is submitted through an untrusted
**coordinator** relay; each node independently re-runs every policy gate, signs at ingress, and
holds its partial signature until the **Hold** elapses. Nodes then release partials to each
other, and whichever node first holds `t` of them combines and broadcasts. Every spend request
carries a **PIN**; a second, distinct *duress* PIN silently arms an escape sweep that claws the
coins into an independent escape wallet and locks the federation down. See ADR-0012 for the
consolidated architecture.

## 3. Adversaries

| # | Adversary | Holds | Design answer |
|---|---|---|---|
| A1 | **Remote attacker / malware on the coordinator** | The coordinator relay, network position | The coordinator is untrusted by construction (ADR-0010). It holds no signing key, cannot finalize, and cannot broadcast — nodes assemble and broadcast. Every request is re-validated per node. |
| A2 | **Thief with the user key** | User key, but no PIN | Cannot produce a valid request: the PIN gate is independent of the key. Destination allowlist and Hot budget bound anything that does pass. |
| A3 | **Thief with user key + normal PIN** | Both | Bounded, not prevented. The destination allowlist, per-tx cap, and velocity ledger (ADR-0014) bound the loss; the **Hold** gives the user a window to notice and claw back with the duress PIN. This is the `demo theft-refused` scenario. |
| A4 | **Coercion / wrench attack** | The user, under duress, plus everything they know | The **duress PIN** (ADR-0008): a spend ceremony that looks and sounds identical to the attacker, but silently arms an escape sweep at `T` and locks the federation down unconditionally. This is the design's centrepiece. |
| A5 | **Compromise of `c < t` nodes** | Up to 2 of 5 federation keys | Cannot reach quorum alone. ADR-0009 requires no correlation class (host, OS, location, operator) reach `t`. The Hot budget's routing bound is stated for `c < t` explicitly (ADR-0014). |
| A6 | **Compromise of `≥ t` nodes** | 3+ federation keys **and** the user key | **Out of scope — this breaks the vault.** The federation threshold is the security boundary; nothing below it recovers from `t` honest-key compromise combined with the user key. |
| A7 | **Coordinator-auth-key thief** | User key + PIN + coordinator auth key | Can feed one node directly and rely on propagation to arm the federation. Loss is bounded by allowlist/Hot budget/Hold, and every node's pin-uniform `GET /pending` projection makes the accepted candidate visible without relying on the coordinator relay. |
| A8 | **Chain-level adversary** | Miners, mempool, fee market | Cannot steal. Can *delay*: fee spikes, censorship, and reorgs are handled by the RBF escape ladder, the re-broadcast path, and reorg-aware settlement — and every failure degrades to "funds frozen → recovery", never to theft. |
| A9 | **Supply chain** | A dependency, or the build | Bounded by a deliberately small dependency set and a policy that every dependency must beat writing it (`docs/SBOM-AND-DEPENDENCY-POLICY.md`). **Weakly defended — see R4.** |

## 4. Trust boundaries

1. **User ↔ coordinator.** The coordinator authenticates requests with its own key but is
   *untrusted*: it is a relay whose signature only proves "this vault's coordinator authored this
   request", never that the request is legitimate.
2. **Coordinator ↔ node.** The hard boundary. Every node independently re-runs coord-auth,
   freshness, the PIN, the user signature, destination class, the Hot budget, and the chain
   preflight. A node never signs because a peer or the coordinator said so
   (the signing-oracle prohibition).
3. **Node ↔ node.** Peers relay coordinator-signed requests verbatim and exchange partials after
   the fire event. A peer is pure transport: authority is cryptographic, rooted in the sealed
   manifest (ADR-0011, ADR-0013 §1).
4. **Node ↔ chain backend.** Each node runs its own bitcoind and is its own watchtower
   (ADR-0001). A node that cannot read its chain fails closed.
5. **Setup ceremony.** The one moment the whole vault's parameters are fixed. After it, nodes
   are **sealed** (ADR-0005): the manifest is immutable, so a changed parameter is a *new vault*,
   not a reconfiguration.

   **The ceremony is TRUSTED, and that boundary is easy to misread.** The coordinator is
   "trusted until the wrench attack, untrusted after" (ADR-0010/0012) — so R8b's pre-wrench
   compromise means malware resident on the **operating** coordinator, observing the normal PIN
   during ordinary spends before a coercion event. It does **not** mean a compromised ceremony
   tool. The ceremony is one-time and witnessed, and it precedes any funds.

   Nor is it useful to defend individual ceremony outputs against a hostile ceremony tool: such a
   tool would not forge a display, it would seal a descriptor containing its own key or exfiltrate
   the recovery keys. A control that assumes an adversary strong enough to forge one field yet
   uninterested in taking the vault is not defence in depth — it is confusion. (Corrected
   2026-07-30, after exactly this error was made while designing the recovery-timelock control.)

## 5. Load-bearing invariants

These are what a reviewer should try hardest to break. Each is enforced in code, not convention.

| Invariant | What it means | Break it and… |
|---|---|---|
| **SILENCE** (scoped — read the scope) | Across the protocol observables a node emits — response bytes, timing class, `/events`, `/healthz`, `/pending`, peer effects — a duress-PIN ceremony is identical to a normal-PIN one. **It is NOT a claim that no adversary can learn the PIN class.** A compromised NODE sees the submitted PIN in plaintext, and a coordinator compromised BEFORE the wrench can read the normal PIN and substitute it, nullifying duress entirely (ADR-0012 Direction 3, and R8 below). The guarantee is: silence against a coordinator that turns hostile AT the wrench, across the observables listed. R10 below states the evidence boundary for end-to-end timing and post-handler effects; SILENCE itself remains normative. | The wrench attacker learns the duress PIN was used and simply escalates. This is the invariant most easily lost to an innocuous-looking new field or endpoint. |
| **Signer/partial COUPLING + RELEASE-GATE** | A partial is finalizable authority the moment `t−1` compromised peers hold it, so every fire-time check runs BEFORE release; `release_partials` is the sole egress. | A `t−1` set combines a transaction the honest node had refused. |
| **Unconditional Lockdown at T** | Once armed, Lockdown happens at `T` regardless of whether the sweep succeeded, the chain was readable, or anything else. | Duress becomes survivable for the attacker: the vault keeps signing after coercion. |
| **Determinism across the honest set** | Every honest node derives the same verdicts, and the same fee-bump rung, from the same chain state. | Partials cover different transactions, no rung reaches `t`, and the escape fails exactly when it is needed. |
| **Escape-key independence** | The escape wallet's keys share no seed/ancestor with the user, node, or recovery keys (ADR-0003). | The claw-back becomes theft outright — the attacker who coerced the user also controls the destination. Checked at ceremony time and refused if violated. |
| **policy-core purity** | The refusal core has no clock, chain, or I/O. | Refusals stop being deterministic, and §5's determinism invariant falls with it. |
| **Fail closed** | Every unknown, error, or degraded state refuses; funds route to recovery rather than moving. | The classic "error path is the attack path" failure. |

## 6. Attack surfaces, concretely

| Surface | Exposure | Notes for a reviewer |
|---|---|---|
| `POST /sign` | The main gate | Coord-auth → freshness/nonce → PIN (two Argon2id evaluations, constant-time compare) → user signature → class/allowlist → Hot budget → chain preflight → register. The nonce is consumed atomically under the sign lock; the slow chain I/O is deliberately *outside* it so no RPC can delay Lockdown-at-T. |
| `POST /channel` | Peer transport | Manifest-pinned endpoints and endorsed channel keys; per-peer rate quota; size bound is manifest-uniform. |
| `GET /events` | Watchtower alerts + one channel diagnostic | Carries on-chain watchtower alerts (`RECOVERY_PATH_SPEND`, `UNRECOGNIZED_SPEND`) plus `CHANNEL_FRESHNESS_REJECT`, which names a peer whose clock is off. It carries nothing about pending or armed state. A reviewer should confirm the freshness diagnostic is genuinely pin-independent, since it is the one `/events` entry not derived from the chain. |
| `GET /healthz` | Liveness | Three atomic loads; must stay free of duress-dependent content. |
| `GET /pending` | Accepted hot-candidate ids | Sorted opaque commitment ids only. No arm state, transaction, amount, destination, signature material, or explicit timing field. The complete body must stay byte-identical across normal/duress and armed/idle twins. One short `sign_state` snapshot is allowed; concurrent snapshots are shed before entering the blocking pool. The SILENCE row above is asserted here on the response **bytes**. This is the one read surface that waits on `sign_state`, and it is **not** structurally isolated from arm-dependent work: the fire pass's release/combine loop holds `sign_state` too (it must — the release gate is fail-closed under that guard). What makes the channel pin-uniform is scheduling, not isolation: dynamic-`T` puts `T` at or before the earliest pending hot Hold expiry minus `epsilon_secs`, so **pre-`T` the due set is empty on an armed node and an idle twin alike** and the guarded section does no arm-dependent work on either; the arm-dependent duration difference is confined to the post-`T` window, by which point Lockdown is already public. A separate, weaker residual remains and is not co-residency: because the route is unauthenticated and waits on this lock, any network observer can poll it and infer *that* a `/sign` was being processed — including one that was REFUSED and therefore never appears in the projection. That is a spend-activity timing channel, not a duress oracle. |
| Chain backend RPC | Per-node bitcoind | Requires `-txindex=1`. Node fails closed if unreadable. |
| Setup ceremony | One-time | The highest-consequence surface: it fixes keys, PINs, policy caps, and the manifest hash. See `docs/SETUP-CEREMONY.md`; `finalize` refuses to seal an edited state. |
| Node config + preimage | At rest on each host | The signing key is derived from an operator-supplied preimage at start, not stored. ADR-0007 assumes tmpfs so a reboot kills the node. |

## 7. Residual risks — stated plainly

**R1 — The pending projection is pull-only, and it is an unauthenticated timing surface.**
The coordinator-auth-key visibility gap is closed by `GET /pending`, but there is no paging or
push notification. Someone must poll every node and compare the opaque ids with the user's
authorized spends. Polling also bounds when an id appeared and disappeared; that timing is
pin-uniform, but observable. The route deliberately exposes no transaction details or deadline.

Two residuals a reviewer should weigh rather than take as closed. First, the route is
**unauthenticated** (matching `/healthz` and `/events`) and it is the one read surface that waits
on `sign_state`, so any network peer — holding no keys at all — can poll it and infer that a
`/sign` was being processed, **including a spend that was refused** and therefore never appears
in the projection. That is a spend-activity timing channel, not a duress oracle, and it is not
the co-residency residual documented for `/healthz`: it needs no co-tenancy. Second, the
pin-uniformity of that channel rests on dynamic-`T` keeping the fire pass's due set empty pre-`T`
on armed and idle nodes alike — **not** on lock isolation, since the release/combine pass holds
`sign_state` as well. If dynamic-`T` ever stopped guaranteeing an empty pre-`T` due set, this
would need re-analysis.

**R2 — `t` compromised nodes plus the user key is unrecoverable.** By construction (A6). The
mitigation is operational — ADR-0009's correlation-class rule — not cryptographic.

**R3 — Reboot-death is an assumption, not an enforcement.** ADR-0007 assumes config/keys live on
tmpfs so a reboot wipes the signing key and Lockdown latch. The node *warns* when it detects a
non-volatile filesystem and proceeds only because storage enforcement is disabled; in that state
the model's premise does not hold.

**R4 — Supply chain is defended by policy, not tooling.** No `cargo audit` / `cargo deny` runs in
CI, and there is no reproducible release yet. See `docs/SBOM-AND-DEPENDENCY-POLICY.md`.

**R5 — Full-UTXO-set scanning does not scale, and it is still the fallback.** Measured on live
signet: ~10.4 s per `scantxoutset` against 72.2M outputs, serialized process-wide by Core. This
is availability, not theft — but a node that cannot warm its view in time is a node that is not
protecting anything. Since `btc-policy-hn8` the steady state no longer pays it: the vault-unspent
cache is served from a node-owned watch-only descriptor wallet, and restarts read `listunspent`.
A scan still runs on a node's FIRST bring-up against a backend (it supplies the wallet's
birthday), whenever the wallet is missing, unreadable, or unrecognized, and after a reorg below
the wallet's completion anchor — which also re-imports the descriptors, rescanning from the
vault's oldest live output. Those paths are unmeasured on a real chain, and the mainnet UTXO set
is larger than signet's. Remaining scaling work is tracked as `btc-policy-zzv`.

**R6 — One honest signet spend is the extent of real-chain evidence.** Duress, claw-back, and
reorg behaviour are proven on regtest only (`attack all`, the demos). See
`docs/SIGNET-SPEND-RECORD.md`, which is explicit about this.

**R8 — The two most severe residuals are currently mitigated by documents, not code.**
Both independent reviews of this repo converged here, and neither found an unknown protocol
break — the problems are deployment-shaped.

*R8a — the federation is not actually independent.* `docs/SETUP-CEREMONY.md` provisions five
node processes on ONE host with loopback channel endpoints. ADR-0009 requires that no
correlation class reach quorum; one host IS a correlation class holding all five keys. Until the
nodes run on genuinely independent hosts and backends, **3-of-5 is a property of the design, not
of the deployment**, and the first thing an attacker should do is take that host. The abstract
design stops "user key plus one compromised node"; the current deployment does not.

*R8b — a pre-wrench coordinator compromise nullifies duress.* ADR-0012 Direction 3 accepts this:
malware resident on the coordinator before coercion reads the normal PIN and substitutes it, so
the escape never arms, no node locks down, and — because every observable is pin-uniform by
design — the user sees exactly what they would have seen if it worked. The stated mitigations
are a hardened dedicated host and reproducible builds. **Neither exists** (see R4). The user key
is also software in every current driver and would live on that same host, which merges this
with adversary A3.

**Attribution corrected 2026-07-30 (codex + Fable spec review).** The two stated mitigations do
not cover the same vector, and this entry used to imply they jointly answered R8b. ADR-0012's
residual names four vectors; reproducible builds close **poisoned build** and **tampered
dependency**, host hardening reduces the *probability* of **resident malware** without removing
the capability — malware that is already on the host reads the PIN out of a byte-identical
binary — and **nothing** addresses a **wrench that begins mid-spend** while the normal PIN is
still in RAM. See the vector table in ADR-0012 under "Coordinator host hardening". So R8b is
**likelihood-reduced but unclosed**, and it would remain unclosed even if both mitigations
shipped tomorrow. Its severity is unchanged and was already right — this is a correction to what
the controls are credited with, not a re-ranking. What keeps the loss finite once it fires is the
consequence-bounding set: the Hot budget and velocity ledger (ADR-0014), the Hold, the allowlist,
and hardware user signing (`btc-policy-bq6`) for the merged-A3 half. The only true prevention is
ADR-0012's Direction 1, which is hardware-gated and deliberately unplanned.

Neither is a new discovery; both are named in ADR-0009/ADR-0012. What is worth stating plainly
is that they are the top of the risk list and the code has not moved on either.

**R9 — The operator path does not exist yet.**
`setup finalize` seals a vault, and no command in this repository can then spend from it, refresh
it, claw back during a Hold, or drive recovery: nothing outside `setup.rs` reads `manifest.json`,
and every driver (`demo`, `attack`, `signet spend`) builds its own federation in-process with
ephemeral keys. Sections of `docs/OPERATIONS-RUNBOOK.md` therefore describe actions a user cannot
currently perform. The runbook flags this inline, but a reader should know it up front: the
protocol core is considerably more finished than the product around it.

**R7 — No external human security review has happened yet.** This is the open half of the
core-proven gate. Correlated automated review — including this repo's `codex` + Claude Fable
panels, however adversarially prompted — **does not** substitute for it, and this document must
not be read as evidence that it has.

**R10 — End-to-end SILENCE timing has no hard wall-clock gate.** The live normal/duress skew is
still sampled and reported, but it is advisory: repeated CI runs on identical code produced
opposite signs and a noise range larger than the one-extra-Argon2 regression it was meant to
detect, so it could produce false negatives as readily as false positives. The hard replacement
is deterministic and in-process: it compares the synchronous `/sign` response, ordered handler
operations, an exhaustive pin-masked channel-store projection, an exhaustive projection of the
`/sign` handler state (including the PIN attempt budget), schedule-work counts, PIN evaluations,
and carrier derivations — across seven request shapes including a locked-out node. Its capture ends at handler return, before the server drains
the outbox and spawned peer sends run. Those post-handler effects are exercised by live
propagation scenarios, but neither they nor arbitrary end-to-end CPU/scheduler cost have a
deterministic timing gate. SILENCE remains the normative invariant; this is the evidence boundary
an external reviewer must not mistake for a proof of every timing effect.

## 8. What a reviewer should attack first

Ranked by "most damaging if wrong":

1. **SILENCE.** Diff every observable between the two PIN classes: response bytes, timing,
   `/events`, `/healthz`, `/pending`, peer nonce effects, and anything newly added. A
   length-preserving difference is the shape to hunt.
2. **The release gate.** Find any path where a partial leaves a node before every fire-time
   check has passed, or any second egress besides `release_partials`.
3. **Determinism.** Find two honest nodes that, on the same chain state, could disagree about a
   verdict or a fee rung — especially across the manifest-pinned config fields.
4. **Lockdown-at-T unconditionality.** Find a failure (chain unreadable, panic, lock poisoned,
   RPC hang) that skips or delays it.
5. **The ceremony.** Find a way to seal a vault whose manifest, descriptor, keys, or coordinator
   secret disagree with each other — or an independence violation that slips past ADR-0003's
   check.
6. **Fail-closed-ness.** Find an error path that moves coins or admits a spend rather than
   refusing.
