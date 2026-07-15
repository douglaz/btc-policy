# Model B: node-assembled spends + the duress architecture (consolidated)

Status: accepted 2026-07-15 (user design session). This ADR is the **authoritative, self-contained** spec for the Model-B spend path and the duress mechanism. It consolidates and supersedes the relevant parts of ADR-0008 (duress), ADR-0010 (coordinator relay), and ADR-0011 (node channel); those remain as decision records but this ADR is the source of truth. It also revises ADR-0001 (watchtower) and ADR-0002 (alert delivery) as noted, and reverses two earlier locked invariants ("coordinator trusted in MVP", "no intra-node communication, ever").

## Threat model (precise — everything below depends on it)

- **Coordinator: trusted until the wrench attack, untrusted from that moment.** It is honest during all normal operation and **never persists the pin** (RAM-only, discarded each spend). At the wrench it may turn fully hostile. Consequence: a coordinator compromised *at* the wrench has no pin history, and since the user always enters the *duress* pin under coercion, it never learns the normal pin — so it **cannot substitute the pin**. It can drop or selectively deliver requests, but see "duress propagation".
- **Silence model A:** the duress response must be silent against an *outside* attacker (controls the coordinator/laptop + the physical scene) who has compromised **no node**. A compromised quorum node *can* detect a duress event (it hash-compares the pin) — accepted: silence has a weaker threshold (1 node) than theft (t nodes). Designing silence against a node-owning attacker would require hiding the duress bit from nodes (threshold crypto) and is explicitly out of scope.
- **Soft-vault boundary unchanged:** user key + t compromised nodes = theft. Up to t−1 compromised nodes tolerated for theft.

## Architecture: full Model B

The coordinator is a **pure relay, always** — it operates the user key, composes candidate normal-spend transactions, relays `{exact single-signed tx, pin}` to the nodes, and pulls alerts. It **never** combines partial signatures, finalizes, or broadcasts. Each node validates independently, signs its partial, exchanges partials with peers over the node-to-node channel, assembles the complete tx, and broadcasts via its own chain backend. This is uniform for **every** spend, so the escape path is exercised by every normal spend (battle-tested, no special-case seam).

What this buys and its limit: a hostile (post-wrench) coordinator can **censor** (drop) and **selectively deliver**, but cannot forge/redirect signatures, cannot broadcast (it never holds a complete tx), and cannot control broadcast timing. It cannot get a coerced spend signed without delivering the duress-pin'd request, which makes nodes arm the escape instead — there is no move that yields funds. Total censorship (drop to all nodes) is an accepted residual (funds stay safe in the vault; closed in v1 by a direct user↔node path).

## Transactions and exact-byte identity

- **User signs first.** For a normal spend the coordinator composes the exact transaction (coin selection, fee ≤ 10%, change); the user reviews outputs+fee on-device and signs it under SIGHASH_ALL, producing a **single-signed** tx. The user signature **freezes the exact bytes** — the coordinator cannot alter a coin/fee/output afterward without invalidating it, and nodes verify it (V0-1) and reject tampering. Nodes then validate policy + prevouts (their own chain view) and add partials over the *identical* bytes, so partials combine.
- **The commitment binds the exact unsigned transaction** — including `version`, `nLockTime`, and every input `nSequence` (resolves the parked V0-2/V0-3 gap). Two distinct transactions must never share a commitment id, or the channel could gather non-combinable partials.
- **The escape is deterministic and node-built.** It is a parameterless "sweep every vault UTXO → the escape descriptor at a panic feerate". Every node builds byte-identical escape bytes from its own chain view; the coordinator never touches it. The user signs the escape too (two-tx ceremony), and each node **stores the latest user-signed escape**, refreshed as the UTXO set changes. "Escape" means a **full-balance sweep**, not a same-inputs sweep (resolves the DESIGN/ADR-0008 ambiguity).

## The node-to-node channel

- **Identity (ADR-0011 revised):** each node's channel key is **RAM-only, re-derived at startup** from the wskdf preimage (like the signing key; dies on reboot per ADR-0007 — no at-rest secret for a provider/rescue-mode attacker). Membership is an **immutable per-vault manifest**; each channel key is **endorsed at setup by that node's Bitcoin signing key** (which is in the descriptor), so peers accept a channel identity only if vouched for by a key already in the federation, and the **coordinator cannot mint or impersonate a node**.
- **Signing-oracle prohibition (absolute):** a peer message must **never** cause a node to create a signature. A node signs only after it has independently received and accepted the full user-authorized request (valid user sig, valid pin, exact tx, its own policy verdict, its own Hold/duress state). Peer claims ("I validated", "broadcast now") carry no authority. This is ordinary independent-ECDSA multisig — there is no legitimate nonce-exchange phase.
- **Message binding:** every partial envelope carries wallet_id, exact unsigned-txid, input index, signer node id, sighash type, spend purpose, protocol version, session nonce, and the user-signature hash it is bound to; peers verify each partial against the expected descriptor pubkey before storing/forwarding. Nodes keep their own canonical PSBT and import only verified signature fields (never blind-merge peer PSBTs).
- **DoS:** an authenticated-but-compromised minority can spam. Strict per-peer quotas, bounded message/session sizes, concurrency limits, deadlines, duplicate suppression, and isolation from the watchtower loop. No leader/single-assembler required for progress.
- **Transport:** v0 demo runs localhost (regtest); v1 exposes nodes as Tor hidden services with the endorsed-identity auth above.

## Duress state machine (per node)

1. **Idle (normal):** processes spends; stores the latest user-signed escape (refreshed as UTXOs change), persisted.
2. **Arm** (a request whose pin matches `pin_duress_hash`, from the coordinator OR a peer): validate the user-signed escape (user sig, sweeps to escape descriptor, covers current UTXOs per own chain view); **propagate the duress request to all peers over the channel** (one delivered node arms them all — kills selective/split delivery); compute `T = first_seen + duress_delay_secs` on the node's own clock; **persist {armed, escape, T}** to disk (survives reboot — safe under A); keep answering the coordinator normally (silent).
3. **Armed** (`[arm, T]`): silent to the coordinator/attacker; **silently refuses to finalize any hot-class spend** (stops a pending or coerced hot spend racing the escape — no `duress_delay` vs Hold tuning needed); assembles the escape with peers so a complete tx is ready; on reboot reloads persisted state and re-arms (broadcast needs no key).
4. **Fire (at T):** broadcast the assembled escape via the chain backend and **re-broadcast the same bytes until confirmed** (fixed panic-fee, no re-signing); then enter Lockdown.
5. **Lockdown (terminal):** every request → `FRAUD_SUSPECTED`, persisted, no reset — exit is the recovery path only (ADR-0005). Presented as automated fraud prevention; the user's story is "the system locked itself, I can't override it."

`duress_delay_secs` is now purely the hostage-safety window (per-vault, `0` allowed). Per-node clocks fire within a small skew; redundant broadcast of the same tx dedups.

## Pin handling

Ephemeral (RAM-only, **never logged anywhere** — coordinator or node — the load-bearing substitution defense under the corrected threat model). Nodes hash-compare in constant time and **rate-limit online guessing** (a post-wrench coordinator could submit guesses; also throttle across nodes). Both pin hashes live in each node's config; a compromised node learns both (low-entropy) — accepted under silence model A.

## Watchtower under Model B (ADR-0001 revised)

A node marks a vault spend "recognized" **only if it locally validated/participated in that exact request** — never merely because a peer supplied a complete tx or "broadcast coordination". Otherwise the n−t non-participating nodes would false-alarm on legitimate quorum spends. An offline/partitioned node that later observes an unrecognized spend still alerts. (ADR-0002 alert *delivery* is still coordinator-pull; a post-wrench coordinator suppressing alerts is a known residual to revisit — it was calibrated for a trusted coordinator.)

## Accepted residuals (all are denial/degradation — never theft)

- **Total coordinator censorship** (drops the duress request to all nodes) → nothing fires; funds safe in the vault. Closed in v1 by a direct user↔node path.
- **Sustained fee spike** above the escape fee → escape doesn't confirm → funds frozen → recovery path.
- **A compromised quorum node detects duress** → silence model A's accepted boundary.

## How this answers the three-model review (2026-07-15)

Resolved: pin substitution (corrected coordinator model); "coordinator only censors" (restated — it can also selectively deliver, defeated by channel propagation; total-drop residual named); split-lockdown (channel propagation + arm-from-peer); reboot-cancel (persist armed escape, safe under A); silence-vs-robustness (honest nodes under A don't fire early); "nodes build from intent" (user-signs-first freezes exact bytes; escape is deterministic); escape freshness/staleness (stored standby refreshed each ceremony; full-sweep semantics fixed); signing-oracle, message binding, node-auth trust root, DoS, watchtower reclassification, and the durable duress state machine — all specified above. The doc contradictions are being reconciled in the same pass.
