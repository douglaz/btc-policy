# The coordinator is an untrusted relay; nodes assemble and broadcast

> **Consolidated into [ADR-0012](0012-model-b-spend-and-duress-architecture.md), which is the source of truth.** Two corrections since this was written: the coordinator is **trusted until the wrench attack**, not untrusted-always (it never persists the pin, so a wrench-moment compromise can't substitute it); and "can only censor" is imprecise — a hostile coordinator can also selectively deliver (defeated by channel propagation) and totally drop (an accepted residual). Also, the body below says nodes "build the transaction from the relayed intent" — that was reversed too: nodes **validate** the coordinator-composed, user-signed spend + escape PSBTs (relayed as full PSBTs, not an intent), they do not build the tx (ADR-0012). Read 0012.

Reverses the earlier "coordinator trusted in MVP" decision (2026-07-14, user — Model B). The coordinator no longer combines partial signatures, finalizes, or broadcasts anything. It operates the user key (producing the user signatures), relays `{spend intent, user_sigs, pin}` to the nodes, and pulls alerts (ADR-0002). That is all it does.

The nodes assemble and broadcast **every** spend themselves: each node independently builds the transaction from the relayed intent + its own chain view, validates it against policy, signs its partial, gathers the other nodes' partials over the node-to-node channel (ADR-0011), combines into the complete tx, and broadcasts via its own chain backend (V0-6).

## Why

A coordinator that assembles or holds a complete, broadcastable transaction has levers even though it can never forge a signature: it can broadcast a held tx at the wrong time, choose which of two signed variants to broadcast, or (during a duress window) broadcast a held hot tx to double-spend the vault's UTXOs and sabotage the escape sweep. The federation already guarantees no *theft* — every node validates independently, so no signature ever lands on a non-allowlisted spend — but it did not guarantee the coordinator couldn't *control broadcast*. Removing all assembly and broadcast from the coordinator removes that entire class of levers uniformly, for normal spends and the duress escape alike. The user judged the coordinator-control risk too large to accept even in the MVP.

## Consequences

- A compromised coordinator can **censor** (drop a request) — denial, never theft, never redirection, never broadcast control. Funds stay safe in the vault under the normal policy. Guaranteed delivery of a request despite a hostile coordinator (e.g. under duress) needs a user↔node direct path — v1 (the planned Tor exposure).
- This makes the **node-to-node coordination channel (ADR-0011) a core subsystem on every spend**, not a duress add-on. It is the v0 spine.
- What is preserved: each node still **independently validates every PSBT** and holds no shared policy state. The channel carries signatures, assembly, and broadcast coordination only — never policy. The federation guarantee ("every quorum ran the checks by construction; nodes share no policy oracle") is intact.
- The duress escape (ADR-0008) is no longer a special broadcast mechanism — it rides the same node assembly+broadcast path; the pin only selects which tx fires and whether to lock down.
