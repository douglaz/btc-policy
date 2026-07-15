# Vault nodes are the watchtower

> **Revised by [ADR-0012](0012-model-b-spend-and-duress-architecture.md):** recognition is by *validation* of a request, NOT by co-signing (in t-of-n, n−t nodes legitimately don't sign a spend — co-signed would false-alarm). Recovery-path detection (branch-identifiable on-chain) is unaffected and is the primary job. Read 0012's watchtower section.


There is no separate watchtower service and the coordinator is not trusted with monitoring. Every vault node watches its own chain backend for (a) any recovery-path spend of vault UTXOs and (b) any vault UTXO spend it never co-signed — a node knows every spend it participated in from its own sign/refuse log, so an unrecognized spend is by definition out-of-band — and emits an alert. This gives n independent watchtowers on n hosts for free: an attacker must silence a quorum of nodes *and* hold recovery keys to sweep quietly.

## Considered Options

- **Coordinator as watchtower** — rejected: it is the machine most likely to be offline and the one an attacker already targets for alert suppression.
- **Separate watchtower daemon** — rejected: a sixth deployable in a project whose stated failure risk is ops surface swallowing the novel work.

## Consequences

- The node's role is "signer + sentinel"; nodes queue alerts locally for the coordinator to pull (ADR-0002 — nodes make no outbound connections). [Under Model B (ADR-0012), nodes make outbound peer + broadcast connections; "no outbound" applied to the pre-Model-B design.]
