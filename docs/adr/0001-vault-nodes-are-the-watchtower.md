# Vault nodes are the watchtower

There is no separate watchtower service and the coordinator is not trusted with monitoring. Every vault node watches its own chain backend for (a) any recovery-path spend of vault UTXOs and (b) any vault UTXO spend it never co-signed — a node knows every spend it participated in from its own sign/refuse log, so an unrecognized spend is by definition out-of-band — and emits an alert. This gives n independent watchtowers on n hosts for free: an attacker must silence a quorum of nodes *and* hold recovery keys to sweep quietly.

## Considered Options

- **Coordinator as watchtower** — rejected: it is the machine most likely to be offline and the one an attacker already targets for alert suppression.
- **Separate watchtower daemon** — rejected: a sixth deployable in a project whose stated failure risk is ops surface swallowing the novel work.

## Consequences

- The node's role is "signer + sentinel"; nodes queue alerts locally for the coordinator to pull (ADR-0002 — nodes make no outbound connections).
