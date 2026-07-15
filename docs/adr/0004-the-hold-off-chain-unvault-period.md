# The Hold: an off-chain unvault period, no covenants needed

> **Model-B correction — see [ADR-0012](0012-model-b-spend-and-duress-architecture.md) "Model-B Hold lifecycle."** Under Model B a node **signs its partial(s) at INGRESS** (pin-independent — signing must not depend on the pin, or signing itself becomes a duress oracle), **times the Hold itself** (node-driven, each node against its own clock), and **combines + broadcasts at Hold-expiry with NO coordinator re-submission**. This **supersedes the "sign only on re-submission after the Hold" shape** described in this ADR: the pin is entered once, at ingress. The Hold's *purpose, duration, and pending/first-seen accounting* below are unchanged — only *when the node signs* (ingress, not re-submission) and *who drives combine+broadcast at expiry* (the nodes, not the coordinator via a re-submit) change.

Spends to the hot wallet are not signed immediately. A node records the commitment with a first-seen timestamp, exposes it as a pending spend (pulled by the coordinator like any alert), and signs only when the same commitment is re-submitted after a static hold period D (default 24h). Spends to the escape wallet and refresh self-spends are signed instantly. This supersedes the earlier scope decision that spending delays were future work.

The clawback needs no cancel protocol and no covenant: an unauthorized pending spend is answered by an instant escape-wallet sweep of the same UTXOs — when the attacker's hold expires, the inputs no longer exist. The escape sweep *is* the cancellation. A veto message would be forgeable (the attacker holds the user key); the escape sweep is not, because its destination is the one place the attacker cannot be.

## Consequences

- The silent-theft window for an attacker holding the user key (spend-to-allowlisted, then pivot) goes from minutes to D hours. This is why a sometimes-on, pull-based coordinator is acceptable and **no always-on coordinator daemon is planned**: the mempool-speed race now exists only on the recovery path, where it is best-effort by declaration and **refresh discipline is the primary defense**.
- `/sign` becomes two-phase in vault-proto (submit → pending → sign after D); the anti-replay log gains first-seen/pending state. *(Model-B correction: the node signs at INGRESS, not on re-submission — the "sign after D" here is superseded by combine+broadcast at Hold-expiry with no coordinator re-submission; see the banner above and [ADR-0012](0012-model-b-spend-and-duress-architecture.md) "Model-B Hold lifecycle.")*
- Hold state is node-local with independent clocks (no intra-node communication). A node restart resets the timer — the hold gets longer, failing safe.
- The user's own vault→hot top-ups take D. Accepted: this is the Swan-hold UX the problem statement endorses, applied to savings.
- v0.1 ships D=0 (demo stays one command); v0.2 implements the hold and the theft demo gains the caught-mid-hold + escape-sweep scene.
