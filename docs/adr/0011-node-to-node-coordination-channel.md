# The node-to-node coordination channel (revising "no intra-node comms, ever")

Model B (ADR-0010) requires nodes to assemble the t-of-n signatures themselves, which is only possible if nodes talk to each other. This revises the founding invariant *"no intra-node communication, ever"* to: **nodes coordinate signature assembly and broadcast among themselves over an authenticated channel, and share no policy state.**

The revision is deliberately narrow in *what* the channel carries, which is the security-relevant axis:

- **Carries:** partial signatures for a specific commitment, the assembled complete tx, and broadcast coordination. Mechanical only.
- **Never carries:** policy decisions, shared spend counters/velocity state, or any gossip. Each node still independently validates every PSBT against its own policy config and its own chain view. There is still no shared policy oracle — the property the original invariant existed to protect survives.

## Shape (to be detailed in its own design before build)

- **Node identity + mutual auth.** Nodes must authenticate each other so a stranger can't inject partials or spam the assembly. (Bad partials fail signature verification anyway, so this is DoS/spam hardening, not a theft defense.) Keys minted at deploy time, alongside the mTLS/Tor plumbing.
- **Transport.** Each node knows the others' addresses (deploy-time config); v1 exposes them as Tor hidden services (already planned).
- **Assembly protocol.** For a commitment, each node contributes its partial; any node with the user sig(s) + t node partials combines and broadcasts. Redundant broadcast by several nodes is fine (same txid; mempool dedups).
- **No shared mutable state.** The channel is request-scoped signature exchange, not a standing gossip mesh. Velocity limits etc. remain out of scope (would need shared state — a separate future decision).

## Consequences

- New security-sensitive surface (node identity, auth, transport) — designed and reviewed on its own before it becomes the spend spine.
- Independence claim narrows honestly: nodes are no longer network-isolated from each other, but they remain **policy-isolated** (no shared policy oracle), which is the claim that matters. The design doc and CONTEXT.md must state this precisely.
