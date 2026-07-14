# A rebooted node is a dead node (MVP)

Node keys exist only in memory on sealed hosts (ADR-0005), so any reboot — host maintenance, kernel panic, provider migration — permanently kills that node. The MVP accepts this rather than weakening either property: no key material at rest, no admin path back in. The 3-of-5 federation is the budget: two node deaths are absorbed; the vault must be rotated before a third.

## Considered Options

- **Key at rest, auto-decrypted at boot** — rejected: the disk image alone would yield the key to a provider-level or rescue-mode attacker.
- **`/unseal` endpoint** — deferred, not rejected ("maybe later"): a rebooted node comes up keyless and sealed-empty; the operator re-injects a high-entropy wskdf preimage over the authenticated channel. If adopted later it carries two hard sub-rules: duress lockdown persists on disk and is never cleared by unsealing, and no single location may store t preimages (the no-two-keys-one-place invariant extended to paper).

## Consequences

- The coordinator's node polling doubles as a liveness monitor: a node that stops answering is presumed dead, surfaced to the user, and counted against the federation budget.
- Rotation guidance: at one dead node, plan a rotation; at two, rotation is urgent (three alive = bare quorum, zero margin — one more reboot strands the normal path and forces the recovery path).
- Node uptime becomes a selection criterion for hosts; the deployer should prefer providers/plans with low forced-reboot rates.
