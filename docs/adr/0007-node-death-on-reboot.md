# A rebooted node is a dead node (MVP)

> **Banner RESOLVED (user, 2026-07-16): strict reboot-death PICKED — this ADR stands as written.** ADR-0012's earlier persistence branch (duress schedule + own escape partial on disk, "running-but-signing-keyless" daemon) is NOT adopted. Node state lives on RAMDISK; nothing survives reboot. A rebooted armed node contributes no partial; the surviving armed set fires the sweep at T if ≥ t remain, else lockdown-only → recovery. Safety holds (fewer sweeps, never theft). See ADR-0012's "Persistence & reboot" invariant (rewritten to match).

Node keys exist only in memory on sealed hosts (ADR-0005), so any reboot — host maintenance, kernel panic, provider migration — permanently kills that node. The MVP accepts this rather than weakening either property: no key material at rest, no admin path back in. The 3-of-5 federation is the budget: two node deaths are absorbed; the vault must be rotated before a third.

## Considered Options

- **Key at rest, auto-decrypted at boot** — rejected: the disk image alone would yield the key to a provider-level or rescue-mode attacker.
- **`/unseal` endpoint** — **REJECTED (user, 2026-07-16; was "deferred, maybe later")**: a re-key path back into a sealed box reopens the exact attack this ADR closed, and it is only safe with a durable never-cleared lockdown flag — an at-rest artifact the RAMDISK/nothing-at-rest rule forbids (and an at-rest "duress was detected" leak besides). Node attrition + vault rotation is the accepted price; the two hard sub-rules recorded here (durable lockdown flag; no location holds t preimages) stay as the reasons it cannot be safely revived, not as a roadmap.

## Consequences

- The coordinator's node polling doubles as a liveness monitor: a node that stops answering is presumed dead, surfaced to the user, and counted against the federation budget.
- Rotation guidance: at one dead node, plan a rotation; at two, rotation is urgent (three alive = bare quorum, zero margin — one more reboot strands the normal path and forces the recovery path).
- Node uptime becomes a selection criterion for hosts; the deployer should prefer providers/plans with low forced-reboot rates.
