# Nodes are sealed after setup

Once a vault node is provisioned and configured, the deployer seals the host: SSH is uninstalled, no administrative access path remains, and the node's only surfaces are its API (`/sign`, event pull) and its chain backend. There is deliberately no reset, no reconfiguration, no upgrade-in-place — any change to the federation means rotating to a new vault.

This makes duress lockdown irreversible by anyone, including the legitimate owner: a locked federation's only exit is the recovery path (timelock + 2-of-3 recovery keys). Coercion has no reset to demand, no operator to threaten, and the configured recovery timelock (180-day default) during which the victim can reach safety.

## Consequences

- Lockdown's exit ramp is the recovery path, not an admin action. An accidental or false duress trigger therefore costs a full recovery ceremony — the duress PIN must be deliberate and distinct, never a typo-neighbor of the normal PIN.
- A VPS is never fully sealed against its *provider*: web console and rescue mode remain. Provider-account hygiene (strong 2FA, no session on the coordinator laptop) is part of the security perimeter and must be documented as such.
- Sealing conflicts with in-memory wskdf keys on reboot (no SSH to re-enter the preimage) — resolution tracked separately.
- No upgrade-in-place: security fixes to node software ship by rotating the vault. This is the price of "nothing to coerce."
