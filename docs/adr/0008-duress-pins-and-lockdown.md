# Duress PINs: every spend ceremony carries a silent panic path

Every `/sign` submission requires a PIN. Two are enrolled at setup (hashes in each node's static config): the normal PIN authorizes the requested spend; the duress PIN triggers the vault's configured duress response. Entering either is externally identical, and the two must be deliberately distinct (never typo-neighbors — a false trigger costs a recovery ceremony under sealed nodes, ADR-0005).

Every vault→hot spend is a two-transaction ceremony: the user signs the hot transaction AND an escape-sweep variant on the hardware device, every time, as normalized routine — so under coercion, signing the escape transaction raises no suspicion. The PIN entered at submission decides which one the nodes act on.

The duress response is a per-vault, creation-time choice:

- `lockdown` — nodes sign nothing and refuse everything onward; simplest ceremony (no second signature).
- `sweep_and_lockdown` (recommended default) — nodes instantly sign and broadcast the escape sweep, then lock down.

Lockdown state persists on disk, survives reboots, and — on sealed nodes — has no reset: the only exit is the recovery path (timelock + recovery keys), which is the point: coercion has nothing left to demand.

All post-duress refusals present as automated fraud prevention (`FRAUD_SUSPECTED: funds quarantined by policy`), never as "duress PIN used". The software is open source, so an attacker knows a duress PIN exists — but they can never verify which PIN they were given, and the fraud-lockdown framing means even the on-chain outcome doesn't prove deception. The user's story is "the system locked itself; I cannot override it."

## Consequences

- The PIN doubles as a second factor on every spend: a stolen user key alone can no longer get anything signed (closing most of the remaining stolen-key surface).
- Nodes see submitted PINs in plaintext (hash-compare); a compromised node learns them. Accepted: a minority of nodes cannot act on that alone, and the PIN is defense-in-depth, not the primary control.
- The escape variant must be re-signed whenever the UTXO set changes; the full-balance line on the device screen is covered by the (true) story that the system mandates re-authorizing the security sweep on every spend.
