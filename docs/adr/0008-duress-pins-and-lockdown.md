# Duress PINs: every spend ceremony carries a silent panic path

> **The mechanism is consolidated into [ADR-0012](0012-model-b-spend-and-duress-architecture.md), which is the source of truth** for the duress state machine (arm → armed/silent-freeze → fire → lockdown), the node-assembled deterministic escape, and the corrected threat model. This ADR remains for the dual-PIN and lockdown rationale; where it says the coordinator assembles/distributes the escape, 0012 supersedes it (nodes do). Read 0012.


Every `/sign` submission requires a PIN. Two are enrolled at setup (hashes in each node's static config): the normal PIN authorizes the requested spend; the duress PIN triggers the vault's configured duress response. Entering either is externally identical, and the two must be deliberately distinct (never typo-neighbors — a false trigger costs a recovery ceremony under sealed nodes, ADR-0005).

Every vault→hot spend is a two-transaction ceremony: the user signs the hot transaction AND an escape-sweep variant on the hardware device, every time, as normalized routine — so under coercion, signing the escape transaction raises no suspicion. The PIN entered at submission decides which one the nodes act on.

The duress response is a per-vault, creation-time choice:

- `lockdown` — nodes sign nothing and refuse everything onward.
- `sweep_and_lockdown` (recommended default) — the escape sweep plus lockdown.

**Silent, deferred, sign-now/broadcast-later, node-distributed, no abort** (revised 2026-07-14, superseding the original "instant sweep + instant lockdown"):

- **Silent and deferred.** An observable countermeasure endangers a hostage, so the duress PIN does NOTHING observable at entry. It schedules the escape sweep and lockdown to fire together after `duress_delay_secs` (a per-vault config value, decoupled from `hold_secs`; `0` is allowed = instant). During `[T, T+delay]` the nodes behave normally, so nothing on-chain or in node responses reveals the pending response.
- **Nodes assemble and broadcast — not the coordinator.** The escape is not a special mechanism: it rides the same node assembly+broadcast path as every spend (ADR-0010/0011). The coordinator relays `{intent, user_sigs, pin}`; each node builds the escape sweep from its own chain view, gathers the other partials over the node-to-node channel, and at T+delay broadcasts the complete tx via its own chain backend and enters lockdown. The coordinator never holds a broadcastable escape, so it cannot broadcast it early (breaking silence), cannot choose it, and cannot prevent the lockdown. Signing is off-chain, so the window stays silent.
- **A coordinator compromised at entry can only censor.** Its sole power is to drop the request (deny) — never redirect, never control broadcast, never steal. Denial keeps funds safe in the vault. This is the accepted residual of ADR-0010; guaranteed delivery under a hostile coordinator is the v1 user↔node direct path.
- **No abort.** Once entered, nothing halts it — no key, no PIN, no command. This removes the coercion lever entirely: the victim can truthfully say "I can't stop it, nobody can," which is the strongest answer under a wrench attack. Accepted cost: a mis-entered duress PIN is unstoppable and sweeps funds to the escape wallet — recoverable (funds are in your own cold wallet; re-setup the vault), and rare given the deliberately-distinct duress PIN.
- **The pin is un-substitutable because it is ephemeral.** No encryption or signature-binding is needed. Pins are held in RAM only and **never persisted or logged anywhere — coordinator or node** (not the sign log, the anti-replay log, an alert, or disk; at the node, hash-compared and immediately discarded). A coordinator is honest during normal operation, so it accumulates no pin history; a coordinator compromised *only at the duress moment* has never seen the normal pin and cannot swap it in. And the user always enters the *duress* pin under coercion, so the normal pin is never observed by an attacker. This "never log pins" property is load-bearing security, not hygiene — the day a request is logged "for debugging," substitution comes back.

Lockdown state persists on disk, survives reboots, and — on sealed nodes — has no reset: the only exit is the recovery path (timelock + recovery keys), which is the point: coercion has nothing left to demand.

All post-duress refusals present as automated fraud prevention (`FRAUD_SUSPECTED: funds quarantined by policy`), never as "duress PIN used". The software is open source, so an attacker knows a duress PIN exists — but they can never verify which PIN they were given, and the fraud-lockdown framing means even the on-chain outcome doesn't prove deception. The user's story is "the system locked itself; I cannot override it."

## Consequences

- The PIN doubles as a second factor on every spend: a stolen user key alone can no longer get anything signed (closing most of the remaining stolen-key surface).
- Nodes see submitted PINs in plaintext (hash-compare); a compromised node learns the one pin used in the request it handled, and nothing more (pins are never logged). Accepted: a minority of nodes cannot act on that alone, and the PIN is defense-in-depth, not the primary control.
- The escape variant must be re-signed whenever the UTXO set changes; the full-balance line on the device screen is covered by the (true) story that the system mandates re-authorizing the security sweep on every spend.
- Depends on the node assembly+broadcast spine (ADR-0010/0011): the escape uses it, so duress can't be built until nodes assemble+broadcast. Lockdown itself is node-local and needs no channel. Two escape *timings* coexist for the same destination: duress = delayed + silent; manual rotate / watchtower race = instant (`duress_delay_secs`-independent).
- Lockdown fires at T+delay, not at entry, precisely to keep the window silent (an immediate freeze would reveal the trigger to an attacker who probes with another spend).
