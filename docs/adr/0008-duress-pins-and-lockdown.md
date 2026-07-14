# Duress PINs: every spend ceremony carries a silent panic path

Every `/sign` submission requires a PIN. Two are enrolled at setup (hashes in each node's static config): the normal PIN authorizes the requested spend; the duress PIN triggers the vault's configured duress response. Entering either is externally identical, and the two must be deliberately distinct (never typo-neighbors — a false trigger costs a recovery ceremony under sealed nodes, ADR-0005).

Every vault→hot spend is a two-transaction ceremony: the user signs the hot transaction AND an escape-sweep variant on the hardware device, every time, as normalized routine — so under coercion, signing the escape transaction raises no suspicion. The PIN entered at submission decides which one the nodes act on.

The duress response is a per-vault, creation-time choice:

- `lockdown` — nodes sign nothing and refuse everything onward.
- `sweep_and_lockdown` (recommended default) — the escape sweep plus lockdown.

**Silent, deferred, sign-now/broadcast-later, node-distributed, no abort** (revised 2026-07-14, superseding the original "instant sweep + instant lockdown"):

- **Silent and deferred.** An observable countermeasure endangers a hostage, so the duress PIN does NOTHING observable at entry. It schedules the escape sweep and lockdown to fire together after `duress_delay_secs` (a per-vault config value, decoupled from `hold_secs`; `0` is allowed = instant). During `[T, T+delay]` the nodes behave normally, so nothing on-chain or in node responses reveals the pending response.
- **Sign now, broadcast later.** At entry T the coordinator assembles the fully-signed escape transaction (quorum of node sigs + the user's escape-variant sig) and distributes the *complete* tx to all n nodes. Because it is fully pre-signed, firing it needs no federation re-cooperation — it cannot be easily interrupted, and a passively-dead coordinator no longer stops it. Signing is off-chain, so this stays silent.
- **Node-distributed broadcast (the only acceptable design).** Each node independently broadcasts the pre-signed tx at T+delay via its own chain backend (V0-6), and enters lockdown at the same moment. Suppressing the broadcast requires taking down all n nodes. The coordinator is not needed after T; only a coordinator malicious at the instant of entry can starve it (it must assemble the quorum, since there is no intra-node gossip) — the general "coordinator trusted in MVP" boundary, and the acknowledged v1 hardening target.
- **No abort.** Once entered, nothing halts it — no key, no PIN, no command. This removes the coercion lever entirely: the victim can truthfully say "I can't stop it, nobody can," which is the strongest answer under a wrench attack. It also makes distributing the pre-signed tx to all nodes pure upside (no abort-must-reach-all-holders problem). Accepted cost: a mis-entered duress PIN is unstoppable and sweeps funds to the escape wallet — recoverable (funds are in your own cold wallet; re-setup the vault), and rare given the deliberately-distinct duress PIN.

Lockdown state persists on disk, survives reboots, and — on sealed nodes — has no reset: the only exit is the recovery path (timelock + recovery keys), which is the point: coercion has nothing left to demand.

All post-duress refusals present as automated fraud prevention (`FRAUD_SUSPECTED: funds quarantined by policy`), never as "duress PIN used". The software is open source, so an attacker knows a duress PIN exists — but they can never verify which PIN they were given, and the fraud-lockdown framing means even the on-chain outcome doesn't prove deception. The user's story is "the system locked itself; I cannot override it."

## Consequences

- The PIN doubles as a second factor on every spend: a stolen user key alone can no longer get anything signed (closing most of the remaining stolen-key surface).
- Nodes see submitted PINs in plaintext (hash-compare); a compromised node learns them. Accepted: a minority of nodes cannot act on that alone, and the PIN is defense-in-depth, not the primary control.
- The escape variant must be re-signed whenever the UTXO set changes; the full-balance line on the device screen is covered by the (true) story that the system mandates re-authorizing the security sweep on every spend.
- Node-distributed broadcast makes this depend on V0-6 (node chain backend): V0-4 cannot be built until nodes can broadcast. Two escape *timings* now coexist for the same destination: duress = delayed + silent; manual rotate / watchtower race = instant (`duress_delay_secs`-independent).
- Lockdown fires at T+delay, not at entry, precisely to keep the window silent (an immediate freeze would reveal the trigger to an attacker who probes with another spend).
