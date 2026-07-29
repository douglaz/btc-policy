# Rollout funding caps, and a test-only waiver of ADR-0009

ADR-0009 forbids any correlation class from reaching quorum. The rollout ladder
(`docs/ROLLOUT-PLAN.md`) nevertheless runs stages 2 through 5 with all five nodes at a **single
hosting provider** — a correlation class holding quorum — and stages 3 and 5 put **real mainnet
funds** behind that topology.

That is a knowing violation, and this ADR is what makes it knowing rather than accidental. Two
independent reviews flagged it; the decision after seeing them was to keep the ladder's ordering
and bound the exposure instead of reordering.

## Decision

**1. Stages 2–5 operate under an explicit, time-limited, test-only waiver of ADR-0009.** A
federation provisioned under this waiver is a *laboratory*, never a custody deployment, whatever
network it runs on.

**2. Every mainnet rung is capped, and the cap must be a NUMBER WITH AN OBSERVER before any mainnet
rung is funded.** "An amount whose total loss is operationally irrelevant" is an intention, not a
control — an operator negotiates that with themselves at funding time. So:

- `btc-policy-cod` sets the per-stage figure and **blocks `4wx`**: stage 3 cannot be funded before a
  cap exists in writing.
- The cap must be **observable by the machinery that already watches the vault**. Inflow is
  permissionless — anyone can deposit, and no code knows "this is a stage-3 vault" — and the manifest
  pins *outflow* (ADR-0014), never balance. Nodes already maintain a vault-unspent cache, so a
  manifest-pinned stage balance ceiling with a watchtower alert on breach makes the cap enforceable
  by the same path that raises every other alert. Without that, the void-clause below is undetectable.
- Reaching a mainnet rung is **not** authorisation to move meaningful savings. Value-at-risk is a
  separate axis, and it moves last.

**2a. The cap fights the purpose of the rungs it protects, and the answer is pre-committed here.**
Stages 3 and 5 exist for earlier exposure to real fee and relay behaviour. At true dust, fees dominate
the outputs and the RBF escape ladder, ancestor pressure and relay evidence are all unrepresentative
— so the honest experimenter's conclusion at stage 3 will be "we need slightly more to get real
data." That pressure is built into the rung's own justification. **The pre-committed answer: accept
unrepresentative fee data at stages 3 and 5.** Representative fee behaviour is acquired at stage 8's
soak, under provider diversity and sealing, where the topology no longer violates ADR-0009. Anyone
proposing to raise a waived stage's cap for better fee data is proposing to void this ADR (below),
not to tune it.

**2b. The waiver expires the TOPOLOGY, and also the SECRETS. Nothing provisioned under the waiver
crosses stage 6.** A stage-2–5 federation lives entirely inside one provider's console reach, so
every secret it touched must be treated as exposed to that provider: operator preimages, node keys,
escape-wallet keys, recovery keys, the coordinator auth key, and the coordinator host itself. Reusing
any of them in a post-waiver federation leaks the waiver forward past its own expiry and silently
un-does it. Fresh key material at stage 6, no exceptions; mechanics in `cod`.

**3. `imb`'s deploy-time correlation enforcement gains an explicit test-mode bypass**, and using
it must be recorded in the stage's artifacts. Without this, `imb` (which promises to *refuse* a
co-located federation) and `4wx` (which *requires* one provider) could not both pass honestly —
the contradiction that prompted this ADR.

**4. The waiver expires at provider diversity.** From stage 6 onward the bypass is unavailable,
and any federation that would need it fails to deploy. The waiver cannot reach an alpha.

## Why sealing does not substitute for diversity

ADR-0005 concedes it directly: *"A VPS is never fully sealed against its provider: web console
and rescue mode remain."* Sealing removes the operator's access, not the provider's. Five sealed
nodes at one provider are therefore still one entity away from quorum, so stages 4 and 5 need
this waiver exactly as much as 2 and 3 do. Any reading in which sealing "fixes" the topology is
wrong.

## What the waiver does NOT cover

By the time stage 3 (first mainnet funds) is reached, these are required — wired as hard
dependencies of `btc-policy-4wx`, not left to discipline:

- **Coordinator host hardening** (`4y3`). The one accepted conditional-theft residual.
- **The fire-path mempool scaling fix** (`zzv`), because mainnet is where congestion is real.

**Hardware signing (`bq6`) is deliberately NOT required for the capped mainnet rungs.** Decided
2026-07-29. Without it the user key is software on the coordinator host, which merges adversary A3
with residual R8b — an attacker who owns that host skips the wrench entirely and signs. That is a
real capability, and the reason it is acceptable here is precisely the dust cap: **the cap is the
mitigation.** What such an attacker gets at stages 3–8 is dust.

The consequence is that **`bq6` becomes mandatory before the caps are lifted**, and it gates the
stage-9 freeze (`u5r`) — the last point before an alpha, and the artifact external review #2
examines. An auditor handed a "deployed system" whose user key is a file on the coordinator will
say so immediately, and they will be right.

So the residual risk this ADR knowingly accepts at stages 3 and 5 is narrower than "one provider,
nothing else done": it is **provider-level quorum correlation, a software user key on the
coordinator, unsealed node hosts at stage 3, and an unresolved node lifecycle** — every one of them
bounded by the dust cap, and none of them permitted past stage 9.

## Consequences

- A provider-account compromise (or a provider acting adversarially, or under legal compulsion)
  during stages 2–5 yields all five node keys. Since hardware signing is deferred past these rungs,
  the user key is a file on the coordinator host — so an attacker who takes both gets a complete
  authorization path and none of the off-chain policy (PIN, allowlist, Hold, duress, release gate)
  applies. **The cap is the entire mitigation, and it is the only one.** That is the trade this ADR
  exists to record.
- Provider-account hygiene (strong 2FA, no provider session on the coordinator host) is part of
  the security perimeter for these stages, as ADR-0005 already states.
- Stages 2–5 produce **no evidence about correlation-class independence.** Any claim of ADR-0009
  compliance dates from stage 6, not earlier, and the stage-9 review must be told so.
- If the dust cap is ever raised on a waived stage, this ADR is void and the ladder must be
  reordered to reach provider diversity first.

## Alternatives rejected

- **Reorder the ladder** (both reviewers' recommendation: multi-provider before sealing and before
  any mainnet). Rejected to keep the ladder's experiment-per-rung structure; the caps and this
  waiver are the compensating controls.
- **Drop stages 3 and 5 to signet.** Rejected for the same reason — earlier exposure to real fee
  and relay behaviour was judged worth the capped risk.
- **Silence.** Rejected outright: `imb` and `4wx` would have contradicted each other in the bead
  graph, and the first person to implement `imb`'s enforcement would have blocked the ladder
  without knowing why.
