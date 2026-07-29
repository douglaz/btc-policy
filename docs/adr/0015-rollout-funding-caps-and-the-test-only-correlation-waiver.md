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

**2. Every mainnet rung is capped at a dust-level amount** — an amount whose total loss is
operationally irrelevant. Reaching a mainnet rung is **not** authorisation to move meaningful
savings. Value-at-risk is a separate axis from network, and it moves last.

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

By the time stage 3 (first mainnet funds) is reached, these are required — they are wired as
hard dependencies of `btc-policy-4wx`, not left to discipline:

- **Hardware signing** (`bq6`). Without it the user key is software on the coordinator host,
  which merges adversary A3 with residual R8b — the attacker skips the wrench entirely.
- **Coordinator host hardening** (`4y3`). The one accepted conditional-theft residual.
- **The fire-path mempool scaling fix** (`zzv`), because mainnet is where congestion is real.

So the residual risk this ADR knowingly accepts at stages 3 and 5 is narrower than "one provider,
nothing else done": it is **provider-level quorum correlation, unsealed node hosts at stage 3, and
an unresolved node lifecycle**, bounded by a dust cap.

## Consequences

- A provider-account compromise (or a provider acting adversarially, or under legal compulsion)
  during stages 2–5 yields all five node keys. Combined with the user key — which stage 3 requires
  to be in hardware — that is theft of whatever the cap allows. The cap is the entire mitigation.
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
