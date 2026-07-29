# Rollout plan

The ten-stage ladder from "five daemons on a laptop" to public alpha, agreed 2026-07-29.

It exists because a state review found that **Core-proven** and **Production-ready** had fused
into one milestone called "v0 done" — which let a strong protocol core read as a shippable
custody system. They are now separate (see `CONTEXT.md`), and this document is the path between
them.

## What varies, and why it varies separately

Three axes, moved one at a time so a failure is attributable:

| Axis | From | To |
|---|---|---|
| **Host distribution** | five daemons on one machine | five machines, one provider → many providers |
| **Host hardening** | open (SSH, admin access) | **Sealed host** (ADR-0005 in full) |
| **Network** | signet | mainnet |

**Correction (2026-07-29 plan review):** the "one axis at a time" framing is true only against a
reference rung, NOT between consecutive ones — 3→4 moves hardening *and* network, and 5→6 moves
all three. Both reviewers called the attribution argument overstated, and they are right: stage
7→8 already flips only the network, so a stage-8 failure is attributable whether or not stages 3
and 5 exist. What stages 3 and 5 actually buy is earlier exposure to mainnet fee/relay reality —
paid for in real funds on topologies the design itself forbids. Read this table as a test matrix
with a funding policy, not as a monotonic hardening curve.

**Value-at-risk is a FOURTH axis, and it is not the same as "mainnet".** Mainnet can be exercised
with dust. Reaching a mainnet rung is **not** authorisation to move meaningful savings; value moves
last, after stage 9.

**Stages 2-5 run under an explicit test-only waiver of ADR-0009** (ADR-0015). All five nodes sit at
one provider there — a correlation class holding quorum — and **sealing does not fix that**, because
ADR-0005 concedes provider console and rescue access survive. Every mainnet rung is therefore
**capped at dust**, and the waiver expires at stage 6; from there `imb`'s deploy-time enforcement
refuses a co-located federation outright. Both reviewers recommended reordering instead; the
decision was to keep the ordering and bound the exposure. ADR-0015 records what that accepts.

What it does NOT accept, because these are wired as hard blockers of stage 3 (`btc-policy-4wx`)
rather than left to discipline: coordinator hardening (`4y3`) and the fire-path mempool fix
(`zzv`).

**Hardware signing (`bq6`) is deliberately deferred past the capped rungs** — the dust cap is the
mitigation for a software user key on the coordinator — but it gates the stage-9 freeze, because
the caps cannot be lifted, and an alpha cannot ship, with the user key as a file on the machine
ADR-0012 already names as the severe residual.

## The ladder

| Stage | Hosts | Hardening | Network | Notes |
|---|---|---|---|---|
| **1** | one machine | open | signet | Path suite on signet for the first time. **Freeze → external review #1 (protocol core).** |
| **2** | 5 machines, same provider | open | signet | First real network transport; loopback assumptions die here. Waived (ADR-0015). |
| **3** | 5 machines, same provider | open | **mainnet** | First real funds, **dust cap**. Waived (ADR-0015). Requires `4y3`+`zzv`. |
| **4** | 5 machines, same provider | **sealed** | signet | First sealed hosts. **Begin measuring attrition.** Waived (ADR-0015). |
| **5** | 5 machines, same provider | sealed | **mainnet** | **Dust cap.** Waived (ADR-0015). Gated on `nju` being decided. |
| **6** | **many providers** | open | signet | Provider diversity — the ADR-0009 correlation-class requirement. |
| **7** | many providers | **sealed** | signet | Attrition measurement continues under provider diversity. |
| **8** | many providers | sealed | **mainnet** | **Run it for a while**, capped. The Survivor vault is the observation subject. |
| **9** | many providers | sealed | mainnet | Full Path suite on the real configuration. Requires `bq6` (hardware signing) before the caps lift. **Freeze → external review #2 (deployed system).** |
| **10** | — | — | — | Public alpha. |

## Per-stage testing: two vaults

Every stage runs **two** vaults, because two paths are terminal — a duress arm ends in
unconditional Lockdown for the federation's lifetime, and Recovery spends the coins out.

**Survivor vault** — non-destructive paths, then stays funded and running:

1. Honest hot spend (normal PIN, allowlisted destination, Hold elapses, nodes combine and broadcast)
2. Refresh (pin-less self-spend, resets the recovery timelock)
3. Theft refusal (non-allowlisted destination → `DEST_NOT_ALLOWED`; over-cap → `HOT_BUDGET_EXCEEDED`)
4. Clawback (escape-class spend under the normal PIN, fires immediately, defeats a pending spend)

**Sacrificial vault** — driven to its terminal end:

5. Duress arm (duress PIN) → `T` → escape sweep → unconditional Lockdown
6. Recovery (2-of-3 recovery keys after the timelock), from the locked-down vault

Step 5 → 6 is not an artificial sequence: after Lockdown the Recovery path *is* the only exit, so
the Sacrificial vault rehearses the real incident rather than approximating it. A stage where 6
cannot be completed from cold artifacts alone (descriptor + manifest + recovery keys, no live
federation) has not passed.

**How step 6 has anything left to spend.** A *successful* step-5 sweep moves the coins to the escape
wallet, leaving the dead vault empty — so Recovery would have nothing to exercise. Step 6 therefore
runs against a **fresh deposit made to the locked-down vault after Lockdown**, which is also the more
valuable drill: "coins arrived at a vault that can no longer sign" is a real incident (a straggler
deposit, a counterparty paying a stale address), and Recovery is its only exit. Do not instead
arrange a deliberately failed sweep — that tests the escape's failure path, not Recovery's.

## The recovery timelock is configurable

The 180-day timelock is a **default, not an invariant**. It is chosen per vault at creation, with
a warning when a low value is used. Without this, "test all paths on signet" would mean 180 days
of wall-clock per Recovery test, and Recovery — the last exit when everything else has failed —
would only ever be exercised against a faked clock on regtest.

This is a deliberate loosening: `parse_vault_template` previously *required* exactly
`RECOVERY_TIMELOCK_NSEQUENCE`. A short timelock is a weaker vault (a thief holding 2-of-3
recovery keys waits hours instead of months), which is what the warning is for. Tracked in
`btc-policy-wdu`.

**On mainnet, a below-default timelock requires typed confirmation that is RECORDED in the
ceremony artifacts.** There is deliberately no hard floor — the choice stays the operator's — but it
cannot be made by accident or by scrolling past a warning, and an auditor can see afterwards that it
was chosen deliberately. This answers the reviewers' concrete failure case: confusing BIP68 512-second
units for days, or copying a signet configuration to mainnet, would otherwise seal a vault whose
2-of-3 recovery keyset becomes a complete spend path about eight minutes later — unrepairable, since
the manifest is immutable. Signet and regtest keep warn-only.

**Only the Sacrificial vault may use a short timelock.** Both reviewers independently confirmed
the interaction: a Survivor vault left deliberately "untouched" at stage 8 runs past its own
recovery maturity, and the 2-of-3 recovery keyset — which this design distributes to THIRD PARTIES,
since it doubles as the inheritance mechanism — becomes a complete authorization path for real
mainnet funds, with no PIN, no user key, no Hold, no allowlist and no federation involved. The
recovery alert is post-spend: by the time it fires the coins are moving and the normal path cannot
stop them.

So: **Survivor vaults use the production default timelock**, publish their maturity countdown, and
Refresh (or migrate) before a mandatory safety margin — which is also more faithful observation,
since a real long-lived vault is refreshed rather than untouched. **The two vaults must not share
recovery keys**, because the Sacrificial ceremony deliberately exposes and uses those keys.

## Sealing, attrition, and the deferred lifecycle decision

"Locked" means **Sealed host**: ADR-0005 in full — no SSH, no administrative path, no
upgrade-in-place, and a reboot kills the node (ADR-0007).

**Sealing does NOT make one provider safe.** ADR-0005 itself says a VPS "is never fully sealed
against its *provider*: web console and rescue mode remain." So five sealed nodes at a single
provider remain a correlation class holding quorum — ADR-0009 is violated by stages 2–5 whether
or not the hosts are sealed. This is the strongest argument for moving provider diversity earlier
than this table currently does (see the open ordering question at the end).

The consequence is uncomfortable and deliberate: **patching a node means rotating the vault**, and
a dead node has no remedy. Whether that is livable is an empirical question, so stages 4 and 7
(signet, cheap to lose) **measure node attrition and the true cost of a migration-to-patch**. That
data decides `btc-policy-nju`'s open question — immutable one-shot nodes versus recoverable
hardware-backed nodes with a durable monotonic Lockdown latch — **before** stages 5 and 8 put
mainnet funds behind either.

Deciding now, without the attrition numbers, is what this defers. The risk it accepts is possibly
rebuilding the node lifecycle mid-ladder.

## Where the two reviews sit

- **After stage 1** — the protocol core, against a frozen artifact. Early because a core finding
  discovered at stage 9 invalidates everything built on top of it.
- **Before stage 10** — the deployed system, against a frozen artifact. Late because an alpha
  needs the thing users will actually run reviewed, not a single-machine prototype.

Both must target a **frozen, reproducible** build (`btc-policy-gbw`), not a moving branch. Neither
is satisfied by automated review: correlated AI panels — including this repo's own codex + Fable
loops, however adversarially prompted — are explicitly not a substitute (`docs/THREAT-MODEL.md`
R7).

## What stage 1 needs that does not exist yet

Stage 1 is close to what the repo can already do, but not reachable today:

- **`btc-policy-mby`** — the operator CLI. Nothing outside `setup.rs` reads `manifest.json`, so a
  sealed vault cannot currently be spent from, refreshed, clawed back, or recovered by any
  command. Steps 1–6 above all need it.
- **`btc-policy-wdu`** — the configurable timelock, or step 6 takes 180 days.
(**`btc-policy-bq6`**, hardware signing, is deliberately NOT on this list — see above and ADR-0015.
Stage 1 runs on signet with a software user key, and the dust cap carries that risk through the
capped mainnet rungs. It is required before the caps lift.)

Stages 2+ additionally need **`btc-policy-imb`** (independent hosts, authenticated transport,
correlation enforcement). From stage 4, the **sealed node image** is `btc-policy-nwd` — NOT `4y3`,
which is *coordinator* host hardening and is required earlier, by stage 3 (ADR-0015). These are two
different machines and two different threats; conflating them is an error this document has already
made once.
