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

Moving two at once would make a stage-8 failure unattributable, which is the whole reason the
ladder is this long.

## The ladder

| Stage | Hosts | Hardening | Network | Notes |
|---|---|---|---|---|
| **1** | one machine | open | signet | Path suite on signet for the first time. **Freeze → external review #1 (protocol core).** |
| **2** | 5 machines, same provider | open | signet | First real network transport; loopback assumptions die here. |
| **3** | 5 machines, same provider | open | **mainnet** | First real funds. Path suite again. |
| **4** | 5 machines, same provider | **sealed** | signet | First sealed hosts. **Begin measuring attrition.** |
| **5** | 5 machines, same provider | sealed | **mainnet** | |
| **6** | **many providers** | open | signet | Provider diversity — the ADR-0009 correlation-class requirement. |
| **7** | many providers | **sealed** | signet | Attrition measurement continues under provider diversity. |
| **8** | many providers | sealed | **mainnet** | **Run it for a while.** The Survivor vault is the observation subject. |
| **9** | many providers | sealed | mainnet | Full Path suite on the real configuration. **Freeze → external review #2 (deployed system).** |
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

## The recovery timelock is configurable

The 180-day timelock is a **default, not an invariant**. It is chosen per vault at creation, with
a warning when a low value is used. Without this, "test all paths on signet" would mean 180 days
of wall-clock per Recovery test, and Recovery — the last exit when everything else has failed —
would only ever be exercised against a faked clock on regtest.

This is a deliberate loosening: `parse_vault_template` previously *required* exactly
`RECOVERY_TIMELOCK_NSEQUENCE`. A short timelock is a weaker vault (a thief holding 2-of-3
recovery keys waits hours instead of months), which is what the warning is for. Tracked in
`btc-policy-wdu`.

## Sealing, attrition, and the deferred lifecycle decision

"Locked" means **Sealed host**: ADR-0005 in full — no SSH, no administrative path, no
upgrade-in-place, and a reboot kills the node (ADR-0007).

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
- **`btc-policy-bq6`** — hardware signing, if stage 1 is to reflect the design's actual premise
  rather than a software user key.

Stages 2+ additionally need **`btc-policy-imb`** (independent hosts, authenticated transport,
correlation enforcement) and, from stage 4, **`btc-policy-4y3`** (sealed-host build).
