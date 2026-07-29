# Signet spend record — the core-proven gate, deliverable (1)

Bead `btc-policy-9y5.8` deliverable (1): *"a real SIGNET spend through a live
5-process federation with a NONZERO Hold"*. Every prior acceptance run in this repo
is regtest — a chain the harness spawns, funds by mining, and time-warps. This record
is the first spend of this vault on a **public chain the harness does not control**:
real fee/relay policy, real peers, real ~10-minute block timing, and a Hold that
elapses on wall-clock time rather than by warping a private clock.

Reproduce with `btc-vault signet spend` (see `crates/vault-cli/src/signet.rs`) against
a synced signet node; it prints the same fields recorded below.

## The confirmed spend

| | |
|---|---|
| Network | Bitcoin **signet** (default/global signet, not a custom one) |
| Spend txid | `2a67d484fd8c4a89f75a3ced4d17740fda3e347d53dc33075728a1006907f825` |
| Confirmed in block | `00000011404a6bff9f8cb5e4790d27b3fde488f75575e3e0c0374e2ac03f6353` |
| Block height | 315081 |
| Block time | 1785199867 (2026-07-27 UTC) |
| Size / vsize | 747 B / 281 vB |
| Fee | 2 000 sat (≈ 7.1 sat/vB) |

**Input** — the vault coin, funded on-chain and confirmed before the spend:

```
925d90816847313b28865b47847603635729eef69e36b654526385a69d36aa7f:1   0.00200000 BTC
```

**Outputs**

| Value (BTC) | Address | Role |
|---|---|---|
| 0.00100000 | `tb1qk8jljkalllajdvufy6a34n00amfspjw3h92j22` | hot wallet, derived at index 5 (allowlisted destination) |
| 0.00098000 | `tb1qml684gxlkfru03wvr3j3as95j6697ptsu4z72qjpf5auafvdaspszuvnx9` | change, back to the vault |

**Witness: 7 items**, which is the vault's normal branch satisfied exactly as designed —
`CHECKMULTISIG` dummy, **three federation signatures**, the user signature, the `or_i`
branch selector, and the witness script. The recovery branch is untouched.

## The vault

Descriptor (frozen by the ceremony, checksum included):

```
wsh(or_i(and_v(v:pk(02ca616dc441c873cd8a0981c4bbd943a8c52ed2f0d160a99ca638a9d5042d0e0a),
multi(3,022ba7a5ae1e4bcdf48e30cdf398411c2f27f177fb755da0c00fda19e6a94ee4c4,
02321de515ee328f205fdf4de88116ca6c767e7a3dc4cebfed4e6bc76cb4a707e8,
0243938c2df8deea4418559768fb97d5cb07c05d38213f9d7605c25f7143bd8baf,
033a9d9ab80794a37b71dfd28c53875c3a09a7d428c600f51312e47e1165047860,
039a952f09d9748c33710e538155d3df1b796962c22813c755fc007ca03c8af521)),
and_v(v:older(4224679),multi(2,02070a0412d2b3f3dcce9ec5fa45205825bcb7ba8c570ebf4acfdb0887cc91edf0,
03c144526d18cd639a35326800497b49fa4e06ad03413932f0ecbb982001ae8399,
03cfbb0ece5d8edf32a5040384a8d18fb3e0d61293803d213e5b74f98b574cc8a0))))#lckrt7ws
```

Address: `tb1qml684gxlkfru03wvr3j3as95j6697ptsu4z72qjpf5auafvdaspszuvnx9`
(3-of-5 federation + user, or the 2-of-3 recovery branch after `older(4224679)`.)

The ceremony's own escape/recovery key-independence check ran as part of the bring-up
and reported `VERDICT: no overlap detected` — a shared-seed escape would turn the
claw-back into theft (ADR-0012 threat model), so the run could not have proceeded
without it.

## Policy in force for the run

| Field | Value |
|---|---|
| Threshold | 3-of-5 |
| **Hold** | **120 s, elapsed on real wall-clock time** |
| Combine slack | 120 s |
| Commitment TTL / max age | 3 600 s / 172 800 s |
| Hot budget (per-tx / per-window / window) | 10⁹ sat / 10⁹ sat / 172 800 s |
| Escape feerate floor | 1 sat/vB |
| Escape coverage | 95 % (default) |
| Policy version | 1 |
| Max derivation index | 100 |

## What the run demonstrates

1. **Five separate `vault-node` processes**, each with its own key born in its own
   `setup node-keygen` process, all pointed at the live signet node as their chain
   backend (`channel ON`).
2. **The coordinator relayed the request to exactly ONE node.** That node propagated
   the coordinator-signed request to its peers; each re-ran its own gates and signed at
   ingress. Selective delivery buys a post-wrench coordinator nothing.
3. **A real, non-zero Hold elapsed on wall-clock time** before any partial was
   released — the property regtest's time-warp cannot exercise.
4. **The federation combined and broadcast it, not the coordinator.** Node 5's log:
   `fire: broadcast 2a67d484… for candidate e9588d96…`; the other four then observed
   `already settled on-chain`. `vault-cli` issued zero `sendrawtransaction` calls.
5. **It confirmed in a real signet block** under real relay/fee policy.

## Environment / artifacts

| | |
|---|---|
| Repo commit | `6c04bad44a376b9983ce882a059ae167f772a3de` (branch `feat/9y5.8-signet-spend`) |
| rustc | 1.96.1 (31fca3adb 2026-06-26) |
| cargo | 1.96.2 (356927216 2026-06-26) |
| Bitcoin Core | v31.0.0 (`bitcoind`), signet, `txindex=1` |
| `btc-vault` sha256 | `4c684fad0c5d4a9e592d6d8f0c376ce1a44a3952a881236f8ceda13fb3b5311b` |
| `vault-node` sha256 | `5ff9367965a98d1b246b54a0bb778bf7bb38d8a0a5e8eec2ec034bdea888f722` |
| Signet tip at run | 315 081 |

Binaries are debug builds; the reproducible-release artifact called for by deliverable
(2) is separate work and is **not** claimed by this record.

## Two real-chain findings this run surfaced

Both are things no regtest run could have shown, and both are recorded because they
are properties of the vault on a real chain, not incidental setup trouble.

1. **The chain backend must run `-txindex=1`.** Escape-class union coverage needs
   confirmed-transaction lookup, so a node pointed at a signet daemon without the index
   refuses to start. This belongs in the operator runbook as a hard backend requirement.

2. **Startup UTXO warm is a full `scantxoutset`, and it does not scale.** This signet's
   UTXO set is **72 273 640 outputs**; one scan costs **≈10.4 s**, and Core serializes
   scans process-wide — so five nodes booting at once queue their scans and blow a
   15 s readiness deadline. The driver works around it by spawning nodes sequentially
   and raising the deadline (`VAULT_NODE_READY_TIMEOUT_SECS`), but the underlying cost
   is a genuine scaling limit for a production vault; tracking vault outputs with a
   descriptor wallet instead of repeated full-set scans is the real fix, and is filed
   as follow-up work rather than papered over here.

   *Code change since (bead `btc-policy-hn8`) — NOT a new signet measurement.* The node
   now serves the vault-unspent cache from a node-owned watch-only descriptor wallet
   named from the node identity and watched scripts. A `scantxoutset` runs only on that
   node's FIRST bring-up against a fresh backend — and that scan supplies the wallet's
   birthday, so the import rescans from the oldest live vault output rather than from
   genesis. Restarts issue no scan at all. The scan remains the fallback for a missing,
   failed, or unrecognized wallet — and for a reorg below the wallet's own completion
   anchor, which can un-spend a vault output older than the wallet's birthday and so
   blind a wallet-only read to it until the descriptors are re-imported. A shallower
   reorg cannot: while that anchor's block is active nothing at or below it has moved,
   so every output such a reorg can resurrect was unspent at the anchor and is already
   watched, and the wallet reconciles it with no scan. Every one of those degrades
   slow, never to an understated vault balance.

   The numbers above still stand as this record's only signet observations. Nobody has
   re-run this driver since, so the standing measurement is: 72 273 640 outputs,
   ≈10.4 s/scan, five scans serialized. What the change is expected to alter is the
   restart cost, not that first bring-up; on this driver's own flow the wallet's
   birthday lands at the tip because nodes spawn before `fund_vault`, so first bring-up
   should read the same ≈10.4 s plus a negligible rescan. **Re-measuring that on signet
   is outstanding.**

## Staleness — this record is about ONE COMMIT, not about `main`

The run recorded here was performed at repo commit `6c04bad` with debug binaries whose hashes are
listed above. `main` has moved substantially since — including chain-tracking and concurrency work
that touches the very paths this run exercised. **Nothing here is evidence about current `main`.**

A re-run against a frozen release candidate is what deliverable (2) of `btc-policy-9y5.8` needs,
and this record should be regenerated at that commit rather than cited as if it travelled forward.

## Scope — what this record does NOT claim

- It is **one honest spend**. Duress, claw-back, reorg, and refusal behaviour on signet
  are not covered here; those remain proven on regtest (`attack all`, the demos).
- Deliverable (2) (full matrix incl. proptest/fuzz with reproducible-release artifacts)
  and deliverable (3) (**one genuine external human security review**) of bead
  `btc-policy-9y5.8` are untouched by this record. Per the bead, correlated automated
  review — including this repo's `codex` + Claude Fable panels — **does not** satisfy
  (3).
