# Operations runbook

Part of the core-proven gate's artifact set (bead `btc-policy-9y5.8` deliverable 2). The
ceremony has its own document (`docs/SETUP-CEREMONY.md`); this covers **running** the vault
afterwards, and what to do when something is wrong.

Written for the person who will be tired, possibly frightened, and reading this at the worst
moment. Where a step is dangerous, it says so.

## 0. The one thing to know first

**If you are being coerced, use the duress PIN.** It behaves identically to the normal PIN from
the attacker's side — same responses, same timing, same everything — while silently arming an
escape sweep and locking the federation down. Do not try to signal anything else. Do not stall.
Complete the ceremony normally with the other PIN.

Everything else in this document is secondary to that.

## 1. Daily / routine checks

| Check | How | Healthy answer |
|---|---|---|
| Each node is serving | `GET /healthz` on every node | `{"serving": true, "locked_down": false, ...}` |
| The deadline driver is alive | `last_deadline_tick` in `/healthz` | advancing; a stale value means the driver stopped and Lockdown-at-T may not fire |
| No unexpected pending spend | `GET /pending` on every node | `{"pending":[]}`, or only ids matching spends you authorized |
| No unexpected on-chain activity | `GET /events` on any node | empty, or only alerts you can explain |
| Enough nodes are up | count of serving nodes | **≥ 3 of 5**. At 3 you have no margin — fix it before anything else. |

`/healthz` is deliberately three atomic loads and nothing else, so polling it costs nothing and
cannot interfere with signing. `/pending` takes one bounded snapshot of the node's accepted hot
candidate ids; poll it at an interval appropriate to the Hold, and compare every id with the
spends you authorized. It serves one snapshot at a time: a `429` means another read is already in
flight, so retry it — that is a shed read, not a down node, and above all not an empty
projection.

## 2. Reading `/events`

| Event | Means | Do |
|---|---|---|
| `RECOVERY_PATH_SPEND` | A spend used the 2-of-3 recovery branch | If it was not you: **the recovery keys are compromised.** The coins are moving and the normal path cannot stop them. Treat as an active incident. |
| `UNRECOGNIZED_SPEND` | A vault UTXO was spent by a transaction this node never policy-accepted | If it was not an expected external event, treat as an active incident. |
| `CHANNEL_FRESHNESS_REJECT` | A peer's clock is outside the freshness window | Fix that peer's clock. A node with a bad clock silently drops out of the combine set, which quietly erodes your 3-of-5 margin. |

## 3. Refusals — what the node is telling you

Refusals are normal. They are the vault working. The ones worth understanding:

| Code | Meaning | Usual cause |
|---|---|---|
| `DEST_NOT_ALLOWED` | Output pays a non-allowlisted script | Spending to a new address that is not in the allowlist — by design, this is a **sealed** list |
| `HOT_BUDGET_EXCEEDED` | Per-tx cap or velocity window exceeded | Spending too much, or too much too fast (ADR-0014) |
| `FEE_EXCEEDS_CAP` | Fee above the bug-guard cap | Usually a malformed request, not a fee-market problem (ADR-0006) |
| `BAD_PIN` | PIN did not match either enrolled PIN | Typo — **or** the attempt budget is engaging. Repeated failures back off, then lock out. Lockout is a transient rate-limit, **not** Lockdown. |
| `COMMITMENT_EXPIRED` | The request outlived its expiry on this node's clock | Slow chain backend or a clock problem; the carrier is still forwarded |
| `REFRESH_SUBORDINATED` | A refresh was refused because a spend is pending | Correct behaviour — refreshes never race a pending spend |
| `FRAUD_SUSPECTED` | This node is **locked down** | Terminal. See §5. |

A refusal is byte-identical under both PINs by design. **Never** try to infer the PIN class from
a response — you cannot, and the property that you cannot is what protects the user.

## 4. Node lifecycle

**Starting a node.** The signing key is *derived at start* from the operator preimage supplied on
stdin, never stored. So every start — first boot, restart, or recovery — needs that preimage.

**Stopping a node.** A stopped node is simply absent; 3-of-5 tolerates two. It does not need to
be drained.

**A node's FIRST start against a given bitcoind takes longer than its restarts** and does not
answer `/healthz` until it finishes. It warms its vault-unspent view before serving, and that
first pass runs a `scantxoutset` (~10 s on signet's 72M-output set, and Core serializes scans
process-wide, so five nodes sharing one backend queue behind each other) and then imports the
vault descriptors into its own watch-only wallet — which rescans from the vault's oldest live
output, so against an already-funded vault that import, not the scan, dominates. Bring nodes up
one at a time on a real chain and expect minutes, not seconds. Every later start reads the wallet
instead and is fast. See `docs/THREAT-MODEL.md` R5.

**A node that says it is falling back to `scantxoutset` is slow, not wrong.** Two log lines
report it — `vault descriptor-wallet read unavailable, falling back to scantxoutset: …` and
`vault descriptor wallet not established, scantxoutset stays in use: …`. In both, the node keeps
a complete scan-derived view of the vault's coins; nothing it accepts or refuses changes. What
changes is cost: it is back to paying the scan above, on a resource Core serializes across every
node sharing that bitcoind, which is a readiness problem long before it is anything else. **Do:**
the first line retries itself on the next refresh pass; the second may print once and never
again, because the node re-attempts that build on its next start — so restart it. If the message
survives that, read its tail. `is not a complete
node-owned vault wallet` means a wallet carrying this node's own generated name exists but this
node did not build it — it will never write to a wallet it does not recognise, so move that
wallet aside and restart. Anything else is bitcoind refusing to make one (no wallet support
compiled in, a full or read-only wallet directory). Neither is urgent the way §5 is, but do not
leave it: see `docs/THREAT-MODEL.md` R5.

**A rebooted node is a dead node** (ADR-0007). The model assumes config and keys live on tmpfs,
so a reboot wipes the signing key, the Lockdown latch, and the process-generation marker. If the
node warns at startup that its inode is on a non-volatile filesystem, that assumption does not
hold on that host — record it, because it changes the threat model (`docs/THREAT-MODEL.md` R3).

**Upgrading — there is no in-place path.** ADR-0005 seals the host: SSH is uninstalled and no
administrative access path remains, so a "just restart it with the new binary" procedure is not
performable on a correctly sealed node, and would be the reset a coercer wants if it were. A
binary change is a vault MIGRATION (`docs/UPGRADE-AND-ROTATION-POLICY.md` §2-3). Plan for that
cost before you need it.

**On the preimage and restarts.** The signing key is derived at start and never stored, so any
start needs the preimage — but on a sealed host there is no supported way to *cause* a restart,
and ADR-0007 treats a rebooted node as dead. Keep the preimage backed up because ceremony and
recovery need it, not because routine restarts are a procedure you have.

## 5. Lockdown

`locked_down: true` is **terminal for that node's lifetime**. It answers `FRAUD_SUSPECTED` to
every spend and does nothing else. It happens when:

- a duress PIN armed an escape and `T` arrived (unconditionally — whether or not the sweep
  succeeded), or
- a fail-closed safety net fired (a poisoned lock, a panic on a critical path).

**Do not try to clear it.** There is no supported un-lockdown, and a node you coax back into
serving after a duress event is a node serving the person who caused the duress event.

If the whole federation is locked down, the vault is in its designed end state: the coins are
either already swept to the escape wallet, or they are frozen and exit via the recovery branch.

## 6. Incidents

### The user was coerced (duress PIN used)
1. The escape sweep arms and fires at `T`; every node locks down. This is automatic.
2. Once safe, confirm on-chain where the coins went — the escape wallet is independent of every
   vault key by construction (checked at ceremony time).
3. The old vault is finished. Stand up a new one (`docs/UPGRADE-AND-ROTATION-POLICY.md` §3).

### An unauthorized spend is pending and the Hold has not expired
This is what the Hold is for.

1. Read `GET /pending` from every node. An id you did not receive for a spend you authorized is
   evidence that the node accepted an unauthorized candidate, including one fed directly by a
   coordinator-auth-key thief.
2. Answer inside the Hold, and pick the answer by your own situation:
   - **If you are free to act**, submit an escape-class spend of the threatened coins under the
     **normal PIN**. Escape-class fires immediately (`remaining_secs: 0`), so the conflicting
     transaction defeats the pending spend well before its Hold expires, and the vault keeps
     working afterwards. This is the clawback `demo theft-refused` act two performs end to end.
   - **If you are under coercion**, submit the **duress PIN** ceremony instead (above): it arms
     the escape sweep at `T` and locks the federation down unconditionally, and the ceremony is
     indistinguishable to the attacker. The vault is finished afterwards — that is the trade.
     This path is exercised by the `attack all` duress scenarios, not by the demo.
3. Keep polling. The id remains visible through Lockdown, and leaves the projection once this
   node observes the conflicting transaction on the network or the commitment expires. A node
   that drops an id has also stopped scheduling it, so a dropped id cannot fire later.

The projection is intentionally minimal: it gives commitment ids, not transaction details,
amounts, destinations, or deadlines. There is no push notification; if nobody polls it, nobody
sees it.

### The normal path is bricked (coordinator auth key lost)
No request can be authenticated ever again — the manifest pins that pubkey and is immutable. The
only exit is the recovery branch after the 180-day relative timelock. `demo recovery-drill`
exercises it. Start the clock immediately; there is no faster path.

### A node will not boot
Read the startup error before changing anything.
- *Manifest mismatch* → its config disagrees with the sealed federation value. **Do not edit the
  config to make it match**; that produces a node that boots while enforcing a policy the
  federation never agreed. Roll back whatever changed.
- *Chain backend unreachable / missing `-txindex=1`* → fix the backend. The node fails closed on
  purpose.
- *Wrong preimage* → the derived key does not match the published bundle; you have the wrong
  secret for that host.

### Fewer than 3 nodes are serving
The vault cannot sign. It is not losing coins — it is frozen, which is the safe direction.
Restore nodes. If they cannot be restored, the recovery branch is the exit.

## 7. Backups — verify these before you need them

| Artifact | Why it matters |
|---|---|
| `descriptor.txt` | Without it you cannot even *find* the coins, let alone spend them |
| `manifest.json` | The full sealed manifest; `manifest_hash` must be recomputable from it |
| `coordinator-auth.secret` | Losing it bricks the normal path (§6) |
| Recovery keys | The last exit, and the one that works when everything else has failed |
| Each host's operator preimage | Required at every node start |

Test a restore. A backup you have never restored from is a hypothesis.

## 8. What this runbook does not cover

- **Monitoring/alerting integration.** There is no paging integration; `/healthz`, `/events`, and
  `/pending` are pull surfaces and someone has to actually pull them.
- **Key ceremony logistics** (who holds what, where, in which jurisdiction) — that is deployment
  policy, and ADR-0009's correlation-class rule is the constraint it has to satisfy.
- **Anything about running at scale.** This is a single-user vault. Steady-state operation no
  longer scans the UTXO set (§4), but the `scantxoutset` cost measured on signet still applies to
  first bring-up and to every fallback path, and nobody has measured it on mainnet
  (`docs/THREAT-MODEL.md` R5).
