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

> **Most of this procedure cannot be executed with what ships today.** There is no sealed-vault
> receive, balance, or spend command, and no operational code reads `manifest.json` at all
> (threat-model R9). Steps 3-6 below describe what must happen, not commands you can run: until
> `btc-policy-mby` (operator CLI core), `btc-policy-en1` (`recover`) AND `btc-policy-00i` (receive
> addresses and balance reads) land, each is a manual operation against the descriptor and a block explorer or your own node. Read the whole section
> before starting so you know what you are committing to.

1. At `T`, the deadline driver unconditionally attempts Lockdown; the independent fire driver
   attempts the escape sweep. The sweep is BEST-EFFORT: it may not fire at all, and even when it
   fires it need not move everything. Assume a partial result until you have checked — step 3 reads the balances; not now.
2. **Once safe — including the checks. But do not linger.** Do none of this while you are still
   with the attacker: step 4 generates the new vault's keys and PINs,
   telling payers to stop announces that the duress response fired, and even the verification below
   reveals it to anyone watching your screen. Silence is the protection; do not spend it to satisfy
   your own curiosity about whether Lockdown landed. Once you ARE safe, verify immediately rather
   than at leisure: if the carrier never reached `t` nodes then nothing armed and nothing froze, a
   coerced hot spend can still finalize, and `hold_secs` has no positive lower bound — so "wait a
   few hours" is not safe advice in that case — and no check will tell you which case you are in,
   which is why the action below does not depend on knowing.
   **Check `GET /healthz`, but do NOT treat it as proof, and do NOT act on it.** It reports
   `locked_down` and `last_deadline_tick` and answers even while a node is jammed, which is useful
   for triage. It is also unauthenticated, carries no identity claim, and is reached over the same
   relay path as `/sign` (DESIGN.md's `/healthz` wire contract) — and that relay is the actor
   assumed hostile after a wrench. Treat BOTH answers as unreliable: a hostile coordinator fakes
   `true` to make you stand down, and fakes `false` to bait you into sending it something.
   Do NOT probe with a real spend or refresh: `FRAUD_SUSPECTED` is a postcondition of Lockdown, not
   a test for it, and on a node that has NOT locked down the spend can be registered and propagated
   and a refresh signed and released, RESETTING the recovery maturity step 5 depends on.
   **And do NOT attempt a normal-PIN clawback here, however tempting.** The clawback in "An
   unauthorized spend is pending" below is written for a coordinator you still trust. After the
   wrench you do not, and it is the only path you have to the nodes: sending it the normal PIN hands
   over the one secret that stops pin substitution, and it already holds the user-signed spend, the
   escape and the coordinator auth key — so it can censor your clawback and reissue a normal-PIN
   request of its own, letting the coerced spend release at its Hold. If Lockdown DID land the
   clawback cannot fire anyway: every spend then returns `FRAUD_SUSPECTED`, for that node's
   lifetime.
   **There is one action available, and it is not a message — it is the power switch. Use it
   promptly; do not research first.** If you still control the hardware, cutting power destroys all
   five nodes' keys permanently: the v0 federation is co-located on one host and its keys are
   RAM-only, so a rebooted node is a dead node (ADR-0007). It needs no coordinator, no PIN and no
   network, which is why a hostile relay cannot interfere with it.
   DO NOT check the chain first. The state that decides whether this works — whether the coerced
   spend's partials have been released yet — is not visible on chain or in the mempool, so a check
   cannot tell you, and it spends the window in which the switch still helps.
   The two ways this can go are settled by the state machine. (Arming converges rather than flipping —
   ADR-0012 describes a window where an early node is armed while the rest are not — but that
   changes nothing here: the action below is the same in every one of those states.) If NOTHING
   ARMED, no sweep exists to interrupt and the coerced spend is the live threat: the switch stops
   any partial not yet released, which is the whole of what you can do. If the vault DID ARM, then
   hot-class finalization is already frozen and the coerced spend cannot finalize anyway — you do
   not need the switch, and using it would abort the in-flight escape combine that Lockdown
   deliberately preserves (ADR-0012's Lockdown row). You cannot reliably tell which case
   you are in — `/healthz` is untrustworthy in both directions, as above — so DO NOT try to judge
   it. CUT POWER. That is the default because the two errors are not symmetric: cutting power while
   the vault HAD armed only exchanges one already-safe outcome (the escape sweep) for another the
   design already accepts (the recovery branch, "the same trade the duress PIN makes"), whereas
   leaving it running when nothing armed risks the coerced spend finalizing outright. A wrongly
   aborted sweep costs you time; a wrongly unfrozen theft costs you the coins.
   Afterwards, check the chain — not before. The switch cannot revoke a signature already released
   or un-broadcast a transaction already in the mempool, so the coerced spend may still land; there
   is no `hold_secs` floor and `hold_secs = 0` is a supported configuration where the fire event is
   ingress itself. Watch for late confirmations: one that lands post-shutdown creates vault change
   and restarts THAT output's recovery clock, which changes the dates in step 5.
   Understand the trade before you do it: it finishes the vault. The coins then exit only through
   the recovery branch, on each UTXO's own clock. That is the same trade the duress PIN makes, and
   it is the right one when a hot spend is still assemblable and you cannot otherwise stop it.
   If you do NOT control the hardware, then there is no action, and that is by design. A coerced hot
   spend may complete; the residual is accepted and BOUNDED by the Hot budget (ADR-0014, "the hot
   wallet is the risk budget"). Guaranteed delivery under a hostile coordinator is the v1 direct
   user-to-node path (ADR-0012) and does not exist in v0. Everything else is on the recovery side.
   **Stop inbound payments to the old vault.** Its addresses stay payable after Lockdown, and
   anything arriving lands in a fresh recovery lock. You will have replacement addresses at step 4.
3. **Read the old vault's remaining balance and the escape-wallet balance on-chain.** Do not infer
   either from whether the sweep fired — ask the chain. Whatever reached the escape wallet is safe:
   that wallet is independent of every vault key by construction (checked at ceremony time).
4. **Rebuild the coordinator and ceremony environment from trusted media FIRST, then stand up the
   new vault** using `docs/UPGRADE-AND-ROTATION-POLICY.md` §3 steps 1–2. The setup ceremony is a
   trusted phase — it generates the successor's PINs, user key and coordinator auth key — and the
   host you ran the old vault from is the one this procedure has been treating as hostile since
   step 2. Running the ceremony on it can leak the new vault's secrets or tamper with the ceremony
   before a single sat is deposited, which would carry the compromise across the rotation and make
   everything below pointless. New host, and binaries you obtained independently of the compromised one — note that
   byte-identical rebuilds and signed artifacts are `btc-policy-oy3` and do NOT ship yet, so this
   is a provenance judgement you have to make, not a check you can run. Then: run the ceremony, then fund it
   with a small deposit — from unrelated funds if step 3 found the escape
   wallet empty — and complete one honest spend end to end, waiting for it to CONFIRM rather than merely broadcast. Section 3 step 3's migration spend does
   NOT apply either way, and the reason is the same one that rules out the clawback above: it runs
   through the coordinator. If Lockdown landed, the old vault's normal path is dead outright. If
   nothing ever armed — the failed-carrier case in step 2 — the federation is still live, but the
   relay you would reach it through is the one assumed hostile, so a live normal path is not a
   usable one for you. Do not send it the normal PIN to find out. Step 5's recovery branch is the
   exit in BOTH cases, and it is the one path that owes the federation nothing: after the timelock
   matures, 2 of 3 recovery keys move the coins with no user key and no node quorum
   (`crates/policy-core/src/template.rs:10-12`), so neither a locked-down federation nor a hostile
   coordinator can block, censor or delay it. It is NOT private, though, and do not plan as if it
   were: the recovery spend is an ordinary public transaction, and this vault's own watchtowers
   classify exactly that shape as `RecoveryPathSpend` (`crates/vault-cli/src/recovery.rs:197-216`).
   Anyone watching the chain — including whoever coerced you — sees the coins move when it
   confirms, and can tell it was the recovery branch. Assume that moment is visible to them and
   time it accordingly. If step 3 found an escape balance, move
   it into the new vault once that check passes; otherwise migration waits for step 5's recoveries.
   Do not leave an escape balance there for months: it is a single-key holding pen. Give payers the
   new vault's addresses.
5. **Recover whatever is still in the old vault, coin by coin, into the new one.** The locked-down
   vault's only exit is the recovery branch: 2 of the 3 recovery keys, after a lock that is
   BIP68-relative per UTXO — each coin matures 180 days (fixed for every vault; there is no
   setting) after its own confirmation or last refresh, so compute each straggler's own date: a
   coin refreshed 170 days ago matures in ~10 days. No shipped tool performs this spend — check
   whether `btc-vault recover` (bead `btc-policy-en1`) exists yet; until it does, this is a manual
   PSBT against the descriptor, using `build_recovery_spend` in `crates/vault-cli/src/recovery.rs`
   as the recipe (`demo recovery-drill` proves the path on its own throwaway regtest and cannot
   touch your vault).
6. The old vault is finished when its balance is zero.

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
     **It assumes the coordinator SOFTWARE is still honest, which is not the same as the auth key
     being safe.** A stolen auth key lets a thief inject requests, but your clawback still reaches
     the nodes through your own honest relay and your normal PIN goes nowhere else — that is the
     case above. If the coordinator ITSELF is compromised, as it is assumed to be after a wrench,
     do NOT use this: the normal PIN is the secret that stops pin substitution, and handing it to
     the relay lets it censor your clawback and reissue a normal-PIN request of its own. See "The
     user was coerced" above, where there is deliberately no action for that case.
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
only exit is the recovery branch, after the fixed 180-day recovery lock. There is no faster path.
The clock is not something this incident starts: the lock is BIP68-relative and has been accruing
per UTXO since each coin's own confirmation or last refresh, and no further refresh can be
authenticated now — so work out each coin's remaining maturity rather than assuming a full
timelock from today. Recovery itself is the manual PSBT operation described under "The user was coerced" above;
`demo recovery-drill` exercises the path but cannot spend your vault.

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
