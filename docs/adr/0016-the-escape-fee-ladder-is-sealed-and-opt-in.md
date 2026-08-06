# The escape fee ladder is sealed, opt-in, and one number

Every `SpendRequest` carries a mandatory Escape. (A `RefreshRequest` does not — it is a Normal-path
self-spend with one PSBT and no Escape, so everything below is scoped to SpendRequest.) The Escape
fee ladder adds up to `MAX_ESCAPE_BUMPS = 3` pre-signed higher-fee alternatives to that Escape, and
because the fee lives inside the signed bytes under SIGHASH_ALL, **each rung is a separate
transaction the Operator must authorize**. A fully-laddered spend therefore presents up to FIVE
transactions for approval where the protocol needs two — up to, not exactly: the ceiling, the dust
floor and the relay increment each drop rungs, so 3 or 4 is common and 2 is the default. (Counted as
TRANSACTIONS PRESENTED, not signatures: a multi-input PSBT takes one signature per input, so a
signature count is not a stable observable.)

The rungs are *derived*, not authored: `escape_fee_ladder` composes them from the Escape at 4×, 16×
and 64× the base fee. So the Operator is not authorizing five transactions in any meaningful sense
— they are authorizing one policy, *"sweep everything to my escape wallet, and pre-approve paying up
to N% of it to get that confirmed"*, which is then encoded as five objects for a machine.

That framing decides where the choice belongs. Under duress is the worst possible moment to reason
about fee multipliers, and the Ceremony is the only moment the Operator is calm, unhurried, and
already making permanent decisions.

## Decision

**1. By default the Operator approves exactly two transactions per `SpendRequest`** — the spend and
the Escape. (A `RefreshRequest` presents one; it has no Escape and no ladder.) A vault
with no ladder is a supported, first-class configuration: `lib.rs`'s ladder validation returns
`Ok(())` on an empty `escape_bumps`, and `attack.rs` and `signet.rs` already run this way.

**2. The ladder is one sealed number: `escape_bump_max_fee_pct`, default `0`.** Not a boolean, not a
rung count. At `0` the honest composer's fee ceiling is zero sats, every rung at 4×/16×/64× base
exceeds it, none is offered on that path, and the two-transaction default falls out of the value
rather than needing a second field to express it. The number is the one quantity an Operator can
actually reason about at setup: the share of the swept value the honest composer may offer as rung
fees to get it confirmed.

Precisely what it bounds on the honest composing path: **each replacement rung's ENTIRE transaction
fee.** `escape_fee_ladder` compares `base_fee * multiplier` against `total_in * pct / 100`
(fed.rs:354) — so it is a cap on a rung's whole fee, not on the increment above the base. What it
does NOT bound is the base Escape itself: the base is always retained and never checked against the
ceiling, so at `0` the base still pays its own (nonzero) fee and the vault simply offers no rungs.

Setup must say that plainly, because the Ceremony cannot show the number that would make it
concrete: no Escape PSBT exists at seal time, and its fee depends on inputs, output shape and a
feerate source chosen much later. So the Ceremony states that the ceiling governs rungs only, and
the per-spend authorization UI always displays the actual base fee at spend time, because that
concrete fee cannot exist at seal time.

**3. The Ceremony must reject a value that the vault's own nodes would refuse.** The node's
fire-time guard is `fee ≤ 100 − escape_coverage_pct` (5% by default), already sealed in the
manifest. TWO hard caps exist in code, and both must be respected at seal time:
`escape_bump_max_fee_pct <= 100 - escape_coverage_pct` (the fire-time coverage guard) and
`escape_bump_max_fee_pct <= policy_core::MAX_FEE_PERCENT` (10 — the ingress cap every rung passes
through `verify_escape`). Without the second, a low coverage would admit a ceiling of 19 and a rung
over 10% would be refused at ingress, sealing a vault whose own ladder is unusable.

On top of those, **this ADR DECIDES a 5× safety margin against the coverage guard**:
`escape_bump_max_fee_pct * 5 <= 100 - escape_coverage_pct`. Stated as a decision, because it is one
— nodes accept 2–5% at the 95% default (both caps are `<=`, and policy-core's doctrine is "Exactly at the cap passes"), so this rule rejects ladders they would take. The margin
buys two things: headroom under the guard a rung is checked against at `T`, and reproduction of the
posture the tree already ships (1% under a 5% guard). It does NOT guarantee a rung always passes:
`sweep_rung_admissible` measures coverage against `protected_value` — the current authorized vault
balance — so a deposit landing during the Hold can fail even a 1% rung. This is a static bound under
full-coverage assumptions; dynamic coverage failure stays possible. It is NOT derived from
code: `fed.rs` has no computation relating its ceiling to the coverage guard —
`ESCAPE_BUMP_MAX_FEE_PCT` is a bare constant used as `total_in * pct / 100`, and the 5× ratio is an
incidental relationship between two independent constants. (`fed.rs`'s comment used to call that ratio "an order of
magnitude"; it is five times, and this change corrected the comment.) If a future reader wants
2–5%, the margin is the thing to argue with — not a node behaviour.

**3a. "Sealed" means IN THE CANONICAL PREIMAGE, not merely in `manifest.json`.** A field written to
the JSON but absent from `base_manifest_bytes` is a value the Ceremony writes and no node is bound
to. So `btc-policy-mby` must amend the preimage and the node config startup parses, in the same
change — otherwise this ADR's "sealed" is decoration.

The canonical preimage is version-bound: adding `escape_bump_max_fee_pct` changes `manifest_hash`
for otherwise-identical inputs, so it MUST ship with a protocol-version bump rather than continue
to declare `PROTOCOL_VERSION_V0`. Existing sealed vaults are unaffected — their manifests are
immutable and rotation creates a new vault.

Be precise about what "unaffected" does and does not mean, because the difference is a bricking
risk. It means their sealed bytes stay valid and no manifest needs rewriting. It does NOT mean an
upgraded node can still serve them: `base_manifest_bytes` computes ONE layout and dispatches on
nothing — `protocol_version` is hashed IN as a parameter, not switched on — so a node built with
the extended preimage derives a different `manifest_hash` from the same v0 `manifest.json` and
cannot serve that vault, whether it fails as a version error or as a hash mismatch. So one of two
things must be decided and written down before the field lands: either the hashing becomes
version-DISPATCHED, so an extended node reproduces the v0 preimage for a v0 anchor (with a
cross-version vector proving it), or upgrading past this change is accepted as bricking a v0 vault
and the migration is rotation to a new vault — which is consistent with "there is no in-place
rotation in v0", but must be stated rather than left to be discovered by an operator whose nodes
stop recognising their own manifest after a restart. `btc-policy-mby` owns the decision.

That refusal is NOT implementable today, and `btc-policy-mby` owns closing the gap rather than
assuming it. Nothing feeds a declared version into a node at startup: `ConfigFile`/`ChannelConfig`
carry no `protocol_version`, nodes never read `manifest.json` at all, and manifest hashing injects
`PROTOCOL_VERSION_V0` internally — so an extended node handed an old anchor can only report the
opaque hash mismatch, which is the failure this paragraph wants to avoid. Adding the field
therefore means adding a version-bearing startup input and an explicit old-version rejection path,
with a cross-version vector test, in the same change. Bumping the compile-time constant alone
changes the hash and nothing else.

**ADR-0013 §4's LIST MUST STAY AUTHORITATIVE.** It instructs reimplementers to work "from THIS list
+ order, NOT a naive serialization". That list previously omitted `escape_feerate_floor` and
`escape_coverage_pct`, which the code hashes between `max_derivation_index` and the node count
(`channel.rs:499-501`) and which `docs/UPGRADE-AND-ROTATION-POLICY.md` already listed as preimage
members. The authoritative §4 list now includes both fields in that order.
`escape_bump_max_fee_pct` is an unsigned `u8`, encoded at fixed width as the single byte written by
`Enc::u8`. Its exact canonical position is immediately after `escape_coverage_pct` and immediately
before the node-count `u32`: the tail is `max_derivation_index(u32)`,
`escape_feerate_floor(u64)`, `escape_coverage_pct(u8)`, `escape_bump_max_fee_pct(u8)`, then
`nodes(u32 count, ...)`. `btc-policy-mby` must add that exact field to the canonical list when it
adds it to the preimage; otherwise this ADR's new value would be present in `manifest.json` but not
sealed by `manifest_hash`.

**4. The Ceremony presents the ladder and the recovery timelock as ONE question; the schema keeps
them as TWO independent fields.** The coupling is a presentation affordance, not a data model.
`recovery_timelock` and `escape_bump_max_fee_pct` are separate manifest entries, independently
validated, and the Ceremony displays the resulting value of each explicitly before sealing. An
implementation that encodes both in a single field is building the wrong thing.

The bead ordering can violate this MUST in an intermediate release, and the result is irreversible.
`btc-policy-mby` adds the ladder's Ceremony input; `btc-policy-wdu` is what later makes the recovery
timelock a choice and merges the two prompts. Between them the Ceremony would put the ladder
question alone in front of an operator, and vaults sealed in that window are sealed forever. Resolve
it the cheap way rather than by coupling the beads: `mby`'s prompt must show the recovery timelock
alongside the ladder ceiling as a FIXED, displayed value (which is what it is today — 180 days, no
setting), so the operator still reasons about both together and only the second value is
selectable. `wdu` then turns that displayed constant into the second half of the question. Landing
the ladder input while the timelock is invisible is the failure mode to avoid.

**4a. The SIGNER checks the ladder against the sealed ceiling as composition validation, not as
hostile-coordinator enforcement.** Nodes do not enforce `escape_bump_max_fee_pct`, and at the wrench
the Coordinator composes the authorization object the Operator is asked to sign. The signer
therefore compares each supplied ladder with the ceiling from its own authenticated manifest and
refuses a directly presented over-ceiling ladder. That catches an honest-path composition mistake
and a naive hostile ladder, preserving the two-transaction default and keeping fee-policy choices
out of the Operator's hands on the honest duress path.

That check is NOT an integrity guarantee against a hostile Coordinator. It cannot detect a validly
signed over-ceiling PSBT obtained earlier as the ceiling-exempt base Escape, as an escape-class
spend, or in another authorization request and then replayed later as a bump. SIGHASH_ALL
authenticates the transaction bytes, not the base/rung role or authorization group; neither sealed
state nor the signature carries that missing context. The sealed ceiling is therefore a
deterministic per-vault COMPOSITION DISCIPLINE for the honest path, not the adversarial fee-loss
bound. The bounds that still apply to a hostile Coordinator are node-side: every rung passes the
`policy_core::MAX_FEE_PERCENT` (10) ingress cap, and the fire-time coverage guard limits fee loss to
`100 - escape_coverage_pct` of protected value.

Caller-supplied labels remain display aids, and the signer's authority comes from sealed state it
loaded itself — but that state cannot always authenticate a ROLE. For an escape-class
`SpendRequest`, both the immediate spend and its mandatory distinct, disjoint residual pay the
sealed escape descriptor, so the signer cannot derive which is "spend" and which is "residual" from
destinations or wallet membership. It MUST approve every otherwise-valid pair and display both as
generic escape-destination transactions, making no positional role claim. It MUST NOT reject on the
ground that the roles are indistinguishable: sealed state cannot distinguish the roles of ANY valid
pair, so that branch rejects every escape-class spend and disables the incident `escape`/clawback
path the runbook directs a user under duress to take. Unauthenticated role is a display limit, not
an admissibility defect.

**5. Nothing pin-dependent crosses the signing seam.** The seam takes no PIN parameter, so no signer
implementation can vary its behaviour by pin class — it never receives the input that would let it.
(The normal/duress VERDICT is computed node-side and never exists client-side at all.) The number
of transactions presented follows transaction class and sealed ladder policy — never the pin — which
is what keeps ladder length from becoming a count/presentation observable.

## Consequences

**This is permanent per vault — but state exactly what is permanent.** ADR-0005 seals the host; the
manifest cannot change afterwards. A vault sealed while `escape_bump_max_fee_pct` does not exist
permanently lacks a SEALED, DETERMINISTIC CEILING. It is NOT protocol-barred from ever carrying a
ladder: nodes never consult the field, the `/sign` handler's length cap accepts up to
`MAX_ESCAPE_BUMPS` rungs from any vault, and no sealed LADDER-POLICY field (presence, length,
ceiling) constrains composition — `fed.rs` does read one sealed value, the descriptor's satisfaction
weight, but only to size the relay-increment filter — so an Operator with
a tool that offers rungs can still sign them and have them accepted. What such a vault lacks is the
per-vault discipline this ADR is about, not the capability. The field still lands with the Ceremony
in `btc-policy-mby` for that reason, which is a weaker one than "no path to a ladder" — and the
weaker reason is the true one.

**A default vault's Escape may fail to confirm.** With no ladder, an admissible sweep fires at its
base fee only. Under congestion it may not make it, and the funds then exit via the Recovery path. This does
not break a stated invariant — ADR-0012's "Lockdown at T is unconditional" bullet is explicit that
*"Safety = freeze + lockdown → recovery, independent of the sweep"* — but it converts a fast exit into a slow one, and the Operator chose
that at setup rather than discovering it at `T`.

**Sealing binds the CEREMONY and the composing tool — NOT a hostile relay.** Nodes DO check every
submitted rung's content against node policy — `verify_escape` runs per bump at ingress, and
fire-time selection is clamped by the sealed coverage guard — but neither check enforces the sealed
ladder ceiling. What no node checks is the ladder's PRESENCE OR LENGTH against any sealed ladder
policy: `ensure_escape_ladder` accepts an empty `escape_bumps` unconditionally. A post-wrench
coordinator holds the auth key, so it can drop rungs and re-sign the shortened request, and the
vault's sealed ceiling will not stop it. State the limit plainly rather than implying otherwise:
what this decision buys is that the OPERATOR is not asked to make a fee-policy choice under duress,
and that the honest composing path is deterministic per vault. It is NOT an integrity guarantee
about what reaches a node.

The residual is bounded, but it has THREE arms, and the last is not the obvious one.
`select_escape_rung` picks the CHEAPEST admissible rung at or above the required feerate. So:

- Strip EVERY rung and the `T`-time sweep does not fire. `escape_fee_ladder` rewrote the signed base
  to RBF-signalling `0xfffffffd` when it composed the ladder, while the fire path treats an empty
  bump list as ladderless and requires `Sequence::MAX`, so the base is refused. For a hot-class
  request under duress, nothing from that request broadcasts. For an escape-class request with a
  distinct residual, the immediate escape-class spend already released at ingress; stripping
  suppresses only the residual sweep. The funds that remain in the vault exit via Recovery
  (`a_ladderless_escape_still_requires_a_non_signalling_sequence`). This is STRONGER suppression
  than the two-transaction default posture, not equal to it: a vault that never had a ladder still
  sweeps, whereas a stripped ladder loses its `T`-time sweep.
- Strip the rung that would have met the target while leaving a MORE expensive one, and the node
  fires that instead — bounded OVERPAYMENT, not degraded confirmation.
- Strip every target-reaching rung but leave a BELOW-target one (e.g. keep `[base, 4x]` of
  `[base, 4x, 16x, 64x]`). The request still looks laddered, so the RBF sequence check passes;
  `select_escape_rung`'s `find(reaches).unwrap_or(count-1)` then tops out at the highest remaining
  rung and fires it UNDER the bump target. The sweep broadcasts at an under-market fee, may not
  confirm, and falls to Recovery — degraded confirmation while APPEARING to fire, which is the arm
  an analyst is least likely to anticipate.

The signer has an adjacent ROLE-REPLAY residual: a hostile Coordinator can first present an
over-ceiling transaction as the ceiling-exempt base Escape, as an escape-class spend, or in another
authorization request, then reuse those exact signed bytes as a bump. The signer check catches the
direct over-ceiling presentation, not this reuse, because the signature binds bytes rather than the
role in which those bytes were authorized. The result can exceed the sealed ceiling, including for
a vault sealed at 0.

All three stripping arms and this role-replay residual are bounded, and none is theft: every rung
is user-signed SIGHASH_ALL over its own bytes, every destination output pays the user's escape
descriptor and every remaining output is verified vault change, the 10%
`policy_core::MAX_FEE_PERCENT` cap runs at ingress, and the fire-time coverage guard caps the
fee against protected value. Replay can therefore cause bounded OVERPAYMENT to the user's own
escape wallet, never redirection and never an unsigned transaction — the same shape as the separate
escape-class role-order residual below. Those node-side guards, not the sealed ceiling, are the real
hostile-coordinator fee-loss bound. Node-side enforcement of the sealed ceiling is therefore NOT
specified here; if it is ever wanted it is a protocol change with its own bead.

**A separate escape-class role-order residual is accepted.** The immediate spend and mandatory
residual are distinct, disjoint PSBTs that both pay the user's sealed escape descriptor. Their
SIGHASH_ALL signatures bind each transaction's bytes, not its request role, while the coordinator's
`canonical_bytes` binds those PSBTs only positionally (`spend_psbt` then `escape_psbt`). A
post-wrench coordinator holding the auth key can therefore swap the two positions, issue a fresh
`coord_sig`, and still present a node-valid escape-class request. The effect includes WHICH disjoint
coin set moves immediately versus at `T`, and can also suppress the residual sweep entirely: the
spend role releases immediately without `sweep_rung_admissible`, while only the residual faces the
fire-time sequence, feerate-floor, and coverage checks. For example, swapping a relay-valid 1
sat/vB spend with a 20 sat/vB residual under a 20 sat/vB floor broadcasts the latter immediately
but rejects the former at `T`. The remaining funds stay frozen and exit through Recovery. Both
destinations nevertheless remain the user's escape wallet, neither transaction's user-signed bytes
can be changed, and the coordinator still cannot redirect funds or introduce a transaction the user
did not sign. This residual is why the signer display must not claim a spend/residual distinction it
cannot authenticate.

**The timelock is coupled to the ladder in BOTH directions, and to refresh as well.** This is the
part that is invisible until stated:

- The timelock sets how long the funds are immobile if the sweep misses. A longer timelock makes the
  ladder worth more.
- The timelock is also **the refresh deadline**. Per `btc-policy-ye8`, once the recovery branch
  matures the 2-of-3 recovery keyset — *distributed to third parties by design, since it doubles as
  the inheritance mechanism* — becomes a complete authorization path needing no PIN, no user key, no
  Hold, no allowlist and no federation. A shorter timelock therefore obliges more frequent refreshes.

So the Ceremony's single question is genuinely three-way: immobility risk, ladder value, and refresh
cadence all move together. Presenting the timelock and the ladder independently invites the one
combination that maximises immobility — a long timelock with no ladder — chosen by an Operator with
no basis to see the interaction.

## Alternatives rejected

**A separate on/off flag beside a ceiling.** Two fields that can disagree — a flag saying "on" with
a ceiling of zero has no meaning, and validating the pair is work that a single number does not
need. Rejected as redundant.

**Choosing the ladder per spend.** Rejected because the moment the sweep matters most is the moment
the Operator is least able to reason about fee policy. NOT rejected on integrity grounds — see the
consequence above: a hostile relay can already vary the submitted ladder, sealed or not, so "the
coordinator cannot change it per request" is not a property this decision delivers.

**Rung count, or the multipliers, as the sealed knob.** Both are implementation facts. An Operator
cannot answer "how many rungs?" but can answer "what share of my money will I pay to get it out?" —
and with a ceiling the rung count already falls out of it, since rungs exceeding the ceiling are
simply not offered.

**Deferring the field until the derivation is built.** Rejected, but on narrower grounds than an
earlier draft of this ADR claimed. Vaults sealed in the interval are NOT protocol-barred from a
ladder (see the permanence consequence above); what they permanently lack is a sealed deterministic
ceiling, so their ladders are whatever tool composes them rather than a per-vault property. The
field is cheap and that asymmetry is irreversible, which is enough — "permanently ladder-less" was
not true and is not the reason.
