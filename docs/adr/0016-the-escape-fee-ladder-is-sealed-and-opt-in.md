# The escape fee ladder is sealed, opt-in, and one number

Every Normal-path spend carries a mandatory Escape. The Escape fee ladder adds up to
`MAX_ESCAPE_BUMPS = 3` pre-signed higher-fee alternatives to it, and because the fee lives inside
the signed bytes under SIGHASH_ALL, **each rung costs a separate user signature**. A ladder-bearing
spend therefore asks the Operator to sign five transactions where the protocol needs two.

The rungs are *derived*, not authored: `escape_fee_ladder` composes them from the Escape at 4×, 16×
and 64× the base fee. So the Operator is not authorizing five transactions in any meaningful sense
— they are authorizing one policy, *"sweep everything to my escape wallet, and pre-approve paying up
to N% of it to get that confirmed"*, which is then encoded as five objects for a machine.

That framing decides where the choice belongs. Under duress is the worst possible moment to reason
about fee multipliers, and the Ceremony is the only moment the Operator is calm, unhurried, and
already making permanent decisions.

## Decision

**1. By default the Operator signs exactly two transactions** — the spend and the Escape. A vault
with no ladder is a supported, first-class configuration: `lib.rs`'s ladder validation returns
`Ok(())` on an empty `escape_bumps`, and `attack.rs` and `signet.rs` already run this way.

**2. The ladder is one sealed number: `escape_bump_max_fee_pct`, default `0`.** Not a boolean, not a
rung count. At `0` the fee ceiling is zero sats, every rung at 4×/16×/64× base exceeds it, none is
offered, and the two-signature default falls out of the value rather than needing a second field to
express it. The number is the one quantity an Operator can actually reason about at setup: the share
of the swept value they will pay to get it confirmed.

**3. The Ceremony must reject a value that the vault's own nodes would refuse.** The node's
fire-time guard is `fee ≤ 100 − escape_coverage_pct` (5% by default), already sealed in the
manifest. The ladder ceiling must sit well below it — `fed.rs` currently keeps its hardcoded 1% "an
order of magnitude below" — or setup could seal a vault whose own ladder is refused at `T`, forever.

**4. The Ceremony presents the ladder and the recovery timelock as ONE question; the schema keeps
them as TWO independent fields.** The coupling is a presentation affordance, not a data model.
`recovery_timelock` and `escape_bump_max_fee_pct` are separate manifest entries, independently
validated, and the Ceremony displays the resulting value of each explicitly before sealing. An
implementation that encodes both in a single field is building the wrong thing.

**5. Nothing pin-dependent crosses the signing seam.** The seam takes no PIN parameter, so it cannot
branch on a verdict it never receives. Signature count follows transaction class and sealed ladder
policy — never the pin — which is what keeps ladder length from becoming a timing oracle.

## Consequences

**This is permanent per vault.** ADR-0005 seals the host; the manifest cannot change afterwards. A
vault sealed while `escape_bump_max_fee_pct` does not exist is permanently a two-signature vault
with no path to a ladder. That is why the field lands in `btc-policy-mby` with the Ceremony, ahead
of the derivation logic that consumes it — the field's absence is irreversible in a way the
behaviour's absence is not.

**A default vault's Escape may fail to confirm.** With no ladder, the sweep fires at its base fee
only. Under congestion it may not make it, and the funds then exit via the Recovery path. This does
not break a stated invariant — DESIGN.md is explicit that *"Safety = freeze + lockdown → recovery,
independent of the sweep"* — but it converts a fast exit into a slow one, and the Operator chose
that at setup rather than discovering it at `T`.

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

**Choosing the ladder per spend.** Rejected: the moment the sweep matters most is the moment the
Operator is least able to reason about fee policy, and a per-request field is one more thing an
untrusted coordinator's request shape could vary between pins.

**Rung count, or the multipliers, as the sealed knob.** Both are implementation facts. An Operator
cannot answer "how many rungs?" but can answer "what share of my money will I pay to get it out?" —
and with a ceiling the rung count already falls out of it, since rungs exceeding the ceiling are
simply not offered.

**Deferring the field until the derivation is built.** Rejected on ADR-0005 grounds: every vault
sealed in the interval would be permanently ladder-less. The field is cheap; its absence is not.
