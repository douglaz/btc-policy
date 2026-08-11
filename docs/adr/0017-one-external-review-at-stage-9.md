# One external review, at stage 9

`docs/ROLLOUT-PLAN.md` placed a human security review at BOTH ends of the rollout ladder: stage 1
("Freeze → external review #1 (protocol core)") and stage 9 ("Freeze → external review #2", the
rung where the dust caps lift). `btc-policy-9y5.8` restated the first as a hard deliverable, and it
was emphatic about why AI could not close it — "a 7-agent+codex+Fable fan-out is CORRELATED
automated review, NOT the independent external audit this gate requires; do not treat AI consensus
as audit closure."

That reasoning is not withdrawn. What changed is the SEQUENCING: there is a great deal of
implementation left before it is worth a professional's week — or a friend's afternoon — and stage 1
is a signet vault on one machine that cannot yet be spent from at all. Reviewing there means
reviewing prose about commands that do not exist. `btc-policy-tv3` documents where that leads: the
duress procedure went through roughly thirteen automated review rounds in which every round found a
defect introduced by the previous round's fix, on a section whose own banner says most of its steps
are not executable yet.

## Decision

**ONE external human review, at stage 9.** The order is FREEZE, then REVIEW, then CAPS LIFT:
the stage-9 freeze produces the artifact, the review reads that frozen artifact, and it is LIFTING
THE DUST CAPS that the review gates — not the freeze. Saying the review gates the freeze would be
circular, since a reviewer cannot be handed a frozen target by a freeze that is waiting on the
review. Review #1 is removed.

**Stage 1 keeps its FREEZE.** The stage-1 gate always bundled two mechanisms under one name, and
only one of them needs a person:

- the **freeze** stops churn — interfaces, threat model, ceremony/runbooks, protocol vectors,
  SBOM/dependency policy, upgrade/rotation policy, reproducible release — so stages 2-8 build on
  something stable. It is discipline, not assurance, and `btc-policy-gbw` already owns it;
- the **review** validates what was frozen. That is the part being deferred.

Separating them is the whole decision. Deleting the bundle would have removed the freeze too, and
the freeze is what makes eight downstream stages mean anything.

**`btc-policy-tv3`'s two human conditions move to stage 9** rather than being deleted: a human
reading the duress procedure end to end, and a dry run by someone who did not write it. They
transfer into `btc-policy-yt7` so the human who reads this system before caps lift reads the duress
runbook specifically, with tv3's findings as their brief. tv3 then closes on its mechanical
conditions alone.

## What this accepts, and it should not be discovered later

**Stages 3, 5 and 8 put real mainnet funds in front of code no human outside this project has
read.** The amounts are dust-capped, but they are real.

So the dust cap changes job. ADR-0015 introduced it as a funding policy bounding the ADR-0009
correlation waiver — five nodes at one provider is a correlation class holding quorum, and sealing
does not fix it. It now ALSO carries the assurance weight that external review #1 was carrying. It
was not designed for that, and a reader who sees only "dust cap, ADR-0015" will not know it.

Reordering the mainnet rungs behind stage 9 was considered and rejected, because ADR-0015 already
adjudicated this exact shape: both reviewers recommended reordering, and the recorded decision was
to keep the ordering and bound the exposure. That precedent applies unchanged. Tightening the cap
was also rejected — there is no evidence the current number is wrong, and inventing a new one would
be a guess wearing the costume of a mitigation.

## What carries assurance until stage 9, and what it does not cover

Named here because "no external review" is only half a statement; the other half is what is being
relied on instead.

**Relied on**, and the ORDER is deliberate as of 2026-08-10 — the harness used to sit SECOND, ahead
of the proptest suites, and now sits third behind them, because the MIXED-CLASS EXTRACTION fault
(`classify`'s own comment calls a misclassification "a duress bypass") was caught by the proptest
suites and missed by all sixteen scenarios. The freeze was first before and is first still. Naming
the fault, because `nia` injected TWO and both are duress-related: the other, a Lockdown-at-T
regression, the harness DID catch (`btc-policy-nia`): the stage-1 freeze (`gbw`); proptest and fuzz suites; the
adversarial harness (`attack all`, 16 scenarios — and read the caveat below before weighting this:
the harness HAS been shown red on a deliberately introduced fault, and has also been shown BLIND to
a second one); the full CI matrix; and multi-model AI review panels, which do find real
defects — this repo's own history includes a canonical manifest-preimage list found wrong three
times and an escape self-pairing model wrong across seven sites, all caught by automated review.

**PREREQUISITE — SATISFIED IN BOTH HALVES as of 2026-08-10, and no longer gates the freeze. Read
"satisfied" narrowly: `nia` records two of its three VERIFY criteria as unmet AS WRITTEN — the
class-check half did not turn `attack all` red, and the recorded-CI-run criterion was superseded by
choice — and `btc-policy-u98` is an open coverage gap. What is satisfied is the property the gate
existed for, not every line of the bead's checklist.**
`btc-policy-9yf` (closed 2026-08-09) settled the launch-gate JOB; `btc-policy-nia` (closed
2026-08-10) settled the HARNESS, which `9yf` could not reach. Both halves are now evidenced, so the
stage-1 freeze is no longer waiting on a negative control. Both `blocks` edges on `btc-policy-gbw`
remain in the graph and are satisfied by closure rather than deleted — the record that this gate
existed is worth more than a tidy dependency list, and `br ready` counts only OPEN blockers.

`nia` did find a second thing on its way — `attack all` is blind to the mixed-class extraction path
(`btc-policy-u98`, P1 — raised from P2 once the fault was corrected and the gap turned out to be an
extraction path rather than a lost refusal). That is deliberately NOT made a freeze blocker, and
the reason is recorded
here rather than left to inference. State the gate precisely, because the loose version — "the
harness has never been shown capable of failing" — is one this ADR retracts in the "Stated
precisely, 2026-08-09" parenthesis below: `rt0`'s 15/16 already answered that, and `nia`'s own
description records the loose phrasing as corrected on the same date. What this prerequisite gated
was SENSITIVITY TO AN INJECTED SAFETY REGRESSION, and that is what is now closed. (Referred to by
its wording, not by "the paragraph below" — this ADR has been edited enough times that positional
pointers go stale.) `u98` is one missing scenario whose
underlying regression CI still catches in an independent job. Promoting every coverage hole
discovered by a negative control into a freeze blocker would make the freeze unreachable by
construction, which is the failure mode ADR-0017 was written to avoid in the first place.

The original framing follows: `btc-policy-9yf`'s negative
control gates the stage-1 freeze. As written 2026-08-06 (commit 539dd87), "16/16 scenarios held"
rested on a gate that had never been observed to fail ON A DELIBERATELY INTRODUCED FAULT, which
made it a statement that the run did not report a failure — not that it would report one. (Stated
precisely, 2026-08-09: the gate HAD failed spontaneously — `btc-policy-rt0` records
`escape-class-sequences` at 15/16 — so it was never vacuously green. What was missing, and what a
negative control establishes, is sensitivity to an injected safety regression.) With a human at stage 1 that gap was tolerable. Without one
it is the foundation, so the freeze could not complete until a deliberately introduced fault was
confirmed to turn the gate red.

**SATISFIED 2026-08-08** (`btc-policy-9yf`, PR #6). A branch carrying one real safety regression —
the destination allowlist removed — turned the `launch gate` job RED at `demo first-light`
(CI run 31238105663). The `test` job went red too — 4 policy-core unit tests, exit 101 — so
TWO independent jobs caught the regression, while fmt, clippy and regtest-backend stayed green, so the failure was
attributable rather than a blanket red. Read the demonstration precisely, because it proves less
than the shortest summary of it: the spend was still refused, by the independent output-derived
class check (ADR-0013 §3), so what was shown is **that a weakened control is detected**, not that
funds leave. That is the property this prerequisite needed — the gate reports a regression — and it
is not a claim that any single control is sufficient alone.

**What this does NOT cover, and it matters most to whoever reads this ADR** — because the
"Relied on" list above names the harness, and a stage-9 reviewer is being told what carries
assurance in the absence of human review. The launch-gate job stops at its first failing step, and
this control failed at step 9 (`demo first-light`), so **step 12, `attack all`, never executed**.
The 16-scenario harness was therefore not covered by THIS prerequisite at all. It was covered
separately by `btc-policy-nia`, and the paragraph below records what that found.

**MEASURED 2026-08-10 (`btc-policy-nia`), and it cuts both ways.** Two faults were injected
locally — never pushed, so no branch carried a live safety regression. For each, the three demos
(gate steps 9-11) were run first and confirmed to exit 0, and then a full `attack all` (step 12)
was run: not a single scenario, because the full-run dispatch takes a path a selected run never
reaches. The demos clearing it is what makes step 12 reachable in the gate's own ordering, and it
is exactly the constraint `9yf`'s fault failed.

- **The harness IS sensitive.** With Lockdown at T made never-due in
  `channel::ChannelState::lockdown_due`, all three demos still exited 0 and a full `attack all` came
  back **1/16, exit 1** — "ADVERSARIAL HARNESS FAILED — a duress safety assertion did not hold" —
  with fifteen scenarios each naming itself and citing the invariant: "did not enter Lockdown at T;
  lockdown at T is unconditional (ADR-0012 invariant i)". So "16/16 held" is a statement the harness
  is capable of retracting. The single survivor is the part worth reading: `reorg-watchtower-cursor`
  is the one scenario that never asserts Lockdown, so the harness went red exactly where the broken
  property is asserted and stayed green where it is not — the reds are attributable to the injected
  invariant, which a fault that reddened all sixteen could not have shown.
- **Its sensitivity is UNEVEN, and the gap is an EXTRACTION PATH.** With `classify`'s mixed-class
  arm returning `Escape` instead of refusing, a mostly-to-hot + dust-to-escape spend completes
  IMMEDIATELY UNDER THE DURESS PIN — escape-class fires at `now` rather than taking the Hold, the
  ROLLING-WINDOW half of the Hot budget, or the duress freeze, all three of which key on
  `class == Hot`.

  **State the magnitude precisely.** Three drafts of this paragraph overstated it in three
  different ways, so here it is bounded from both sides. What the misclassification DEFEATS is the
  CLASS-GATED half of the safety track: no Hold, no rolling-window reserve, no duress freeze, so
  each spend is signed, combined and BROADCAST immediately instead of waiting out the Hold.
  ("Settles" would overstate it — confirmation still needs a block; what the fault removes is the
  delay the Hold exists to impose.) What it does NOT defeat:

  - the PER-TRANSACTION Hot budget, which is class-INDEPENDENT — `evaluate` calls
    `check_hot_budget` unconditionally and it takes no class argument, and that function re-sums
    the outflow itself rather than reading the classification — so each spend is still capped at
    `hot_max_per_tx`. That cap is MANDATORY operator config with no default (`docs/DESIGN.md`
    §"The Hot budget"); 50,000,000 sat is the documented EXAMPLE, not a shipped value.
  - **arming and terminal Lockdown at `T`, which are gated on the DURESS PIN and take no class at
    all.** `fire_arm_hook` runs unconditionally on a valid duress pin and BEFORE `classify` is
    reached; `lockdown_due` is `armed.active & (now >= fire_at)` with no class term. So the drain
    is bounded by the duress-delay window from the first coerced carrier, after which Lockdown is
    terminal and every spend and refresh answers `FRAUD_SUSPECTED` for the node's lifetime.

  So: drain at the cap, repeatable **for the duress-delay window**, then terminal Lockdown — not
  "without limit", and not a total defeat of the safety track, whose second half survives untouched.
  Two qualifications point the other way and belong here rather than being dropped for being
  inconvenient:

  - Because the misclassified spend is not hot-class it leaves no pending hot Hold of its own, so
    `T`'s `min(..., earliest pending hot Hold-expiry − ε)` shrink input gets nothing from it and `T`
    MAY remain at its maximum. Not "does" — another pending hot spend, from before the coercion or
    alongside it, would still supply a smaller deadline.
  - The duress-delay bound assumes Lockdown actually fires on schedule, and **THREAT-MODEL R11 says
    the delay before Lockdown at `T` has no finite bound.** Composed with a lock-starvation attack
    that defers the transition, the repetition window is not bounded by configuration at all. So
    "bounded by the duress-delay window" is the single-fault statement; it is not a statement about
    an adversary who also holds R11.

  `classify`'s own doc comment at `lib.rs:74-79` carries the "99%-to-hot" version of this
  overstatement, and so does the doc comment on the very test that catches the fault
  (`lib.rs:937-941`) and `docs/adr/0012-...:24` — tracked as `btc-policy-yh7`.
  `attack all` held **16/16 and exited 0**, printing "No theft path, safety track held" with the
  extraction path live. All three demos were blind too, including `demo theft-refused` — the repo's
  NAMED v0 acceptance artifact. What caught it was `cargo test`: 681 passed, 4 failed, exit 101,
  including a differential oracle over arbitrary output sets and a test asserting attacker-controlled
  outputs are only ever hot-or-refused. The cause is scenario coverage, not architecture — every
  harness spend has exactly one destination class, so nothing ever reaches the mixed arm
  (`btc-policy-u98`, P1).

  **Corrected 2026-08-10, and the correction is instructive.** The first run of this control made
  the arm return `Hot` and called that the bypass. It is not: `Hot` takes the Hold, the Hot budget
  and the duress freeze, so nothing could be extracted and the harness's green run on THAT fault
  was correct rather than blind. Caught in review of PR #8. The distinction is the whole point of
  the class check, so getting it wrong while testing the class check is worth recording.

**A stage-9 reviewer should take two things from that.** First, a green scorecard is evidence about
the properties the sixteen scenarios actually construct, and the harness's own summary line
overstates itself: it printed "No theft path" over a live extraction path. Second, this particular
regression was still caught by CI, because `cargo test` runs in the `check` matrix, an independent
job with no `needs:` on `launch-gate` — so read the gate as a set of independent detectors, not as
the harness plus decoration. And read the class-check result narrowly: ONE ARM of `classify` was
broken — the mixed-class arm — and four tests refused it. That is NOT the arm that carried `9yf`'s
refusal. `9yf` removed `check_destinations`, so its spend was refused by the UNRECOGNIZED-OUTPUT
branch, which `nia` deliberately left untouched. The path this ADR credits above with keeping
`9yf`'s demonstration honest is therefore still unfalsified.

**NOT covered, by anything, until stage 9:**

- **SILENCE end-to-end.** The harness says so itself: "A green scorecard here is not by itself
  evidence that silence holds." It gates the wire — response bodies, sizes, `/events` — and reports
  wall-clock timing as ADVISORY only. The split is: `cargo test` covers the DETERMINISTIC property —
  `channel::duress::normal_and_duress_ingress_op_sequences_*` assert that a normal and a duress
  request perform the identical ingress operations in the identical order. `attack all` covers the
  WIRE — response bodies, body sizes, `/events`. Neither covers end-to-end TIMING, which the
  harness reports as advisory only. So running both leaves the timing channel MEASURED BUT UNGATED, which is the distinction that matters to a reviewer: `two_spend_probe` does collect and compare normal/duress latency samples and emits the skew (`crates/vault-cli/src/attack.rs`), but the samples are noisy and form no hard gate — THREAT-MODEL R10 owns that gap. A stage-9 reviewer has evidence here; what they do not have is a pass/fail.
- **Human-factors executability of the duress runbook.** Nothing tests whether a stressed operator
  can follow it without the author's context. That was exactly `tv3` (d), and it now waits for
  `yt7`.
- **Correlated-reviewer blind spots.** Two models agreeing is not corroboration. This repo has a
  recorded instance of codex and Fable both asserting the same wrong claim, corrected by the owner.

## Consequences

- Stage 1 unblocks on the freeze alone, and as of 2026-08-10 its negative-control prerequisite is
  fully satisfied: `9yf` (the launch-gate job) and `nia` (the harness) are both closed, so neither
  gates the freeze any longer. `btc-policy-u98`, the coverage hole `nia` found, is deliberately not
  a blocker — see the PREREQUISITE section for why.
- No human sees this system until stage 9. That is a choice, recorded here, not an oversight.
- If the stage-9 review finds a protocol-core flaw, the rework spans eight stages. That cost is
  accepted deliberately: rework is absorbable, loss is not, and the caps are what keep the
  intervening exposure to dust.
