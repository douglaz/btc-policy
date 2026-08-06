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

**ONE external human review, at stage 9.** It gates the freeze that precedes lifting the dust caps,
which is the point where real savings become possible. Review #1 is removed.

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

**Relied on:** the stage-1 freeze (`gbw`); the adversarial harness (`attack all`, 16 scenarios);
proptest and fuzz suites; the full CI matrix; and multi-model AI review panels, which do find real
defects — this repo's own history includes a canonical manifest-preimage list found wrong three
times and an escape self-pairing model wrong across seven sites, all caught by automated review.

**PREREQUISITE, and it is load-bearing now rather than optional:** `btc-policy-9yf`'s negative
control gates the stage-1 freeze. Today "16/16 scenarios held" rests on a gate that has never been
observed to FAIL, which makes it a statement that the run did not report a failure — not that it
would report one. With a human at stage 1 that gap was tolerable. Without one it is the foundation,
so the freeze cannot complete until a deliberately introduced fault is confirmed to turn the gate
red.

**NOT covered, by anything, until stage 9:**

- **SILENCE end-to-end.** The harness says so itself: "A green scorecard here is not by itself
  evidence that silence holds." It gates the wire — response bodies, sizes, `/events` — and reports
  wall-clock timing as ADVISORY only. Pin-uniform ingress is gated by `cargo test` assertions that
  `attack all` does not run.
- **Human-factors executability of the duress runbook.** Nothing tests whether a stressed operator
  can follow it without the author's context. That was exactly `tv3` (d), and it now waits for
  `yt7`.
- **Correlated-reviewer blind spots.** Two models agreeing is not corroboration. This repo has a
  recorded instance of codex and Fable both asserting the same wrong claim, corrected by the owner.

## Consequences

- Stage 1 unblocks on the freeze alone, with `9yf` as its prerequisite.
- No human sees this system until stage 9. That is a choice, recorded here, not an oversight.
- If the stage-9 review finds a protocol-core flaw, the rework spans eight stages. That cost is
  accepted deliberately: rework is absorbable, loss is not, and the caps are what keep the
  intervening exposure to dust.
