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

**Relied on:** the stage-1 freeze (`gbw`); the adversarial harness (`attack all`, 16 scenarios —
and read the caveat below before weighting this: the harness itself has never been shown red on a
deliberately introduced fault, `btc-policy-nia`);
proptest and fuzz suites; the full CI matrix; and multi-model AI review panels, which do find real
defects — this repo's own history includes a canonical manifest-preimage list found wrong three
times and an escape self-pairing model wrong across seven sites, all caught by automated review.

**PREREQUISITE, and it is load-bearing now rather than optional** — and as of 2026-08-09 the bead
that carries it is `btc-policy-nia`, NOT `btc-policy-9yf`. `9yf` is closed and satisfied the half
it could; `nia` holds the half it could not (see the section below) and now `blocks`
`btc-policy-gbw`, the stage-1 freeze, directly. Do not read `9yf`'s closure as clearing this
gate. The original framing follows: `btc-policy-9yf`'s negative
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
The 16-scenario harness — the largest part of the gate and the sole support for every "16/16 held"
claim in this repo — has therefore never been shown red on a deliberately introduced fault. It HAS
failed spontaneously (`btc-policy-rt0`, `escape-class-sequences` at 15/16), so it is not vacuously
green; what is unproven is its sensitivity to an injected safety regression. The output-derived
class check that actually refused the spend here has never been falsified at all. Both are tracked
as `btc-policy-nia` (P1), and neither is closed by this prerequisite.

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

- Stage 1 unblocks on the freeze alone. Its prerequisite bead is `btc-policy-nia` as of
  2026-08-09, NOT `9yf` — see the PREREQUISITE section above; `9yf` is closed and covered
  only the launch-gate job, not the harness.
- No human sees this system until stage 9. That is a choice, recorded here, not an oversight.
- If the stage-9 review finds a protocol-core flaw, the rework spans eight stages. That cost is
  accepted deliberately: rework is absorbable, loss is not, and the caps are what keep the
  intervening exposure to dust.
