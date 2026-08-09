# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first — currently `btc-policy-9yf` (P0),
then the P1 set (`imb`, `mby`, `cod`, `oy3`, `rry`, `5ag`, `wqd`, `q6v`). One bead = one
branch = one PR. Beads outside that frontier are NOT in scope for this drive.
**Phase:** HARDEN · **Bead:** btc-policy-9yf · **Branch:** fix/9yf-launch-gate
**Pending:** metadata PR douglaz/btc-policy#6 — `9yf` closes when it merges, not before
**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'` (the stale-flake assertion plus three of the four legs of CI's `check` matrix; `regtest-backend` is the fourth — see AGENTS.md for why each part is load-bearing) · last green 2026-08-09 (exit 0, 685 passed / 0 failed)

## Done
- (nothing closed by this drive yet)

## Now
`btc-policy-9yf` (P0). The problem AS FILED — history, not current state: the launch gate had
never been shown to FAIL, the debug-vs-release profile was undecided, and `recovery-drill` was
ungated. All three now have evidence:

1. **Negative control — DONE.** `test/9yf-negative-control` removed the destination allowlist;
   CI run 31238105663 turned the `launch-gate` job RED at step 9 `demo first-light`, while
   the `test` job also went red (4 policy-core tests, exit 101) while fmt, clippy and
   regtest-backend stayed green — two independent jobs caught it, and the result was
   attributable rather than a blanket red. Read it precisely:
   the spend was still refused by the independent output-derived class check (ADR-0013 §3), so
   what is shown is *a weakened control is detected*, NOT *funds leave*.
2. **Build profile — DONE.** DEBUG, recorded in the `.github/workflows/ci.yml` header with its
   rationale and its residual (the shipped artifact is release; that gap is `gbw`/`oy3`).
3. **Demo coverage — DONE.** `demo recovery-drill` is a gate step, with its source and its
   scorecard section in the artifact.

Review evidence. The three reviewers below all ran on the SAME tree, tip `2052ea9`; the CI
line is deliberately separate because it names a different commit, and conflating the two is
what this bead exists to stop:

- `codex review --base origin/main -c model=gpt-5.6-sol -c model_reasoning_effort=xhigh`
  → exit 0, no findings (9 consecutive passes)
- `claude -p <review prompt> --model fable --effort high` → exit 0, `No findings.`
- consistency pass (fable, whole-artifact) → 2 findings, both dispositioned below
- `nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace
  --all-targets -- -D warnings && cargo test --locked --workspace'` → **EXIT=0**,
  685 passed / 0 failed
- CI: the last FULL launch-gate run is 31266297634 on commit `4b39fd4` (tree
  `1396e654`) → 5/5 jobs, launch gate steps 9-12 (`first-light`, `theft-refused`,
  `recovery-drill`, `attack all`) each `conclusion=success`. That is NOT the reviewed tip
  `2052ea9` (tree `0eafe57`) and must not be read as evidence about it: the commits since
  are documentation-only, but "documentation-only" is a claim about the diff, not a gate
  result. The merge is gated on a green run of the actual merged tip, not on this one.

Files changed: `git diff origin/main --name-only`.

That is deliberately a command and not a list. A hand-maintained inventory of the branch's own
files is a copy of something git already knows, so it can only ever drift — and it did, twice
in three commits (7 named when it was 9, then 9 when it was 10), each time costing a review
round and a CI cycle to correct a fact that was never worth recording by hand. Derive it.

Do NOT build: a self-hosted-runner migration, a release-profile CI matrix, any change to the
attack harness's calibration constants, or new CI jobs. The release-artifact gap is real and
belongs to `oy3`/`gbw` — it is named as a residual, not closed here.

## Next
Closing `9yf` makes `rt0` ready. It does **not** make `gbw` ready — `gbw` carries eight
`blocks` edges, and after `9yf` closes five are still open (`rt0`, `oy3`, `wdu`, `mby`,
`sqn`), which is correct: the stage-1 freeze must not name a commit that predates the
operator CLI. So the frontier after this bead is `rt0`, then the widest unblocker on the
P1 set — `mby`, which blocks 10 beads including `gbw` itself.

## Open questions for the human
- none
