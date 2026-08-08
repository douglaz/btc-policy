# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first — currently `btc-policy-9yf` (P0),
then the P1 set (`imb`, `mby`, `cod`, `oy3`, `rry`, `5ag`, `wqd`, `q6v`). One bead = one
branch = one PR. Beads outside that frontier are NOT in scope for this drive.
**Phase:** HARDEN · **Bead:** btc-policy-9yf · **Branch:** fix/9yf-launch-gate
**Pending:** metadata PR douglaz/btc-policy#6 — `9yf` closes when it merges, not before
**Gate:** `nix develop -c bash -c 'cargo clippy --all-targets -- -D warnings && cargo test'` · last green 2026-08-08 (exit 0, 685 passed / 0 failed)

## Done
- (nothing closed by this drive yet)

## Now
`btc-policy-9yf` (P0) — the launch gate has never been shown to FAIL. Three deliverables:

1. **Negative control.** A deliberately broken branch must turn the `launch-gate` job RED.
   Until that exists, "green" means "did not report a failure", not "would report one".
2. **Build profile.** Decide debug vs release for the gate and write it down. → DEBUG,
   recorded in the `.github/workflows/ci.yml` header with its rationale and its residual.
3. **Demo coverage.** The CLI has three demos; the gate ran two. → `demo recovery-drill`
   is now a gate step, with its source and its scorecard section in the artifact.

All three now have evidence. Round 4 of max 4 — stopping here; the finding stream went from
P1-class substance to one P3 and bookkeeping contradictions, which is the gold-plating signal.

Panel on `c22e544`: codex clean ×4, fable clean, consistency clean — all on the same tree.
CI on `c22e544`: 5/5 jobs green, launch gate ran all three demos + `attack all`, every step
exit 0. Files: `.github/workflows/ci.yml`, `crates/vault-cli/tests/e2e.rs`, `docs/TEST-PLAN.md`,
`docs/adr/0017-*.md`, `AGENTS.md`, `DRIVE.md`, `.beads/issues.jsonl`.

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
