# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first — currently `btc-policy-9yf` (P0),
then the P1 set (`imb`, `mby`, `cod`, `oy3`, `rry`, `5ag`, `wqd`, `q6v`). One bead = one
branch = one PR. Beads outside that frontier are NOT in scope for this drive.
**Phase:** BUILD · **Bead:** btc-policy-9yf · **Branch:** fix/9yf-launch-gate
**Pending:** —
**Gate:** `nix develop -c bash -c 'cargo clippy --all-targets -- -D warnings && cargo test'`

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

Budget: 5 files (`.github/workflows/ci.yml`, `crates/vault-cli/tests/e2e.rs`,
`docs/TEST-PLAN.md`, `AGENTS.md`, `DRIVE.md`), ~140 LOC. Round 1 of max 4.

Do NOT build: a self-hosted-runner migration, a release-profile CI matrix, any change to the
attack harness's calibration constants, or new CI jobs. The release-artifact gap is real and
belongs to `oy3`/`gbw` — it is named as a residual, not closed here.

## Next
Close `9yf` → unblocks `rt0` and `gbw` → then the widest unblocker on the P1 frontier
(`mby`, which unblocks 10 beads).

## Open questions for the human
- none
