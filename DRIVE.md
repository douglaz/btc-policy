# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first. One bead = one branch = one PR.
Beads outside that frontier are NOT in scope for this drive.
**Phase:** BUILD · **Bead:** (selecting) · **Branch:** —
**Pending:** metadata PR douglaz/btc-policy#7 — this record and the `9yf` closure land with it
**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`
(the stale-flake assertion plus three of the four legs of CI's `check` matrix; `regtest-backend`
is the fourth — see AGENTS.md for why each part is load-bearing)

## Done
- `btc-policy-9yf` (P0) — the launch gate can now be shown to FAIL. Merged #6 (squash `037022b`).
  Closed on the merge, which is the condition the bead set for itself; it forbids closing on
  green runs, having been closed that way once and reopened.

  What it established, and what it deliberately does not claim:
  - The gate is sensitive to a deliberately introduced policy regression — CI run 31238105663
    turned the `launch gate` job RED at `demo first-light` AND the `test` job red, while fmt,
    clippy and regtest-backend stayed green, so two independent jobs caught it and the result
    was attributable.
  - It does NOT show funds could leave: the spend was still refused by the independent
    output-derived class check (ADR-0013 §3).
  - It does NOT cover `attack all`, which was SKIPPED when the gate stopped at step 9. The
    16-scenario harness has still never been shown to fail → `btc-policy-nia` (P1).
  - Build profile is DEBUG, with the release-artifact residual left open for `gbw`/`oy3`.

## Now
Selecting the next bead from the ready frontier. `rt0` is unblocked by this closure but may not
be drainable as written — its own notes say the failure is load-sensitivity on this shared box
while CI passes that scenario, and its title ("cannot currently pass") is falsified by the green
runs since. Assess before starting; it may need rescoping rather than fixing.

Otherwise the widest unblocker is `mby` (blocks 10 beads, including `gbw`).

## Next
`gbw` is NOT unblocked by `9yf`. It carries eight `blocks` edges and five remain open
(`rt0`, `oy3`, `wdu`, `mby`, `sqn`) — correctly, since the stage-1 freeze must not name a commit
predating the operator CLI.

## Filed during this drive, not fixed here
- `btc-policy-nia` (P1) — mutation-test the harness itself; `attack all` and the class check
  have never been falsified.
- `btc-policy-gc8` (P3) — push the AGENTS.md fixes upstream; they sit in tool-managed blocks
  that `br agents --update` and the `agents-md` skill regenerate, so the local fix reverts.
- `btc-policy-o97` (P3) — DESIGN.md still prescribes the retired nine-scenario attack set.

## Open questions for the human
- none
