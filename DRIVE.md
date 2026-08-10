# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first. One bead = one branch = one PR.
Beads outside that frontier are NOT in scope for this drive.
**Phase:** BUILD · **Bead:** btc-policy-nia · **Branch:** fix/nia-harness-negative-control
**Pending:** —
**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`
(the stale-flake assertion plus three of the four legs of CI's `check` matrix; `regtest-backend`
is the fourth — see AGENTS.md for why each part is load-bearing)

## Done
- `btc-policy-9yf` (P0) — the launch gate can now be shown to FAIL. Merged #6 (`037022b`); its
  closure record and the beads it spawned merged #7 (`8f1979c`). Closed on the merge, which is the
  condition the bead set for itself.

  Read the closure reason in `br show btc-policy-9yf` rather than restating it here — the limits
  are the load-bearing half and they have been rewritten three times to stop them being
  overclaimed. The one-line version: the gate reports a deliberately introduced regression, and
  that is strictly less than "funds cannot leave".

## Now
`btc-policy-nia` (P1) — mutation-test the harness and the output-derived class check. Two negative
controls, and the constraint that shapes both: the fault must survive gate steps 9-11 so that
step 12 (`attack all`) actually runs. `9yf`'s fault did not, which is why this bead exists.

Chosen over `mby` (the wider unblocker: 10 direct / 21 transitive, versus `nia`'s 1 / 12) because
both are P1 and this session already holds the context — gate step ordering, `if: always()`
scoping, the harness, ADR-0013 §3. `mby` is a money-path surface that deserves a fresh start.

Do NOT build: a general mutation-testing framework, a new CI job, or a second harness. This is two
injected faults and the evidence that each turns something red.

## Next
`mby` (Operator CLI core) — the widest unblocker in the graph and the v0 operator-path gap: the
vault can be sealed but never spent from. Then re-derive the frontier rather than trusting this
line; it has gone stale once.

`gbw`'s remaining open blockers, verified 2026-08-10 against the dependency graph rather than
counted by hand: `mby`, `nia`, `oy3`, `rt0`, `sqn`, `wdu`. `6nq`, `9yf` and `c9r` are closed.

## Filed during this drive, not fixed here
- `btc-policy-nia` (P1) — now the bead in progress; see Now.
- `btc-policy-gc8` (P3) — push the AGENTS.md fixes upstream; they sit in tool-managed blocks
  that `br agents --update` and the `agents-md` skill regenerate, so the local fix reverts.
- `btc-policy-o97` (P3) — a DESIGN.md audit. Rescoped from a site list to a sweep after three
  review passes each found sites the previous enumeration had missed (2 → 5 → 8).
- `btc-policy-8sq` — CLOSED as a duplicate of the pre-existing `tf0` (README/IDEA drift).

## Open questions for the human
- none
