# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first. One bead = one branch = one PR.
Beads outside that frontier are NOT in scope for this drive.
**Phase:** HARDEN · **Bead:** btc-policy-nia · **Branch:** fix/nia-harness-negative-control
**Pending:** —
**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`
(the stale-flake assertion plus three of the four legs of CI's `check` matrix; `regtest-backend`
is the fourth — see AGENTS.md for why each part is load-bearing)

## Done
- `btc-policy-9yf` (P0) — the launch-gate JOB can be shown to FAIL. Merged #6 (`037022b`) and #7
  (`8f1979c`).
- `btc-policy-nia` (P1) — the HARNESS mutation-tested, both ways. Read the closure reason in
  `br show btc-policy-nia`; it is not restated here, and the numbers live in
  `docs/adr/0017-one-external-review-at-stage-9.md`, which owns them.

  The one-line version, and both halves must travel together: the harness DOES go red on an
  injected Lockdown-at-T fault (`arm-split-closed` FAIL, after all three demos cleared it), and is
  BLIND to an injected mixed-class duress bypass (16/16 held, exit 0, while `cargo test` caught it).
  Neither fault was ever pushed — both controls ran locally, which is a deliberate change of method
  from `9yf` after its public negative-control branch was deleted on 2026-08-10.

## Now
Landing `nia`. Docs touched: ADR-0017 (four sites — the retired "never shown red" claim, the
Relied-on ordering, the prerequisite, the consequence), TEST-PLAN, ROLLOUT-PLAN, and two beads
(`ytl`'s citation, `nia`'s own title, which asserted what its results disprove).

## Next
`mby` (Operator CLI core) — the widest unblocker: 10 direct / 21 transitive, and the v0
operator-path gap (the vault can be sealed but never spent from). Re-derive the frontier before
starting rather than trusting this line.

`gbw`'s open blockers, computed from the dependency graph 2026-08-10, not counted by hand:
`mby`, `oy3`, `rt0`, `sqn`, `wdu`. `6nq`, `9yf`, `c9r` and `nia` are closed. The closed edges stay
in the graph deliberately — `br ready` counts only open blockers, and the record that the gate
existed is worth more than a tidy list.

## Filed during this drive, not fixed here
- `btc-policy-u98` (P2) — `attack all` is blind to a mixed hot+escape spend because no scenario
  builds one. Cheap: `build_spend_n` already takes a general output slice. Its done-definition
  requires re-injecting the fault to prove the new scenario CAN go red.
- `btc-policy-gc8` (P3) — push the AGENTS.md fixes upstream; they sit in tool-managed blocks that
  `br agents --update` and the `agents-md` skill regenerate, so the local fix reverts.
- `btc-policy-o97` (P3) — a DESIGN.md audit, rescoped from a site list to a sweep after three
  review passes each found sites the previous enumeration had missed (2 → 5 → 8).
- `btc-policy-8sq` — CLOSED as a duplicate of the pre-existing `tf0`.

## Open questions for the human
- none
