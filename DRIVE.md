# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first. One bead = one branch = one PR.
Beads outside that frontier are NOT in scope for this drive.
**Phase:** HARDEN · **Bead:** btc-policy-q6v · **Branch:** fix/q6v-passive-receipt-clock
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
  injected Lockdown-at-T fault, after all three demos cleared it, and is BLIND to an injected
  mixed-class EXTRACTION path — a spend that completes instantly under the duress PIN, and which is
  extraction only WITH STOLEN HOT KEYS, since its outputs pay the user's own hot wallet — which
  `cargo test` caught instead. Figures deliberately omitted — the ADR owns them, and a copy here is
  how the last one drifted.
  Neither fault was ever pushed — both controls ran locally, which is a deliberate change of method
  from `9yf` after its public negative-control branch was deleted on 2026-08-10.

## Now
`q6v`: make passive receipt lookup non-destructive under a forward raw-clock sample, return a
retryable reply for the matching request generation, and retain bounded cleanup at accepted-nonce
transitions. Budget: all Rust implementation and test changes count together, with a soft 400 /
hard 430 gross-line checkpoint. Summing additions and deletions from
`git diff --numstat origin/main -- '*.rs'` gives 430 gross Rust lines, at the cap; adding
`docs/THREAT-MODEL.md` to that command gives a 456-line audited product/doc diff.
Do NOT build: clock service/persistence/schema changes, candidate-expiry redesign, `/sign`
admission control, or the other destructive clock-pruning paths.

The production residual outside q6v's passive-lookup seam is tracked as P1 bug `btc-policy-sxt`,
which depends on q6v. Its acceptance criteria cover the 1 Hz fire sweep, post-acceptance clock
re-reads, and the two-sample confirmation straddle with red/green production-path evidence.

## Next
Finish q6v HARDEN on this exact tree: Codex + Fable clean together, then independently run the
exact AGENTS.md gate, ignored regtest backend, and full launch gate. LAND only the reviewed tree;
close q6v through the reviewed metadata path.

After q6v lands, re-derive the P1 frontier. `sxt` becomes ready and carries the remaining
clock-authority theft residual. `mby` remains the widest product unblocker but must first be
distilled into a bounded rb-lite task; do not hand its ~30k-character accumulated record directly
to an implementation run.

`gbw`'s open blockers, computed from the dependency graph 2026-08-10, not counted by hand:
`mby`, `oy3`, `rt0`, `sqn`, `wdu`. `6nq`, `9yf`, `c9r` and `nia` are closed. The closed edges stay
in the graph deliberately — `br ready` counts only open blockers, and the record that the gate
existed is worth more than a tidy list.

## Filed during this drive, not fixed here
- `btc-policy-u98` (P1, raised from P2) — `attack all` is blind to a mixed hot+escape spend because no scenario
  builds one. Cheap: `build_spend_n` already takes a general output slice. Its done-definition
  requires re-injecting the fault to prove the new scenario CAN go red.
- `btc-policy-yh7` (P3) — `classify`'s TxClass doc comment, the doc comment on the test that
  catches the fault, and `docs/adr/0012`:24 all assert UNCONDITIONALLY that a 99%-to-hot spend
  completes under the duress PIN. The class-independent per-transaction Hot budget refuses it
  whenever its outflow exceeds the configured cap — so the claim is not absolute, and that is
  the defect. Mechanism right, magnitude wrong; ADR-0017 inherited it before review caught it.
- `btc-policy-gc8` (P3) — push the AGENTS.md fixes upstream; they sit in tool-managed blocks that
  `br agents --update` and the `agents-md` skill regenerate, so the local fix reverts.
- `btc-policy-o97` (P3) — a DESIGN.md audit, rescoped from a site list to a sweep after three
  review passes each found sites the previous enumeration had missed (2 → 5 → 8).
- `btc-policy-8sq` — CLOSED as a duplicate of the pre-existing `tf0`.
- `btc-policy-sxt` (P1) — forward-clock sweeps and confirmation resampling can still destroy
  ruled carrier state outside q6v's passive lookup. This is a separate eviction-authority defect,
  not a reason to widen q6v into a clock subsystem.

## Open questions for the human
- none
