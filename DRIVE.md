# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first. One bead = one branch = one PR.
Beads outside that frontier are NOT in scope for this drive.
**Phase:** PLAN · **Bead:** btc-policy-mby · **Branch:** —
**Pending:** distill and split before any rb-lite implementation run
**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`
(the stale-flake assertion plus three of the four legs of CI's `check` matrix; `regtest-backend`
is the fourth — see AGENTS.md for why each part is load-bearing)

## Done
- `btc-policy-sxt` (`q6v` + `qzo` + `o5g` + `0hv` + `7ip` + `30c`, P1) — bare
  wall-clock reads cannot retire live Carrier confirmation state; accepted `D` supplies monotonic
  authority; recoverable exact receipts retry through both ordinary and outer-Stale paths without
  lowering freshness high-water. Final child #18 merged as `31303f1`; its reviewed head passed
  fmt, Clippy, workspace tests, live-Core regtest and both launch gates.
- `btc-policy-qzo` (P1) — repeated channel-freshness diagnostics coalesce by peer plus
  ingress high-water without evicting unrelated watchtower evidence. Merged #12 (`40c3269`);
  closure merged #13 (`3171f47`).
- `btc-policy-5io` (`o5g` + `0hv`, P1) — channel-mode Spend acceptance fixes immutable
  Carrier deadline `D`; nonce liveness uses wall-live OR monotonic-live; Carrier state retires
  only through store monotonic/terminal authority. The unsafe intermediate never landed:
  both children merged atomically in #14 (`6f1ef82`), with closure in #15 (`8c80d82`).
- `btc-policy-7ip` (P1) — ordinary fresh Carrier receipts enforce `E`/`D` actionability,
  preserve state on recoverable wall-clock refusal, and retry at 30 seconds while short
  owner/KDF windows remain one second. Merged #16 (`8b05c56`); this branch records closure.
- `btc-policy-q6v` (P1) — passive carrier-receipt lookup is non-destructive under forward
  clock excursions, retained retries are generation/sender scoped, and conflicting signatures
  resolve through the bounded memory-hard carrier path without retaining a fast PIN verifier.
  Merged #9 (`8bd896d`); the reviewed Rust implementation plus tests reached the 430-line hard
  cap, with the remaining clock-authority paths tracked separately as `btc-policy-sxt`.
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
Distill `btc-policy-mby` before implementation. Its accumulated record spans the sealed-manifest
substrate, signer seam, protocol/preimage versioning, ceremony, fee handling, operator commands,
documentation and E2E evidence; handing that bundle directly to rb-lite would violate the
one-self-contained-task rule. Re-derive the dependency order and hard budgets with every test line
included, then create bounded code children.

## Next
Review the split with Codex and Opus, then implement and land one child at a time through rb-lite.
The broader channel and coordinator high-water repairs remain separately owned by `r1g` and
`coord-highwater-carrier-recovery-i3p`; neither is folded into the operator CLI. PR #18's
invariant-panic unwind and test-synchronization observations are P3 follow-ups, not reopened
Carrier clock-authority work.

`gbw`'s open blockers, computed from the dependency graph 2026-08-10, not counted by hand:
`mby`, `oy3`, `rt0`, `sqn`, `wdu`. `6nq`, `9yf`, `c9r` and `nia` are closed. The closed edges stay
in the graph deliberately — `br ready` counts only open blockers, and the record that the gate
existed is worth more than a tidy list.

## Filed during this drive, not fixed here
- `btc-policy-carrier-claim-unwind-hardening-i2o` (P3) — give both ordinary and outer-Stale
  alternate-signature claims one exact generation/sender/tag unwind owner if the presently
  invariant-only KDF panic boundary ever unwinds.
- `btc-policy-outer-stale-test-sync-ykp` (P3) — replace the two scheduler-yield polls with
  deterministic test milestones; the mutation is pinned, but the current negative assertion can
  pass before its worker reaches the guarded region.
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
- `btc-policy-r1g` (P2) — `/channel` freshness high-water survives raw clock correction and can
  blackhole every peer message until real time catches the 300-second window, with no protocol bound
  on that duration. It depends on `sxt`; `btc-policy-coord-highwater-carrier-recovery-i3p` (P2) tracks
  the separate coordinator-nonce high-water coupling; do not widen `sxt` into either authority.

## Open questions for the human
- none
