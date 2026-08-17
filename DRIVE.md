# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first. One bead = one branch = one PR.
Beads outside that frontier are NOT in scope for this drive.
**Phase:** SPEC · **Bead:** btc-policy-sxt · **Branch:** beads/sxt-clock-authority
**Pending:** —
**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`
(the stale-flake assertion plus three of the four legs of CI's `check` matrix; `regtest-backend`
is the fourth — see AGENTS.md for why each part is load-bearing)

## Done
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
Finish `sxt` SPEC review. Channel-mode Spend acceptance fixes one immutable process-monotonic
Carrier horizon from the signed lifetime remaining (non-channel stays wall-only); post-accept
wall/effective samples can refuse but never retire or extend
state. Exact authenticated, quota-admitted actionable receipts receive fixed 30-second retry at all three
Carrier clock-refusal sites and through the narrow outer-Stale receipt path; terminal/nonmatching
stale input stays `STALE_TIMESTAMP`, and every stale case records the same high-water-keyed diagnostic. Receiver
correction still waits for elapsed time to re-enter the latched 300-second window before the sender
and monotonic bounds. One resident Carrier owns one nonce in the existing coordinator capacity; no
overlapping body, second cap, schema, lease, or general `/sign` admission. q6v's verified-tag/one-KDF
alternate-signature bound remains, with exact-expiry and terminal-state guards. Carrier intent+memo
retirement is store-only on non-staged terminal owner exit, the fully
completed holder decision, the fixed horizon after owner release, or reboot; immutable `D` stays on
the nonce replay/fan-out tombstone until it lapses, and pruning removes that entry only after wall
expiry also ends. Candidate expiry remains separate. The production-fixed, test-pinnable `HotClock`
supplies the monotonic instant; every store prune driver may execute deadline retirement without
wall-clock authority. The outer-Stale final check briefly serializes `sign_state → store`, keeps KDF
outside both locks, and freshness diagnostics coalesce by peer plus ingress high-water.

## Next
Obtain one final Opus/Codex READY pass on the corrected integrated spec, then land the spec/evidence
baseline before Rust. Implement only through bounded rb-lite children, sequentially in one ownership
lane: `qzo` diagnostics (**400 gross Rust = ~110 prod + 290 test**), `o5g` nonce deadline
(**650 = ~230 + 420**), `0hv` store retirement (**950 = ~280 + 670**), `7ip` ordinary receipt retry
(**550 = ~130 + 420**), and `30c` outer-Stale (**700 = ~150 + 550**). `5io` and `ok4` are their
integration owners. Total hard cap: **3,250 gross Rust lines, ~900 production + 2,350 tests**; tests
are 2.61× production from measured repository/q6v density, and every line is counted. `sxt` closes
only after all children and custody-critical gates.
`mby` remains the widest product unblocker but must first be distilled; do not hand its
~30k-character accumulated record directly to an implementation run.

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
- `btc-policy-r1g` (P2) — `/channel` freshness high-water survives raw clock correction and can
  blackhole every peer message until real time catches the 300-second window, with no protocol bound
  on that duration. It depends on `sxt`;
  do not widen `sxt` into global freshness authority.

## Open questions for the human
- none
