# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first. One bead = one branch = one PR.
Beads outside that frontier are NOT in scope for this drive.
**Phase:** GRAPH · **Bead:** btc-policy-5ag · **Branch:** beads/5ag-network
**Pending:** land the reviewed two-child network graph, then implement child
`btc-policy-sealed-network-v2-mn6` through rb-lite on its own branch; keep both intermediates
non-deployable
**Selection:** `br ready` showed several unblocked P1s on 2026-08-18; `mby` is next because its
recorded 2026-07-30 Codex+Fable split identifies it as the whole-ladder product blocker, after the
bounded custody fix chosen ahead of it (`q6v`/`sxt`) closed. This is an explicit drive choice, not
a `br ready` ranking.
**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`
(the stale-flake assertion plus three of the four legs of CI's `check` matrix; `regtest-backend`
is the fourth — see AGENTS.md for why each part is load-bearing)

## Done
- `btc-policy-mby-manifest-v1-zero-ceiling-88w` (M1, P1) — manifest schema revision 1
  appends and seals the zero-only Escape ladder ceiling, preflights old node configs, refuses
  nonzero ceilings until `sqn`, and publishes one owner-only complete setup artifact set. Merged
  #21 (`53ae011`) at the exact 800-line Rust cap after Codex+Opus rb-lite review, current-head bot
  review, live regtest, and both launch gates. The pre-existing ceremony-parent namespace remains
  explicitly blocked by `b8z` before M6; M1 itself does not authorize a production ceremony.
- `btc-policy-sxt` (`q6v` + `qzo` + `o5g` + `0hv` + `7ip` + `30c` + `ok4`, P1) —
  bare wall-clock reads cannot retire live Carrier confirmation state; accepted `D` supplies
  monotonic authority; under the current `coord_nonces.high_water < E` premise, recoverable exact
  receipts retry through both ordinary and outer-Stale paths without lowering freshness
  high-water. Final child #18 merged as `31303f1`. `br show btc-policy-30c` owns the red-first,
  13-mutation and command/exit evidence; `br show btc-policy-ok4` and `br show btc-policy-sxt`
  own the integrated closure and known-limit qualification. They are linked, not recopied here.
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
Record the reviewed `btc-policy-5ag` split. `btc-policy-sealed-network-v2-mn6` (A) owns the sealed
network byte, revision 2, backend/default-public-signet identity, seven real driver sites, the
three-network Core oracle, and neutral `sealed/` path at **1,150 gross Rust / 230 non-Rust**.
`btc-policy-descriptor-network-kind-x00` (B) depends on A and owns required Escape keygen network
plus one shared `policy-core` Main/Test XPub validator at assemble, finalize, and node load at
**520 gross Rust / 95 non-Rust**. Every Rust cap includes every production, test, helper and fixture
line; tests are estimated at 63% of A and 70% of B. The tracking parent has no implementation
budget. The `mby` umbrella remains open, stage 1 remains unreachable, and `b8z` must close before M6
consumes the ceremony output end to end.

## Next
After this graph-only PR merges, branch from current `main`, claim
`btc-policy-sealed-network-v2-mn6`, and implement A through one rb-lite run/branch/PR. M1's
`protocol_version = 1` is a manifest-schema revision, not routable transport v1; A must not reuse it
after changing the canonical preimage. A lands explicitly non-deployable. Only after A merges,
claim `btc-policy-descriptor-network-kind-x00` and implement B through its own rb-lite
run/branch/PR; B changes no preimage layout and performs no second version bump. Then close the
tracking parent in a reviewed record.
M2 may parse pre-M1 artifacts for cold use but rejects them before live hash validation or network
I/O. Then implement M2 operator core, M3 stable Core composer, M4 Spend command, and the parallel
M5 known-outpoint Escape / M6 stage-1 artifact-to-command evidence children one at a time through
rb-lite. M4/M5 reuse one exact request across ordered stage-1 ingress attempts and report success
only after Core observes node-side threshold combine/broadcast; M6 mutation-tests that non-ingress
nodes receive and validate it through the request channel. M5 rejects unknown/spent/off-vault
outpoints and ships the mandatory two-transaction base Escape pair with an empty bump ladder; M1
rejects every nonzero ceiling until `sqn`. `wdu` follows M1+5ag; `sqn` follows M5 because it decides
whether that escape-class command's delayed residual carries rungs. Other
complete-product dependents stay
blocked on `mby`. `imb` owns confidential authenticated coordinator ingress and routable peer
transport from stage 2 onward; the operator CLI remains on the coordinator host.

The reviewed hard Rust caps are **4,050 gross lines total, additions plus deletions with every test
line included**: M1 800, M2 900, M3 500, M4 500, M5 850, M6 500. The estimate is approximately
1,450 production + 2,600 tests, so tests are 64.2% of the Rust budget; non-Rust evidence/docs total
700. Exact scope and stop conditions live in each child bead. These caps supersede the old
2,500–4,500 estimate, which never said whether tests or deletions counted.

The broader channel and coordinator high-water repairs remain separately owned by `r1g` and
`coord-highwater-carrier-recovery-i3p`; neither is folded into the operator CLI. PR #18's P3
unwind/test-synchronization follow-ups do not reopen Carrier clock authority.

`gbw`'s direct open blockers, refreshed from `br show btc-policy-gbw --json` on 2026-08-18:
`mby`, `oy3`, `rt0`, `sqn`, `wdu`. `6nq`, `9yf`, `c9r` and `nia` are closed. The closed edges stay
in the graph deliberately — `br ready` counts only open blockers, and the record that the gate
existed is worth more than a tidy list.

## Filed or adjudicated during this drive, not implemented here
- `btc-policy-cyberkrill-independent-claims-zgl` (P3) — the 5ag review withdrew cyberkrill as
  an independent address encoder and moved `00i` to A's flake-pinned Core oracle, but the rollout
  pre-funding checklist and `wdu` still use cyberkrill for whole-descriptor/timelock read-back.
  Audit independent implementation versus merely separate binary/caller before changing either
  live check; do not delete the pre-funding verification.
- `btc-policy-sealed-host-cli-packaging-u4y` (CLOSED/rejected) — it conflated the dedicated
  coordinator with an ADR-0005 node image. A sealed node has no lawful interactive invocation or
  secret-input surface, and stage 2+ no longer uses the v0 loopback topology. `4y3` owns the
  coordinator's reproducible install slot; `4wx` binds the `oy3`-identified operator artifact and
  proves it against `imb` transport before stage 4. The invalid `s12 -> u4y` edge was removed.
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
- `btc-policy-r1g` (P2) — `/channel` freshness high-water survives raw clock correction and can
  blackhole every peer message until real time catches the 300-second window, with no protocol bound
  on that duration. It depends on `sxt`; `btc-policy-coord-highwater-carrier-recovery-i3p` (P2) tracks
  the separate coordinator-nonce high-water coupling; do not widen `sxt` into either authority.

## Open questions for the human
- none
