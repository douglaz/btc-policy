# DRIVE — drain the btc-policy bead backlog

**Scope:** the `br ready` frontier, highest priority first. One bead = one branch = one PR.
Beads outside that frontier are NOT in scope for this drive.
**Phase:** IMPLEMENT · **Bead:** btc-policy-m3a-core-view-inventory-rha ·
**Branch:** feat/m3a-core-view
**Pending:** mechanically split and land the reviewed dormant Core adapter/inventory half at
906 production Rust / 60 production non-Rust while test code and test-only evidence remain uncapped
but mandatory
**Selection:** `br ready` showed several unblocked P1s on 2026-08-18; `mby` is next because its
recorded 2026-07-30 Codex+Fable split identifies it as the whole-ladder product blocker, after the
bounded custody fix chosen ahead of it (`q6v`/`sxt`) closed. This is an explicit drive choice, not
a `br ready` ranking.
**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`
(on this claim base, the stale-flake assertion plus three of the four existing CI `check` legs;
`regtest-backend` is the omitted LIVE leg. M3a must add `core-view` as a fifth leg, after which
both LIVE legs are omitted here — see AGENTS.md for why each part is load-bearing)

## Done
- `btc-policy-mby-user-signer-tae` + tracking umbrella `btc-policy-mby-operator-core-signer-7vb`
  (M2 child B, P1) — one file-backed zeroizing software signer implements the frozen
  `UserAuthorization`/`UserSigner` seam over A's secret-free `LiveVault`; mandatory full-prevtx truth,
  derived Refresh/Hot/Escape classes, symmetric pair relations, Escape ladder relay/whole-fee bounds,
  output-complete network-correct operator display, and all-fallible-work-before-SIGHASH_ALL are pinned.
  Merged #31 (`c26e3ed`) from reviewed head `14ded92`; trees are identical. Production is 543/550 Rust
  and 0/80 non-Rust. Tests were uncapped by owner direction: exactly 17 classes, 66/66 attributed
  mutations, exact local/live/launch gates, two current-head Codex rounds, CodeRabbit, bot-gate, and
  both CI launch jobs all cleared. Closing B and the umbrella unblocks M3; no command or PIN surface
  landed here.
- `btc-policy-mby-sealed-vault-ingress-s7u` (M2 child A, P1) — current revision-2 public/policy
  artifacts load from one explicit non-secret directory; a separately selected owner-only/no-follow
  credential verifies against the pinned public key and never enters `LiveVault`; old revisions fail
  before sibling/credential/network I/O; captured pre-M1 bytes, recovery timelock, hash/identity/
  endorsement checks, deterministic endpoint facts, exact-body/nonce reuse, sticky 400/413/replay
  semantics, and Accepted payloads are pinned. Merged #29 (`0754689`); its exact
  `0ed8095..0e85254` budget is 1,247/1,250 gross Rust and 82/120 tracked non-Rust, with the claim
  commit's 43 lifecycle lines (41 DRIVE + 2 Beads) forming the base rather than the work. After
  rb-lite, 32/32 killed mutations, independent exact-byte local/live/launch reruns, two current-head
  Codex rounds, and both CI launch gates succeeded. A remains pre-command substrate:
  `btc-policy-http-bounded-ingress-response-qhe` is the mandatory M4 blocker for the inherited
  read-to-close deadline/cap/framing gap.
- `btc-policy-descriptor-network-kind-x00` + tracking parent `btc-policy-5ag` (P1) — one shared
  `policy-core` validator binds every XPub/MultiXPub destination to the sealed network at assemble,
  finalize, and node load; definite keys stay neutral; Escape keygen now requires `--network`.
  Merged #26 (`8848d66`) at 519/520 gross Rust and 92/95 gross non-Rust after B1-B6 mutations,
  Codex+Opus review, independent audit, live Core, and both launch gates. This branch records both
  closures; downstream rollout gates, not 5ag, authorize deployment.
- `btc-policy-sealed-network-v2-mn6` (5ag child A, P1) — manifest revision 2 seals
  Bitcoin/default-public-Signet/Regtest as explicit codes 1/2/3; old revisions fail before current
  schema/hash/I/O; startup binds to the existing Core chain response and exact public-Signet
  challenge before IBD; the seven ceremony-backed address sites follow the sealed network; three
  fixed digests and offline Core address oracles pin the mapping; live artifacts use neutral
  `sealed/`. Merged #24 (`b7a92b5`) at the exact 1,150-line Rust cap after Codex+Opus review,
  independent adjudication, live regtest, and both launch gates. A is deliberately non-deployable:
  `btc-policy-descriptor-network-kind-x00` remains mandatory.
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
The first rb-lite implementation of M3 exercised the complete reviewed contract and its final governed
`r13` bytes passed 43/43 mutations, the exact local gate, both LIVE legs and all four launch commands, but
measured **895 production Rust against the 650 hard stop**. The code-only floor was 667, so this is an
estimation miss rather than a trimming opportunity. Codex gpt-5.6-sol xhigh and Opus xhigh found no
money-path defect and independently required the recorded split. Original
`btc-policy-mby-spend-composer-l5p` is now tracking-only.

Implement M3a `btc-policy-m3a-core-view-inventory-rha`: the independently compilable eight-read
`CoreRpc`, public-Signet/IBD binding, one physical stable-inventory module, exact early pair/vsize
preflight, block-qualified full-prevtx authority, incremental 64-MiB projection, and node fee
reads/conversion. Its one-time artifact-ratification caps are 906 production Rust / 60 production
non-Rust, with reforecast triggers 800/52. It owns 38 red-first rows, an inventory/preflight-only
`core-view` LIVE leg and TEST-PLAN text, and a fresh shared-lock/hash-bound serial DONE run. No command or
reachable root caller lands. The legacy Core funnel remains dormant, unbounded in time/body/framing and
lossy at invalid UTF-8 until qhe.

## Next
Finish and independently verify M3a through rb-lite at 906/60 (reforecast 800/52), then land it alone.
M3b `btc-policy-m3b-spend-composition-nq8` depends on M3a and owns the two `LiveVault` fields plus final
values, sealed Escape floor, full-parent/SIGHASH attachment, dust/coverage/policy and the frozen
authorization. Its caps are 280/10 (reforecast 245/8), it owns seven local mutations, and its final stack
must run all 45 M3 rows. qhe also depends on M3a and may land before or after M3b; whichever lands second
rebases and runs the full M3+qhe mutation/gate union under the shared evidence lock. Close tracking
`l5p` after M3b; qhe is not a tracker prerequisite, but it remains a direct M4 prerequisite.

Then complete qhe at 290/50 (reforecast 250/42), rewire M3a's one Core funnel plus ingress to the bounded
byte transport, and close qhe before M4. Then re-derive M4's
production-only budget and implement the
Spend command and the parallel
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

The former 6,000-Rust/770-non-Rust aggregate mixed production and tests and is retired. From B onward,
each executable bead must be re-derived before claim as a **production-only** gross cap: additions plus
deletions in production code, production helpers/documentation, and integration wiring count; test
modules, test-only helpers/fixtures, mutation harnesses, and test-only evidence do not. Exclusion from
the cap is not exclusion from delivery: named red controls, mutation sensitivity, review, and all gates
remain mandatory and may grow as needed. Recorded converted caps are B 550/80, M3a 906/60, M3b 280/10,
and qhe 290/50 production Rust/non-Rust. Original M3 is tracking-only and has no implementation cap.
M4–M6 still carry retired mixed caps and must be re-measured before their rb-lite claims. Counts are over
`<claim commit>..<reviewed head>`; gitignored `.rb-lite/` evidence remains untracked evidence rather than
production.

The broader channel and coordinator high-water repairs remain separately owned by `r1g` and
`coord-highwater-carrier-recovery-i3p`; neither is folded into the operator CLI. PR #18's P3
unwind/test-synchronization follow-ups do not reopen Carrier clock authority.

`gbw`'s direct open blockers, refreshed from `br show btc-policy-gbw --json` on 2026-08-23:
`mby`, `oy3`, `rt0`, `sqn`, `wdu`, `w2b`, and `yw4`. `6nq`, `9yf`, `c9r` and `nia` are closed. The closed edges stay
in the graph deliberately — `br ready` counts only open blockers, and the record that the gate
existed is worth more than a tidy list.

## Filed or adjudicated during this drive, not implemented here
- `btc-policy-w2b` (P1) — M3's confirmed-only stage-1 composer loudly refuses a scanned vault coin spent
  in the mempool; it does not yet discover/include vault-authorized-unconfirmed descendants, so normal
  Spend and its duress arm are unavailable while a prior Spend remains mempool-spent, with no protocol
  time bound and no safe inference from eviction alone. ADR-0012/0013 retain the stronger node denominator
  and name this temporary narrowing. `w2b` depends on M3+qhe and directly blocks
  `gbw`; before implementation it must re-derive the bounded ancestry mechanism and production-only budget.
- `btc-policy-yw4` (P1) — finite Core/full-prevtx-memory/wire caps are mandatory, but a confirmed donor can
  use a pathological parent or enough UTXO fragmentation to make the first all-input composer refuse.
  Separately, M3's one-change consolidation leaves the one-UTXO topology M5 must reject. M3 bounds parent
  fetch/cloning incrementally; M4 strips full parents after signing and preflights both wire envelopes.
  `yw4` depends on M3+qhe+M4+M5 and blocks `gbw` until bounded protected-set/resource and reserve-topology
  decisions close both donor-triggered and self-created fast-exit denial.
- `btc-policy-cyberkrill-independent-claims-zgl` (P2) — the 5ag review withdrew cyberkrill as
  an independent address encoder and moved `00i` to A's flake-pinned Core oracle, but the rollout
  pre-funding checklist and `wdu` still use cyberkrill for whole-descriptor/timelock read-back.
  Audit independent implementation versus merely separate binary/caller before changing either
  live check; do not delete the pre-funding verification. A is now a direct prerequisite of `00i`,
  and this audit directly blocks `wdu`, so neither corrected verification can be scheduled ahead of
  its evidence.
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
