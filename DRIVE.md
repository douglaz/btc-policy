# DRIVE — M4-SA → M4-SBR → M4-C

**Scope:** M4-SBR → M4-C; merged M4-SA is a prerequisite, while M4-S and
`btc-policy-mby-spend-command-6mp` are tracking-only parents.  Combined ceiling: 1497
gross production Rust lines within the historical outer 1500-line ceiling.  The
remaining 3 lines are non-spendable reserve, not child contingency or scope.
Documentation hard total is 320 gross lines.

**Baseline:** ~150 lines — Stage SBR Rust 150/164/181/200, docs 7/7/9/11, and an
independent 450 raw-added-line Drive brake.  Ledger totals are gross additions plus
deletions (a move deletes plus adds); every Rust/docs table caps gross independently of
the Drive brake.

**Phase:** BUILD · **Bead:** `btc-policy-5jt` · **Branch:** `beads/m4-sb-replacement`

**Lifecycle:** `btc-policy-5jt` is the P1 replacement and is claimed `in_progress` after the GRAPH transition; it remains claimed until the M4-C work branch records its closure.

**Pending:** run only M4-SBR through one fresh rb-lite run of at most four rounds.
The SBR work PR carries its implementation and the completed GRAPH transition; `btc-policy-5jt`
remains claimed `in_progress` until the later M4-C work branch records its closure.  The stopped predecessor supplies no READY,
review, or evidence claim.

**Do-NOT-build:** normal Spend grammar/route/watch/reporting, parser, terminal-input
work, endpoint refusal reporter, signer display/txid/substitution consumer, new wire
variant, or a change to M4-SA transport semantics.

**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`

## Now

M4-SBR only: sealed 68, signer 32, channel 12, server 8, node-lib 70, proto 10; 200
gross Rust hard; DESIGN 6 and ADR-0013 5 for 11 gross docs hard; independent Drive 450
raw-added-line brake.  Move exactly the two policy-version route test bodies to their
path-declared unit files, then freshly measure the raw counter; the planning arithmetic is `670-(149-3)-(105-3)=422`, not evidence.
Tests are mandatory and uncapped; the brake remains raw, independent, and 450.

## Next

After SBR squash-merges, create the fresh C branch from merged SBR.  The C work PR
closes/syncs SBR and the tracking-only M4-S parent.  Replace this file in full with the
exact C-BUILD record durably embedded in the generated C bead description; do not retain
SBR Pending, Now, Next, cap, ownership, branch, or predecessor text.

## Budget and review

Combined child hard totals are exactly 1497 gross Rust and 320 gross documentation; the
historical outer 1500 Rust ceiling leaves a non-spendable 3-line reserve.  A fourth round
is allowed; a round-four panel that is not READY/clean or needs another fix returns to
GRAPH.  There is no fifth round, second child, brake retirement, cap increase, or
predecessor-evidence carryover.
