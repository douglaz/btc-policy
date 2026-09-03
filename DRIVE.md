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

**Lifecycle:** `btc-policy-5jt` is the P1 replacement and remains claimed `in_progress`
on `master` until the M4-C work branch records its closure.  The first replacement
rb-lite run stopped with exit 14 after one panel round: its round-two fix head
`18087c4` measured 452 raw-added lines against the 450 brake.  It had no round-two
panel or accepted final evidence.  Its stopped directory nevertheless contains
implementer-authored manifest, 109-row, identity, verdict, and `DONE` files that purport
to say READY; the budget stop rejects those artifacts.  Freeze the directory as stop
provenance, and inherit no result from it.

**Pending:** the owner authorizes exactly one additional fresh same-bead rb-lite run from
claim base `674370c`, at most four rounds, under
`.rb-lite/runs/m4-sb-replacement-final/`.  It begins as a new run and must create fresh
evidence; there is no retry or further run.  A stop after this authorization returns to
GRAPH and has no assumed owner permission.

**Do-NOT-build:** normal Spend grammar/route/watch/reporting, parser, terminal-input
work, endpoint refusal reporter, signer display/txid/substitution consumer, new wire
variant, or a change to M4-SA transport semantics.

**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`

## Standing decisions

Tests, test-only helpers, fixtures, mutations, and evidence remain mandatory but are
excluded from production ledgers.  When a path-only counter alone charges them, a coherent
test-module relocation under reviewed GRAPH is allowed without thinning tests or changing a
cap.  For `btc-policy-5jt`, the owner authorizes exactly the sealed test-module relocation
below and one additional fresh same-bead run.  No result is inherited, and any further stop
requires GRAPH with no assumed permission.

## Now

M4-SBR only: sealed 68, signer 32, channel 12, server 8, node-lib 70, proto 10; 200
gross production Rust hard; DESIGN 6 and ADR-0013 5 for 11 gross docs hard; independent
Drive 450 raw-added-line brake.  Production caps remain 200 Rust and 11 docs; the raw
cap remains 450 with no new whole-product exclusion, offset, retirement, or increase.

Move the entire existing `#[cfg(test)] mod tests { ... }` body from
`crates/vault-cli/src/sealed.rs` to `crates/vault-cli/tests/unit/sealed.rs`.  In the
source retain exactly this three-line declaration:

    #[cfg(test)]
    #[path = "../tests/unit/sealed.rs"]
    mod tests;

Preserve lexical module `sealed::tests`, private/`super` access, filters, and all test
behavior.  Update exactly the two physical-path-dependent includes:
`include_str!("sealed.rs")` becomes `include_str!("../../src/sealed.rs")`, and
`include_str!("../tests/fixtures/pre-m1-manifest.json")` becomes
`include_str!("../fixtures/pre-m1-manifest.json")`.  Do not delete, thin, duplicate,
rewrite, or split tests, and do not place normal-build code under `cfg(test)`.

Tests, test-only helpers, fixtures, mutations, and evidence are mandatory but excluded
from production ledgers.  When a path-only counter alone charges them, coherent
test-module relocation under reviewed GRAPH is allowed without thinning tests or changing
any cap.  This owner approval permits only the sealed test-module relocation and exactly
this one final same-bead rerun.  The prior two policy-version moves remain required.

## Next

After SBR squash-merges, create the fresh C branch from merged SBR.  The C work PR
closes/syncs SBR and the tracking-only M4-S parent.  Replace this file in full with the
exact C-BUILD record durably embedded in the generated C bead description; do not retain
SBR Pending, Now, Next, cap, ownership, branch, or predecessor text.

## Budget and review

Combined child hard totals are exactly 1497 gross Rust and 320 gross documentation; the
historical outer 1500 Rust ceiling leaves a non-spendable 3-line reserve.  A fourth-round
panel that is not READY/clean or needs another fix returns to GRAPH.  There is no fifth
round, second child, raw-brake retirement, cap increase, predecessor-evidence carryover,
or further same-bead run.  The final run must independently produce its required final
109-row union, identity, and `DONE`; none may be claimed before successful final exits.
