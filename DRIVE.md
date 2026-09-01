# DRIVE — M4-SA → M4-SB → M4-C

**Scope:** M4-SB → M4-C; merged M4-SA is a prerequisite, while M4-S and
`btc-policy-mby-spend-command-6mp` are tracking-only parents. Combined ceiling:
1497 gross production Rust lines: the allocated combined hard total within the
historical outer 1500-line ceiling. The remaining 3 lines are non-spendable
reserve, not child contingency or scope. Documentation hard total is 320 gross
lines.

**Baseline:** ~150 lines — Stage B Rust 150/164/181/200, docs 7/7/9/11, and a
450 raw-added-line Drive brake. Ledger totals are gross additions plus deletions
(a move deletes plus adds); every Rust/docs table caps gross, independently of
the Drive brake.

**Phase:** BUILD · **Bead:** btc-policy-m4-sb-erasure-policy-version-2g5 · **Branch:** beads/m4-sb-erasure-policy-version

**Pending:** run only M4-SB through its one rb-lite run of at most four rounds.
This work PR closes/syncs merged M4-SA and carries B implementation; B itself
remains open until the later M4-C work PR.

**Do-NOT-build:** Any normal Spend grammar/route/watch/reporting, parser,
terminal-input work, endpoint refusal reporter, signer display/txid/substitution
consumer, new wire variant, or change to A's transport semantics.

**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`

## Now

M4-SB only: sealed 68, signer 32, channel 12, server 8, node-lib 70, proto 10;
200 gross Rust hard; DESIGN 6 and ADR-0013 5 for 11 gross docs hard; Drive 450
raw-added-line brake.

## Next

After B squash-merges, create the fresh C branch from merged B. The C work PR
closes/syncs B and the tracking-only M4-S parent. Replace this file in full with
the exact C-BUILD record durably embedded in the generated C bead description; do
not retain B's Pending, Now, Next, cap, ownership, or branch text.

## Budget and review

Combined child hard totals are exactly 1497 gross Rust and 320 gross
documentation; the historical outer 1500 Rust ceiling leaves a non-spendable
3-line reserve.
A fourth round is allowed; a round-four panel that is not READY/clean or needs
another fix returns to GRAPH. There is no fifth round or cap increase.
