# DRIVE — M4-SA → M4-SB → M4-C

**Scope:** M4-SA → M4-SB → M4-C; M4-S and
`btc-policy-mby-spend-command-6mp` are tracking-only parents. Combined ceiling:
1497 gross production Rust lines: the allocated combined hard total within the
historical outer 1500-line ceiling. The remaining 3 lines are non-spendable
reserve, not child contingency or scope. Documentation hard total is 320 gross
lines.

**Baseline:** ~155 lines — Stage A Rust 155/178/197/207, docs 0/0/0/0, and a
465 raw-added-line Drive brake. Ledger totals are gross additions plus deletions
(a move deletes plus adds); every Rust/docs table caps gross, independently of
the Drive brake.

**Phase:** BUILD · **Bead:** btc-policy-m4-sa-ingress-cookie-2xi · **Branch:** beads/m4-sa-ingress-cookie

**Pending:** run only M4-SA through its one rb-lite run of at most four rounds.
Its one work PR carries the already-reviewed qhe closure plus GRAPH metadata and
A implementation; A itself remains open until the later B work PR.

**Do-NOT-build:** Normal Spend grammar/route/watch/reporting; scalar/signer/node/
proto work; async/concurrency/TLS/configurable deadlines; new wire variants; cap
increases; or WIP ancestry.

**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`

## Now

M4-SA only: ingress 100, http 55, sealed 38, core_view 14; 207 gross Rust hard;
docs 0; Drive 465 raw-added-line brake. Preserve
`beads/m4-s-spend-substrate` at `c330518` read-only and outside ancestry.

## Next

After A squash-merges, create the fresh B branch from merged A. The B work PR
closes/syncs A. Replace this file in full with the exact B-BUILD record durably
embedded in the generated B bead description; do not retain A's Pending, Now,
Next, cap, ownership, or branch text.

## Budget and review

Combined child hard totals are exactly 1497 gross Rust and 320 gross
documentation; the historical outer 1500 Rust ceiling leaves a non-spendable
3-line reserve.
A fourth round is allowed; a round-four panel that is not READY/clean or needs
another fix returns to GRAPH. There is no fifth round or cap increase.
