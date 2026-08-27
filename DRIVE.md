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

**Phase:** GRAPH · **Bead:** btc-policy-m4-sa-ingress-cookie-2xi · **Branch:** beads/m4-sa-ingress-cookie

**Pending:** GRAPH audit/install, qhe closure replay, and A claim. Only after a
successful A claim, rewrite this entire file (not one field) with these same
canonical fields and **Phase:** BUILD for A. After C merge, the final metadata
PR records `**Phase:** DONE (qualified)` plus `**Pending:** metadata PR
owner/repo#N`. Those same committed bytes derive `WAITING_FOR_MERGE` while the PR
is open and `DONE` automatically once it merges; no second transition is needed.

**Do-NOT-build:** Normal Spend grammar/route/watch/reporting in A/B;
async/concurrency/TLS/configurable deadlines; new wire variants; cap increases;
or WIP ancestry. C changes `ingress.rs` only for first-reporter typed-refusal
facts and `signer.rs` only for describe/ordered-txid/test-only substitution; A/B
semantics stay frozen.

**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`

## Now

Stage A / GRAPH: ingress 100, http 55, sealed 38, core_view 14; 207 gross Rust
hard; docs 0; Drive 465 raw-added-line brake. Preserve
`beads/m4-s-spend-substrate` at `c330518` read-only: it is never selected or
ancestry.

## Next

Audit/install, replay qhe on this clean A branch, claim A, and replace this
whole file with the exact A-BUILD record durably embedded in the generated A bead
description. After A and B merge, use the exact B-BUILD and C-BUILD records
durably embedded in the generated B and C bead descriptions respectively. Do not
retain or invent a field from an earlier stage. After C, the final metadata PR
closes/syncs C and the top parent.

## Budget table

| child | Rust baseline | forecast | pre-review | hard | Drive cap |
|---|---:|---:|---:|---:|---:|
| A | 155 | 178 | 197 | 207 | 465 |
| B | 150 | 164 | 181 | 200 | 450 |
| C | 886 | 967 | 1031 | 1090 | 2658 |
| **combined** | **1191** | **1309** | **1409** | **1497** | independent |

| documentation | baseline | forecast | pre-review | hard |
|---|---:|---:|---:|---:|
| A | 0 | 0 | 0 | 0 |
| B | 7 | 7 | 9 | 11 |
| C | 225 | 255 | 270 | 309 |
| **combined** | **232** | **262** | **279** | **320** |

`207 + 200 + 1090 = 1497`; this is the allocated child hard total, while the
historical outer 1500 leaves a non-spendable 3-line reserve. `11 + 309 = 320`.
A=3×155=465, B=3×150=450, C=3×886=2658. A per-file/category cap or Drive cap
is STOP.

## Review and history

A fourth round is allowed. A round-four panel that is not READY/clean or needs
another fix returns to GRAPH; there is no fifth round or enlarged cap.
Supersede/delete all stale monolithic M4-S Drive text and caps. Retain only the
return-to-GRAPH decision, immutable WIP/provenance at `c330518`, and, after C
merge only, the qualified final-metadata waiting record above.
