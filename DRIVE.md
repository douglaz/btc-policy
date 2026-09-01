# DRIVE — M4-SA assurance transfer → M4-SB → M4-C

**Scope:** frozen M4-SA → M4-SB → M4-C; M4-S and
`btc-policy-mby-spend-command-6mp` are tracking-only parents. Combined ceiling remains
1497 gross production Rust lines within the historical outer 1500-line ceiling; the
3-line reserve is non-spendable. Documentation hard total remains 320 gross lines.

**Baseline:** ~0 production lines for this GRAPH adjudication. A's production-path
content/reference is frozen at `bbe9c25f5bf340b2bf906ee6ee181dc832f834e2`, where it
measured 176/207 gross production Rust, 0/0 docs, and 364/465 independent raw-added
Drive lines. The later governance-only commit changes `HEAD` but not those frozen
implementation bytes. Tests, test-only helpers, mutation
definitions, and evidence remain mandatory and uncapped.

**Phase:** GRAPH · **Bead:** btc-policy-m4-sa-ingress-cookie-2xi · **Branch:** beads/m4-sa-ingress-cookie

**Pending:** record the owner-approved one-time assurance transfer after A's sole
rb-lite run stopped at round four with exit 12. Freeze A production; transfer four
round-four test/evidence corrections to B and the R12 correction to C. Do not claim a
clean A panel, start a fifth A round, or change scheduling semantics.

**Do-NOT-build:** Any persistent/final A production, test, or manifest edit during
GRAPH; a minimum-slice/fairness mechanism; normal Spend grammar/route/watch/reporting; scalar/signer/node/proto work;
async/concurrency/TLS; a new wire variant; cap increases; or WIP ancestry.

**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`

## Now

The only tracked updates are resolved beads JSONL and this Drive record. Keep A
`in_progress`, B/C open, and the A→B→C graph unchanged. Preserve A's rb-lite run as
historical provenance. Remove the untracked Python bytecode cache as cleanup before
identity measurement, and treat every partial/mixed-head A evidence artifact as invalid.

## Next

After an independent exact graph/spec audit, commit only the governance changes, then
move directly to A's governed final evidence on that new clean committed `HEAD`. Before
the run, mechanically prove every A implementation/test/manifest path is byte-identical
to the frozen `bbe9c25f5bf340b2bf906ee6ee181dc832f834e2` snapshot; the evidence binds
and reports both the frozen production reference and the actual governance-only `HEAD`.
Then regenerate the current 99-row A union red and
restored green, exact Gate, both ignored LIVE legs, all three demos, `attack all`,
ledger/re-anchor/manifest/final identity/verdict, and `DONE` from scratch. Governed
mutations alone may transiently edit row targets under the common exclusive lock, with
before/after hashes, exact restoration, and zero final diff; they do not thaw A. Then land the
A work PR with the round-four exit and owner exception disclosed. A remains open until
the later B work PR closes/syncs it. B must regenerate the full inherited+A+B evidence
union after adding the transferred rows; C owns the R12 correction with first product
reachability.

## Budget and review

No production or documentation cap changes. The owner explicitly approved transferring
custody-adjacent assurance timing from A to the already-required B/C work rather than a
disguised fifth A round or a fresh implementation recut. PR review and CI remain
mandatory; no historical or partial evidence exit is inherited.
