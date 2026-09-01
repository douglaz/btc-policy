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

**Phase:** PROVE · **Bead:** btc-policy-m4-sa-ingress-cookie-2xi · **Branch:** beads/m4-sa-ingress-cookie

**Pending:** regenerate A's complete governed evidence from scratch on the clean
post-GRAPH committed head. Bind that head and mechanically prove all six frozen A
implementation/test/manifest paths remain byte-identical to
`bbe9c25f5bf340b2bf906ee6ee181dc832f834e2`. Do not claim a clean A panel, start a
fifth A round, inherit a prior exit, or change scheduling semantics.

**Do-NOT-build:** Any persistent/final A production, test, manifest, documentation, or
Beads edit during PROVE; a minimum-slice/fairness mechanism; normal Spend
grammar/route/watch/reporting; scalar/signer/node/proto work; async/concurrency/TLS; a
new wire variant; cap increases; or WIP ancestry.

**Gate:** `nix flake metadata --no-update-lock-file >/dev/null && nix develop -c bash -c 'cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked --workspace'`

## Now

GRAPH transfer commit `fae350cd95dd96ba6a85f58ed198c78a37111650` installed the
owner-approved B/C obligations and was independently audited clean. Keep A
`in_progress`, B/C open, and the A→B→C graph unchanged. Preserve A's rb-lite run as
historical provenance. Delete and regenerate every partial/mixed-head evidence roll-up;
no historical ledger, gate, mutation, LIVE, launch, manifest, identity, verdict, or
`DONE` is reusable.

## Next

Run the current 99-row A union red and restored green, exact Gate, both ignored LIVE
legs, all three demos, `attack all`, ledger/re-anchor/manifest/final
identity/verdict, and `DONE`. Governed mutations alone may transiently edit row targets
under the common exclusive lock, with before/after hashes, exact restoration, and zero
final diff; they do not thaw A. After independently verifying the completed evidence,
land the A work PR with the round-four exit and owner exception disclosed. A remains
open until the later B work PR closes/syncs it. B must regenerate the full
inherited+A+B evidence union after adding the transferred rows; C owns the R12
correction with first product reachability.

## Budget and review

No production or documentation cap changes. The owner explicitly approved transferring
custody-adjacent assurance timing from A to the already-required B/C work rather than a
disguised fifth A round or a fresh implementation recut. PR review and CI remain
mandatory; no historical or partial evidence exit is inherited.
