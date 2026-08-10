# SBOM and dependency policy

Part of the core-proven gate's artifact set (bead `btc-policy-9y5.8` deliverable 2).
Two things live here: **what this vault is actually built out of**, and **the rule that
decides what may be added**. An external reviewer should be able to read the second and
audit the first against it.

Regenerate the inventory with:

```bash
set -eo pipefail                                      # BOTH flags — see below
nix flake metadata --no-update-lock-file >/dev/null   # REQUIRED, and FIRST — see below
nix develop -c cargo tree --locked --workspace --prefix none --no-dedupe \
  | sed 's/ (.*//;s/^ *//' | sort -u
```

Three lines, three different ways this recipe can silently document a dependency graph the repo
does not commit — which is the one thing this file exists to prevent. Each was found separately,
by review, after the previous fix looked sufficient.

`set -e` and `set -o pipefail` are BOTH needed and neither implies the other. `pipefail` makes a
pipeline report its RIGHTMOST failing stage instead of `sort`'s success — the last command to exit
non-zero, not the first, which is what `bash(1)` specifies and what
`bash -c 'set -o pipefail; (exit 3) | (exit 4) | true; echo $?'` prints (4, not 3). Here that
distinction does not change the outcome, since `cargo tree` is the only stage that can fail — but a
reader who adds a stage should know which failure the recipe would report. Without `pipefail` a
failing `cargo tree` yields exit 0 because `sort` succeeds on empty input. `-e` makes the recipe STOP at
the assertion below — without it, `pipefail` alone lets a failed stale-flake check fall through to
the next line, which enters the dev shell, refreshes the lock, and finishes with a green
pipeline.

`nix flake metadata --no-update-lock-file` must come FIRST, before anything enters the dev
shell. `nix develop` will refresh a `flake.lock` that has drifted from `flake.nix` and then
run happily inside the refreshed environment; `cargo tree --locked` would succeed against an
uncommitted TOOLCHAIN, so the Rust lock being pinned proves nothing about which compiler and
which `nixpkgs` produced the inventory. `--no-write-lock-file` is not a substitute: it warns
and passes.

Both halves of that first line are load-bearing, and each defeats the other's absence.
`--locked` makes `cargo tree` FAIL when `Cargo.lock` has drifted from `Cargo.toml` instead of
silently regenerating it — without it, the inventory can describe a dependency graph the repo
does not commit, which is the one thing this document exists to prevent. But a pipeline's exit
status is its LAST command's, and `sort` succeeds on empty input, so without `pipefail` the
`--locked` failure is swallowed and the recipe reports success while emitting a truncated or
empty inventory. Check the exit status, not the output's plausibility.

## The policy

**Every dependency must beat writing it ourselves.** That is the standing rule, and for a
custody vault it is not stylistic: each crate is code that runs in the same address space as
the signing key, and each one is a supply-chain entry point. The bar rises with blast radius:

| Layer | Bar for adding a dependency |
|---|---|
| `policy-core` (the pure refusal core) | Essentially closed. It has exactly two deps (`bitcoin`, `miniscript`) and stays pure — no I/O, no chain, no clock, no crypto beyond what the descriptor needs. |
| `vault-proto` (wire types) | Serialization and zeroization only. Anything that could change *what a byte means* belongs upstream in the schema, not in a crate. |
| `vault-node` (the signer daemon) | Justified case-by-case, and only for things that are genuinely hard to get right: consensus encoding, Argon2, constant-time comparison, async I/O. |
| `vault-cli` (coordinator/harness) | Same bar. The coordinator is trusted during normal operation and may turn hostile at the wrench (ADR-0012); it also handles the trusted ceremony. |

Concrete rules:

1. **No new dependency for convenience.** If the alternative is ~100 lines we can read, write
   the 100 lines.
2. **Prefer the user's own audited crates** where they fit (`wskdf-core` is pinned to an exact
   git revision for exactly this reason).
3. **Pin what matters.** Consensus- and crypto-critical crates are version-pinned in
   `[workspace.dependencies]`; the one git dependency is pinned to a full commit hash, never a
   branch.
4. **Default features off** where the crate is large and we need a slice of it (`axum`,
   `reqwest`, `wskdf-core`, `proptest` all disable default features).
5. **No dependency may be added to `policy-core`** without an ADR saying why the refusal core
   cannot stay pure.
6. **A dependency that reaches the network, the filesystem, or the clock is a design decision**,
   not a packaging one — it changes the threat model and needs to be argued as such.

## What the vault is built out of

Direct dependencies, by crate — this is the surface that matters, because everything else is
reachable only through one of these.

### `policy-core` — the pure refusal core
| Crate | Why |
|---|---|
| `bitcoin` | Consensus types and encoding. Non-negotiable; writing our own consensus encoder is precisely the mistake this rule exists to prevent. |
| `miniscript` | Descriptor parsing and the vault template. The policy IS a descriptor, so this is the policy's own grammar. |

No serde, no I/O, no async, no crypto. `policy-core` cannot read a clock or a chain, which is
what lets its refusals be deterministic across the honest set.

### `vault-proto` — wire types
`serde` (encoding), `bitcoin` (consensus types), `zeroize` (PIN-carrying request bodies wipe on
drop).

### `vault-node` — the signing daemon
| Crate | Why | Notes |
|---|---|---|
| `bitcoin`, `miniscript` | consensus + descriptors | as above |
| `serde`, `serde_json`, `toml` | config and JSON-RPC | config is operator-authored; parsing is a trust boundary |
| `tokio` | async runtime | needed for the deadline driver and the peer channel |
| `axum` | HTTP server (`/sign`, `/channel`, `/healthz`, `/events`, `/pending`) | `default-features = false` |
| `reqwest` | HTTP client for bitcoind JSON-RPC and peer sends | `default-features = false`; proxies explicitly disabled and redirects refused at the call site (a redirect could otherwise exfiltrate a partial) |
| `argon2` | PIN hashing | with `zeroize` |
| `subtle` | constant-time comparison | the duress-PIN compare must not leak through timing |
| `zeroize` | secret wiping | keys, preimages, PINs |
| `wskdf-core` | node signing-key derivation from the operator preimage | pinned to commit `7a840406704b1b070995eb7a301ba1f500790728` |
| `bytes`, `libc` | buffers; `termios` echo suppression for preimage entry | |
| `policy-core`, `vault-proto` | in-workspace | |

### `vault-cli` — coordinator, ceremony, harness
`base64`, `bitcoin`, `miniscript`, `serde`, `serde_json`, `zeroize`, plus the three workspace
crates. Notably it depends on `vault-node` so the ceremony computes manifest bytes with the
node's OWN code rather than a second implementation that could drift.

### Test-only
`proptest` (`default-features = false`) for the V0-7 property suites. Test-only dependencies
never reach a released binary.

## Transitive footprint

**146 transitive crates** across the workspace (see the regeneration command above for the full
list). The consensus- and crypto-critical subset — the crates whose failure would be a
correctness or key-safety problem rather than an availability one:

| Crate | Version |
|---|---|
| `bitcoin` | 0.32.101 |
| `bitcoin_hashes` | 0.14.101 |
| `bitcoin-units` | 0.1.101 |
| `bitcoin-io` | 0.1.101 |
| `secp256k1` | 0.29.1 |
| `secp256k1-sys` | 0.10.1 |
| `miniscript` | 12.3.7 |
| `argon2` | 0.5.3 |
| `password-hash` | 0.5.0 |
| `blake2` | 0.10.6 |
| `blake2b_simd` | 1.0.4 |
| `subtle` | 2.6.1 |
| `wskdf-core` | 0.1.0 (git, pinned) |

`rand` appears in several major versions (0.9/0.10 plus `rand_core` 0.6/0.9/0.10) through
transitive paths. **The vault does not draw its own secrets from `rand`** — key material comes
from `/dev/urandom` directly, and the node's signing key is derived from the operator preimage
via `wskdf-core`. Checked while writing this: `rand` is not a direct dependency of any crate in
the workspace, and `crates/` contains no `rand::` / `thread_rng` / `OsRng` use in production
code. A reviewer should re-run that search rather than take it from here.

## What a reviewer should check

1. That `policy-core`'s dependency list is still exactly two crates, and that it still compiles
   without any I/O, clock, or chain access.
2. That the `wskdf-core` pin is a full commit hash and that the commit is the one intended.
3. That `reqwest`'s no-proxy / no-redirect posture is enforced at every call site that can carry
   a partial signature, not just the one documented here.
4. That no crate in the crypto-critical table above has drifted to an unpinned range.
5. That test-only dependencies (`proptest`) do not appear in a release binary's dependency
   graph.

## Known gaps

- **No automated vulnerability scan is wired into CI** (`cargo audit` / `cargo deny`). That is
  a real gap in this policy, not an oversight in this document: the policy currently relies on
  a small, deliberately-chosen dependency set and human review, and it should not.
- **No reproducible-release artifact yet.** Deliverable (2) of `btc-policy-9y5.8` calls for one;
  the binary hashes recorded in `docs/SIGNET-SPEND-RECORD.md` are debug builds from one machine
  and are evidence about that run only, not a reproducibility claim.
