# Upgrade and rotation policy

Part of the core-proven gate's artifact set (bead `btc-policy-9y5.8` deliverable 2).

The short version, and the thing that surprises people: **this vault has almost no in-place
reconfiguration.** Nodes are sealed after setup (ADR-0005) and the manifest is immutable, so
changing a sealed parameter does not reconfigure the vault — it *creates a different vault* and
requires moving the coins. That is a deliberate trade: it buys the property that every honest
node provably agrees on the same policy, which is what the determinism and silence invariants
rest on.

## 1. The three categories

Every change falls into exactly one of these. Knowing which one you are in is the whole policy.

| Category | What it covers | Cost |
|---|---|---|
| **A. Software upgrade** | New `vault-node` / `vault-cli` binaries, same manifest, same keys, same policy values | Rolling restart, node by node |
| **B. Sealed-parameter change** | Anything in the manifest preimage — coordinator auth key, `max_msg_bytes`, the Hot budget triple, hot allowlist, escape descriptor, `max_derivation_index`, `escape_feerate_floor`, `escape_coverage_pct`, node set, endpoints, channel keys | **New vault.** Re-run the ceremony and move the coins. |
| **C. Key rotation** | Any federation key, the user key, the escape keys, the recovery keys, or the coordinator auth key | **New vault** (the descriptor or the manifest changes). No in-place rotation exists in v0. |

If you are unsure whether a value is sealed, the test is mechanical: does it feed
`base_manifest_bytes`? If yes, it is category B.

## 2. Category A — software upgrade

Safe to do in place, because the manifest binds *policy*, not the binary.

**Preconditions**

- The new build passes the full gate: `cargo fmt`, `cargo clippy -D warnings`,
  `cargo test --workspace`, `attack all` 16/16, and all three demos exit 0.
- The protocol version is unchanged. A `PROTOCOL_VERSION_V0` bump is **not** category A — it
  changes the manifest preimage, so it is category B.
- You have read the release's own notes for any config-schema change. A new *optional* config
  field with a default that is not manifest-bound is category A; a new manifest-bound field is
  category B.

**Procedure**

1. Upgrade **one node at a time**, and verify it before touching the next. The federation is
   3-of-5, so it tolerates two nodes being down — but never take down more than one
   deliberately, because that leaves no margin for an unplanned failure.
2. For each node: stop the daemon, replace the binary, restart it, and re-supply the operator
   preimage on stdin (the signing key is derived at start, never stored).
3. Confirm the node came back before proceeding: `GET /healthz` reports `serving`, and the node
   did **not** log a manifest mismatch. A manifest-hash failure at startup means you are
   actually in category B — stop and reassess rather than "fixing" the config.
4. Watch for the reboot-death warning. If the node reports its config/key inode is on a
   non-volatile filesystem, ADR-0007's premise does not hold on that host (see
   `docs/THREAT-MODEL.md` R3).

**Do not** upgrade during an armed escape's window, a pending Hold you care about, or an
in-flight spend. Wait for the vault to be quiet.

## 3. Category B — sealed-parameter change

There is no in-place path. The manifest hash is checked at every node's startup against the
sealed anchor, so a node whose config disagrees **refuses to boot** — by design (that refusal is
the mechanism that makes the value provably federation-uniform).

**Procedure: run a new ceremony and migrate.**

1. Run the full setup ceremony for the new vault (`docs/SETUP-CEREMONY.md`). Fresh node
   identities, fresh coordinator auth key, fresh manifest.
2. Verify the new vault before moving anything: fund it with a small amount and complete one
   honest spend end to end.
3. Move the coins from the old vault to the new vault's address as an ordinary spend through
   the **old** vault's normal path — allowlist and Hot budget still apply, so the new vault's
   address must be allowlisted in the old one, or the move must be split under the caps.
4. Only then decommission the old federation.

Two things to note honestly: the migration spend is a normal spend, so it is subject to the old
vault's Hold and its Hot budget; and it is a moment when both vaults exist, which is a window
worth minimizing.

## 4. Category C — key rotation

| Key | Rotation story |
|---|---|
| **Federation signing key** | New vault. The key is in the descriptor. |
| **User key** | New vault. Also in the descriptor. |
| **Escape keys** | New vault. The escape descriptor is manifest-bound *and* the independence check (ADR-0003) must be re-run — a rotation that accidentally shares a seed with a vault key turns the claw-back into theft. |
| **Recovery keys** | New vault. In the descriptor's second branch. |
| **Coordinator auth key** | New vault (ADR-0013 §7). The manifest pins the pubkey and the manifest is immutable. |
| **PINs** | New vault. Both digests are in each node's sealed config. |
| **Operator preimage** | Per-host, and *not* manifest-bound — but rotating it changes the derived signing key, which **is** in the descriptor. So: new vault. |

**The coordinator auth key deserves its own warning.** Losing it with no backup **bricks the
normal path**: the manifest pins its pubkey, so no request can ever be authenticated again, and
the only exit is the 180-day recovery timelock. Back it up at ceremony time, separately from the
descriptor backup, and treat that backup as a first-class secret.

## 5. Emergency changes

| Situation | Action |
|---|---|
| A node's host is compromised | The federation is 3-of-5: one compromised node cannot sign alone. Take the host down. Rotating its key is category C, so plan a migration rather than a hot swap. Consider whether ADR-0009's correlation-class assumption still holds for the remainder. |
| The user believes a PIN is known to an attacker | PINs cannot be rotated in place. If the attacker has the user key too, this is the wrench scenario the duress PIN exists for — use it, then migrate. |
| A node will not boot after an upgrade | Do not edit its config to make the manifest match. A manifest mismatch means the config disagrees with what the federation sealed; editing it to fit produces a node that boots while enforcing something other than the agreed policy. Roll the binary back instead. |
| Coins must move now and the normal path is bricked | The recovery branch: 2-of-3 recovery keys after the 180-day relative timelock. `demo recovery-drill` exercises exactly this. |

## 6. What this policy does not yet cover

- **No reproducible release.** There is no way today for an operator to verify that a binary
  corresponds to a given commit. Until there is, "upgrade the binary" rests on trusting the
  build host. Tracked in `docs/SBOM-AND-DEPENDENCY-POLICY.md`.
- **No signed releases**, for the same reason.
- **No automated upgrade tooling.** The rolling restart above is a manual procedure, and it is
  written as one deliberately — but that means it is only as reliable as the operator following
  it.
- **No migration tooling.** Category B and C migrations are hand-run ceremonies plus an ordinary
  spend. For a vault holding meaningful savings, that is a real operational burden and it should
  be measured before it is relied on.
