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
| **A. Software upgrade** | New `vault-node` / `vault-cli` binaries | **New vault** — see §2. There is no in-place binary upgrade in v0. |
| **B. Sealed-parameter change** | Anything in the manifest preimage — coordinator auth key, `max_msg_bytes`, the Hot budget triple, hot allowlist, escape descriptor, `max_derivation_index`, `escape_feerate_floor`, `escape_coverage_pct`, `escape_bump_max_fee_pct`, node set, endpoints, channel keys | **New vault.** Re-run the ceremony and move the coins. |
| **C. Key rotation** | Any federation key, the user key, the escape keys, the recovery keys, or the coordinator auth key | **New vault** (the descriptor or the manifest changes). No in-place rotation exists in v0. |

If you are unsure whether a value is sealed, the test is mechanical: does it feed
`base_manifest_bytes`? If yes, it is category B.

## 2. Category A — software upgrade: there is no in-place path in v0

**This section previously prescribed a rolling restart. That was wrong, and the correction
matters more than the convenience it removes.**

ADR-0005 seals the host after setup: SSH is uninstalled, no administrative access path remains,
and the ADR states outright that there is "no reset, no reconfiguration, no upgrade-in-place —
any change to the federation means rotating to a new vault." A rolling restart requires exactly
the administrative access the seal destroys, so the procedure was not merely risky: on a
correctly sealed node it is not performable at all.

The sealing is not incidental. It is what makes duress Lockdown irreversible by *anyone*,
including the legitimate owner — which is precisely why coercion has no reset to demand and no
operator to threaten. A documented upgrade path that reaches into a sealed node would, if it
existed, be the reset a wrench attacker asks for.

**So in v0, a binary change is a category B migration**: run a new ceremony, verify the new
vault, move the coins through the old vault's normal spend path, and decommission the old
federation. Follow §3.

That is a real operational cost, and it is stated rather than softened: patching a
vulnerability in `vault-node` means migrating a vault. A deployment that cannot tolerate that
should not treat v0 as production-ready — which is the same conclusion `docs/THREAT-MODEL.md`
reaches from the other direction.

**If a future version wants in-place upgrades**, it needs an ADR that supersedes ADR-0005 and
answers the question the seal exists to answer: what administrative capability survives on the
host, and why can a coercer not use it? Until that ADR exists, treat any procedure that
restarts a sealed node as unsupported.

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
| A node will not boot | Do not edit its config to make the manifest match. A manifest mismatch means the config disagrees with what the federation sealed; editing it to fit produces a node that boots while enforcing something other than the agreed policy. Since v0 has no in-place upgrade (§2), a node that stops booting is a node to replace by migration, not to patch in place. |
| Coins must move now and the normal path is bricked | The recovery branch: 2-of-3 recovery keys after the 180-day relative timelock. `demo recovery-drill` exercises exactly this. |

## 6. What this policy does not yet cover

- **No reproducible release.** There is no way today for an operator to verify that a binary
  corresponds to a given commit. Until there is, "upgrade the binary" rests on trusting the
  build host. Tracked in `docs/SBOM-AND-DEPENDENCY-POLICY.md`.
- **No signed releases**, for the same reason.
- **No in-place upgrade at all** (§2), which means every security patch to `vault-node` costs a
  full vault migration. That is the single largest operational objection to running v0 with real
  savings, and it is a consequence of ADR-0005's seal rather than an oversight — but it needs an
  answer before production, not a footnote.
- **No migration tooling.** Category B and C migrations are hand-run ceremonies plus an ordinary
  spend. For a vault holding meaningful savings, that is a real operational burden and it should
  be measured before it is relied on.
