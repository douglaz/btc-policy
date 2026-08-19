# The setup ceremony

The written procedure for provisioning a vault. It is the **trust bootstrap**:
everything else in this system is a state machine defending a vault whose shape
this ceremony decides, and a perfect state machine cannot compensate for a setup
machine that has seen every signer secret.

Two rules carry the whole thing:

1. **No machine ever holds two node secrets.** Each node births its own key on its
   own host; only public bytes travel to the coordinator.
2. **The escape wallet is generated independently, on its own device.** A
   shared-seed escape converts duress into THEFT — a post-wrench attacker holding
   the user key would control the escape wallet, and the sweep hands them the
   vault ([ADR-0012](adr/0012-model-b-spend-and-duress-architecture.md) §10).

Specs: [ADR-0013 §4/§5](adr/0013-concrete-protocol-schemas.md) (manifest, config),
[ADR-0003](adr/0003-key-independence-matrix.md) (key independence),
[ADR-0005](adr/0005-nodes-are-sealed-after-setup.md) (sealing),
[ADR-0007](adr/0007-node-death-on-reboot.md) (reboot-death).

## Who runs what

| Step | Machine | Command |
|---|---|---|
| 1 | each node host | `btc-vault setup node-keygen` |
| 2 | escape device (holds no other vault role) | `btc-vault setup keygen --role escape` |
| 2 | user / recovery devices | `btc-vault setup keygen --role user\|recovery` |
| 3 | coordinator | `btc-vault setup assemble` |
| 4 | each node host | `btc-vault setup node-endorse` |
| 5 | coordinator | `btc-vault setup finalize` |

**Why two rounds.** A node's channel-key endorsement is signed over
`manifest_hash`, and `manifest_hash` is not known until every node's public key is
in. The only way to collapse this into one round is to hand the coordinator the
node secrets — the thing this ceremony exists to avoid.

## 1. On each node host — birth the key

```
btc-vault setup node-keygen --device-dir /run/vault-setup --endpoint 127.0.0.1:8443
```

Prints a **preimage**. Write it down. It is the only copy, it never reaches the
coordinator or another node host, and nothing stores it. Publishes
`node-public.json`: the signing pubkey, the channel pubkey, the wskdf salt and
Argon2id cost, and the endpoints. That file is public — copy it to the
coordinator. The endpoint decides the port the node binds; v0 nodes bind loopback
only, so it must be `127.0.0.1:<port>` (ADR-0013 §4 — v1's onion addresses are to
be derived from node key material, and clearnet dynamic-IP topologies are
unsupported by design). `setup assemble` refuses anything else rather than letting
every node discover it at startup, after the vault is frozen.

> **Two separate meanings of "host."** Key GENERATION is per-device: each node's key
> is born on its own machine and no machine ever holds two node secrets — that is the
> security property this ceremony exists to guarantee, and it holds whether or not the
> daemons later share a box. The v0 RUNTIME, by contrast, is **co-located**: every
> node binds and is reached at `127.0.0.1:<port>`, and inter-node delivery posts to
> those loopback endpoints with proxies disabled, so the running federation lives on
> one host with distinct ports (a hardened appliance / single trusted operator box).
> A genuinely multi-host runtime needs authenticated routable transport (onion/mTLS),
> which is v1 — not this bead. Do not read "birth the key on each node host" as a
> promise that v0 runs the nodes on separate hosts; it does not.

Losing a preimage before the node starts kills that node. That is not a disaster
to design around: under reboot-death a node dies for far less, the federation
absorbs two deaths at 3-of-5, and restoring capacity means rotating to a successor
vault. It is why the preimage takes wskdf's widest form rather than the recoverable
width wskdf's own examples use — a 63-bit-wide value whose top bit wskdf pins, so
62 bits of entropy (a 2^62 search space), the most wskdf yields.

`--kdf-ops` / `--kdf-mem-kib` tune the Argon2id cost. The defaults (4 passes,
256 MiB) put one derivation around a second and are also the PRODUCTION FLOOR:
`node-keygen` refuses a lower cost unless you pass `--allow-weak-kdf` (which only a
test/automation host should). The preimage's 2^62 search space is the primary
barrier, but the ceremony publishes salt/ops/mem in the bundle, so an offline
guesser's cost is the _product_ of that space and per-guess cost — the cost is a
required floor, not a
free knob. The regtest harness derives at the floor with `--allow-weak-kdf` for speed.

## 2. On the independent devices — the other keys

```
btc-vault setup keygen --role escape   --out escape.json      # its OWN device
btc-vault setup keygen --role user     --out user.json
btc-vault setup keygen --role recovery --out recovery-a.json  # ×3, distributed
```

Each prints its secret once. **The escape device must hold no other vault role.**
In a hardware-wallet deployment, `--role escape` is replaced by exporting the
wallet from the device and hand-writing the bundle — the ceremony's structural
check is that an escape **bundle** is required, not a descriptor pasted in beside
the node bundles.

## 3. On the coordinator — assemble

Write a ceremony input (JSON) naming the bundle PATHS, the hot wallet descriptor,
the enrolled PIN digests, the chain backend, and the policy numbers:

```json
{
  "threshold": 3,
  "node_bundles": ["dev0/node-public.json", "dev1/node-public.json",
                   "dev2/node-public.json", "dev3/node-public.json",
                   "dev4/node-public.json"],
  "user_bundle": "user.json",
  "recovery_bundles": ["rec-a.json", "rec-b.json", "rec-c.json"],
  "escape_bundle": "escape.json",
  "hot_descriptor": "wpkh([<fp>]<xpub>/*)",
  "policy": {
    "max_derivation_index": 1000,
    "hold_secs": 86400,
    "duress_delay_secs": 43200,
    "epsilon_secs": 60,
    "combine_slack_secs": 3600,
    "delivery_horizon_secs": 60,
    "max_commitment_age_secs": 172800,
    "policy_version": 1,
    "escape_feerate_floor": 20,
    "escape_coverage_pct": 95,
    "escape_bump_max_fee_pct": 0,
    "hot_max_per_tx": 50000000,
    "hot_max_per_window": 100000000,
    "hot_window_secs": 172800,
    "max_msg_bytes": 1048576
  },
  "pin_normal_hash": "$argon2id$...",
  "pin_duress_hash": "$argon2id$...",
  "chain_backend_rpc_addr": "127.0.0.1:8332",
  "chain_backend_auth": "<base64 user:pass>"
}
```

`threshold` is `t`; the federation must be exactly `n = 2t − 1` with `t ≥ 2`
(ADR-0013 §1), and `assemble` refuses any other shape — the descriptor is
immutable, so the wrong one cannot be migrated, only replaced. Each node's listen
port comes from the endpoint it published; there is no second copy to disagree
with. Then:

```
btc-vault setup assemble --input ceremony.json --out ./vault
```

This is where the vault is decided. It:

* builds and validates the frozen descriptor against the fixed template — one
  concrete pubkey per role (ranged vault keys are rejected), all keys distinct,
  recovery branch `older(4224679)` + 2-of-3;
* **checks key independence and REFUSES to continue on any detectable overlap**
  between the escape wallet and the user key, any node key, any recovery key, or
  the hot wallet — including a scan of the escape wallet's derived keys over the
  same `max_derivation_index` the nodes enforce. The evidence goes to
  `independence.txt`;
* generates the coordinator auth key;
* **bounds and then refuses `escape_bump_max_fee_pct`** — the sealed escape fee-ladder
  ceiling (ADR-0016 §2). It is checked against the 10% ingress fee cap every rung
  passes, the fire-time coverage headroom `100 − escape_coverage_pct`, and ADR-0016's
  decided 5× margin under that headroom. **Only `0` is accepted in this release**:
  nothing yet composes the replacement rungs a nonzero ceiling promises, and ADR-0005
  seals the hosts, so a vault sealed at a nonzero value would be ladderless for life
  while its operator believed they had opted in;
* computes `wallet_id` and `manifest_hash`, and prints one endorsement request per
  node.

The printed banner states the two things the ceiling's number cannot: it governs
REPLACEMENT RUNGS ONLY and never caps the base Escape, whose own fee cannot exist at
seal time (it depends on inputs, output shape and a feerate source chosen later, so it
is displayed per spend); and it prints the recovery timelock beside it as a fixed 180
days, because ADR-0016 §4 requires the two to be reasoned about together and
`btc-policy-wdu`, not this release, is what makes the timelock selectable.

What the independence check cannot see is printed with the verdict: same-seed keys
at unrelated derivation paths are cryptographically unlinkable, and no software can
verify that two commands ran on two physical machines.

## 4. Back on each node host — endorse

```
btc-vault setup node-endorse --device-dir /run/vault-setup \
  --wallet-id <hex> --manifest-hash <hex> --node-id <n>
```

Re-enter the preimage. The device re-derives its key, checks it still matches the
key it published, and signs its channel identity over this manifest. Copy
`endorsement-<node_id>.txt` back to the coordinator.

## 5. On the coordinator — finalize

```
btc-vault setup finalize --dir ./vault
```

Verifies every endorsement (a bad one would otherwise be found by every node at
startup, after the hosts are sealed, when the only remedy is re-provisioning), then
writes `sealed-v1/`: the manifest, one `node-<id>.toml` per node, and `backup/`.
It also re-runs the ceiling bounds above against the state it is about to seal, because
`assemble`'s gate is not the last word: a state edited afterwards and re-endorsed at the
recomputed hash satisfies every other check, and no node ever bounds the ceiling.

**The whole set is rendered and staged under `.finalize-staging.<pid>/` before ANY of it
is published**, then that complete directory is atomically renamed to `sealed-v1/`
(ADR-0016 §4). An interrupted `finalize` therefore exposes either no finalized set or
one complete set—never an independently usable node config from a partial publication.
That staging directory is per invocation, so two `finalize` runs that overlap in one
ceremony directory cannot clear each other's staged set and publish the remnant as a
complete seal: whichever loses fails, at the existing-set refusal below or at the rename.
Both that staging directory and the `sealed-v1/` it becomes request owner-only mode at
creation (`mkdir` mode 0700); the umask can only remove bits, never add group/world access.
That prevents another local account from
traversing those inodes or changing entries inside them. It does NOT protect the directory
entries that name those roots: the ceremony directory that contains them is still created at
your umask, so an account able to write that parent can replace the staging root mid-ceremony
or `sealed-v1/` afterwards. Run the ceremony on a host and medium you control; `btc-policy-b8z`
tracks a parent-namespace remedy.
Re-running after a process interruption safely creates exactly one complete set, but it
does NOT delete the interrupted run's staging directory, which holds the same secrets as
the artifacts below (0600 node configs, the coordinator key). Remove it yourself once the
retry has sealed. Once `sealed-v1/` exists, `finalize` refuses to
accept, merge, or overwrite it—even if its bytes appear identical—so an unsafe hand copy
cannot be blessed without checking its file types and secret modes.

That covers process interruption, which is what `finalize` can control. The rename is
atomic but not `fsync`ed, so a HOST POWER LOSS can still leave a `sealed-v1/` whose
contents are incomplete. That case is fail-closed rather than silent: the same existing-set
refusal requires the operator to inspect and remove `sealed-v1/` before re-running, not
just to re-run. Nothing is lost either way: every artifact in it is re-derived from
`ceremony-state.json` and the coordinator files beside it, none of which `finalize` modifies.

## Artifacts

| File | Secret? | Notes |
|---|---|---|
| `descriptor.txt` | no | Back up promiscuously. Without it even valid recovery keys cannot find the coins. |
| `manifest-hash.txt`, `wallet-id.txt`, `sealed-v1/manifest.json` | no | The immutable trust root every node is sealed to. |
| `coordinator-auth.pubkey` | no | Pinned in the manifest. |
| `coordinator-auth.secret` | **YES** | Store separately. Losing it with no backup **bricks the normal path** — the manifest pins its pubkey and is immutable, so the only exit is the recovery timelock. Rotation is a new vault; there is no in-place rotation in v0. |
| `independence.txt` | no | The witnessed key-independence evidence. |
| `sealed-v1/node-<id>.toml` | **YES** | Per-node config. Contains NO signing key (only the public wskdf derivation parameters), but DOES carry the chain-backend RPC credential and both Argon2 PIN digests — so `finalize` writes it owner-only (0600). Hand each to ITS node's host only, and securely delete the coordinator's copies after distribution; a leaked copy exposes the RPC credential and lets an attacker guess PINs offline. |
| `sealed-v1/backup/` | mixed | The set to move to storage you control, off the coordinator. |

Never in the artifacts, deliberately: the node preimages (each on its own
operator's paper), the escape wallet secret, and the recovery keys.

## 6. Start each node, then seal

```
vault-node --config sealed-v1/node-<id>.toml     # then type that node's preimage
```

The daemon reads the preimage on stdin, derives its signing key in RAM, and
refuses to start if that key is not one the frozen descriptor names. Then seal the
host (ADR-0005): SSH uninstalled, no administrative path left.

**A node starts exactly once in its life.** A reboot leaves a bare machine — no
config, no key, no way to ask for a preimage — which is node death by design
(ADR-0007). At one dead node, plan a rotation; at two, rotation is urgent.

**Once the node is up and its host is sealed, securely DESTROY the paper preimage.**
The machine no longer needs it (the key is in RAM), and a rebooted node is dead — you
rotate to a successor vault, never resurrect it (ADR-0007). Reprovisioning with the
SAME key + SAME manifest would reset a Locked node's budget for a coerced operator,
which is exactly the `/unseal` resurrection ADR-0007 rejects. Keeping the preimage is
the only thing that would make such a resurrection materially possible; destroying it
removes that path, so reboot-death and the Lockdown latch hold even off-machine.

## Known v0 deviations

Stated rather than hidden, since a documented deviation is acceptable and a silent
one is not:

* **PIN enrollment is not part of the ceremony.** `ceremony.json` takes the two
  Argon2id PHC digests as input; producing them is a separate step. The PINs
  themselves never reach any artifact.
* **The regtest harness writes preimages to files.** `demo` and `attack` drive
  this same ceremony, one process per node-side step, but have no human to type a
  preimage — so they use the documented `--preimage-file` automation flag, writing
  each preimage in that node's own directory. The coordinator process still never
  reads those bytes: it hands the file to each child on stdin. A production
  ceremony omits the flag.
* **`--secret-file` / `--preimage-file` exist at all.** They are automation escape
  hatches and say so loudly on every run that uses them.
* **`keygen --role escape` emits a TESTNET-flavoured extended key** (`tpub…`), like
  every other key this v0 tree generates — there is no network parameter anywhere
  in the codebase yet, and adding one here alone would be the first. The prefix is
  a serialization hint, not a derivation input: the same seed derives the same keys
  and the same scripts either way, and the printed `tpriv` re-derives the wallet.
  Some mainnet wallets refuse to import a `tpub`, so a mainnet deployment should
  generate the escape wallet on its own hardware and hand-write the bundle (which
  is the recommended path regardless — see step 2). When you hand-write it, the
  escape descriptor's xpub MUST NOT be the account key you also use as the user
  key (or any node/recovery/coordinator key): non-hardened BIP32 derivation over a
  public chain code means whoever holds that key's private half can derive every
  escape address, silently turning duress into theft (ADR-0012 §10). `assemble`
  now refuses this — it compares the escape wallet's derived children AND its
  ancestor xpubs against every vault key and the coordinator key — but the
  independent generation is what makes the refusal never fire.
* **The coordinator auth secret is written to disk** by `assemble`, at mode 0600.
  That is deliberate: it must be backed up, or ordinary loss bricks the vault.
* **v0 coordinator auth stays as it is** — no mTLS, no Tor. Unchanged by this bead.
