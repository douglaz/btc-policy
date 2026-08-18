# Protocol test vectors

Part of the core-proven gate's artifact set (bead `btc-policy-9y5.8` deliverable 2).

Frozen byte-level vectors for every domain-separated hash this protocol commits to. They exist
so an **independent implementation, or a reviewer with a hex editor, can verify the wire format
without reading the Rust** — and so any accidental change to a preimage layout fails a test
instead of silently forking the federation.

Each vector below is asserted in the codebase; the "pinned by" column names the test. If you
change a preimage and these do not fail, the test is not doing its job.

| Domain | Tag | Pinned by (`crates/vault-node/src/channel.rs`) |
|---|---|---|
| Channel key | `btc-policy/channel-key/v0` | `channel_key_vector_is_frozen` |
| Manifest | `btc-policy/manifest/v0` | `manifest_vector_is_frozen` |
| Channel endorsement | `btc-policy/channel-endorsement/v0` | `endorsement_vector_is_frozen` |
| Channel envelope | `btc-policy/channel-envelope/v0` | `envelope_vector_is_frozen` |
| User sig hash | `btc-policy/user-sig-hash/v0` | `user_sig_hash_vector_is_frozen` |
| Coordinator request | `btc-policy/coord-request/v0` | `crates/vault-proto` commitment tests |

## The hash construction

Every digest uses the same BIP340-style tagged hash (`vault_proto::tagged_hash`):

```
tagged_hash(tag, msg) = SHA256( SHA256(tag) ‖ SHA256(tag) ‖ msg )
```

where `tag` is the ASCII tag string **without** a trailing NUL. Domain separation is what stops
a signature over one structure from being replayable as a signature over another, so an
implementation that skips the doubled tag hash is not compatible — it is a different protocol
that happens to interoperate until it doesn't.

### Encoding conventions

The preimages are built with one small encoder (`Enc`), and there are only five moves:

| Move | Encoding |
|---|---|
| `fixed(bytes)` | the bytes, no prefix (used for 32-byte ids and 33-byte compressed pubkeys) |
| `u16(v)` / `u32(v)` / `u64(v)` | **little-endian**, 2 / 4 / 8 bytes |
| `u8(v)` | one byte |
| `var(bytes)` | `u32` LE length prefix, then the bytes |
| `endpoints(list)` | `u32` LE count, then each entry as `var` |

Little-endian throughout, and every variable-length field is length-prefixed — so no
concatenation ambiguity exists (`[a, b]` can never encode the same as `[ab]`).

## Vector 1 — Channel key

```
tag    : btc-policy/channel-key/v0
msg    : 1111111111111111111111111111111111111111111111111111111111111111
digest : 39d6dee9b0db353e509ef6daa3885eccb21dc01b4b471369b98cd6f3253f20c7
```

The channel key is derived from the node's federation signing key under this tag, so a channel
key can never be mistaken for — or used as — a Bitcoin signing key.

## Vector 2 — Manifest (`BaseManifest`)

The manifest hash is the vault's identity: every node checks its own computed hash against the
sealed anchor at startup and refuses to boot on a mismatch. That refusal is the mechanism that
makes the federation-uniform values *provably* uniform.

**Field order** (this is the whole schema):

```
# This block and ADR-0013 §4's canonical list encode the SAME preimage. ADR-0013's copy has been
# wrong three times (missing escape_feerate_floor, escape_coverage_pct, and both u32 counts);
# this one has not. THIS DOCUMENT IS THE AUTHORITY: on any divergence the vector wins, because it
# is executable against the code. ADR-0013 §4 and ADR-0016 §3a both defer here.
wallet_id                     fixed 32
protocol_version              u32
coordinator_auth_pubkey       fixed 33   (compressed)
max_msg_bytes                 u64
hot_budget.max_per_tx_sat     u64
hot_budget.max_per_window_sat u64
hot_budget.window_secs        u64
hot_allowlist                 u32 count, then each descriptor as var
                              (canonicalized, sorted, deduped — order carries no policy meaning)
escape_descriptor             var
max_derivation_index          u32
escape_feerate_floor          u64        <- fire-time selector input
escape_coverage_pct           u8         <- fire-time selector input
escape_bump_max_fee_pct       u8         <- sealed ladder ceiling (ADR-0016 §3a)
nodes                         u32 count, then per node:
                                node_id          u16
                                signing_pubkey   fixed 33
                                channel_pubkey   fixed 33
                                endpoints        u32 count, then each as var (UTF-8)
```

**Vector** — `wallet_id = 0x22*32`, `protocol_version = 1`, coordinator pubkey `03 8a3b…`,
`max_msg_bytes = 1048576`, hot budget `(0x11111111, 0x22222222, 0x33333333)`, allowlist
`["wpkh(hot)"]`, escape `"wpkh(escape)"`, `max_derivation_index = 5`,
`escape_feerate_floor = 1`, `escape_coverage_pct = 95 (0x5f)`,
`escape_bump_max_fee_pct = 0 (0x00)`, two nodes on `127.0.0.1:9000` / `127.0.0.1:9001`:

```
preimage:
222222222222222222222222222222222222222222222222222222222222222201000000
038a3ba5c99568d26602f4cf8038371da3c86057a96eb1b6a8de1b4f1be723c236
0000100000000000
1111111100000000
2222222200000000
3333333300000000
01000000 09000000 77706b6828686f7429
0c000000 77706b68286573636170652
905000000
0100000000000000
5f
00
02000000
0000 031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
     024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766
     01000000 0e000000 3132372e302e302e313a39303030
0100 02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337
     03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b
     01000000 0e000000 3132372e302e302e313a39303031

digest: e1eacefbc4501240e2c01e61e9ca916b9245b2732a32690893ca0f17eb1aeb3b
```

(The preimage is one contiguous byte string; it is broken across lines above only to show the
field boundaries. The canonical single-line form is `FROZEN_MANIFEST_PREIMAGE_HEX`.)

Note `0100000000000000` (floor = 1), `5f` (coverage = 95) and `00`
(`escape_bump_max_fee_pct` = 0) sitting between `max_derivation_index` and the node count. The
first two are hash-bound precisely so a node provisioned with a different fire-time selector
cannot boot into this federation. The third is hash-bound for the reason ADR-0016 §3a gives:
"sealed" means in the PREIMAGE, and a ceiling present only in `manifest.json` would be a value
the ceremony writes and no node is bound to. Nodes never enforce it (§4a) — they only prove it
uniform. Appending that one byte is why `protocol_version` is `1` here and was `0` before.

## Vector 3 — Channel endorsement

Each node's signing key vouches for its own channel key. The manifest's `channel_pubkey` is
trusted *because* this endorsement verifies — the wire envelope carries no endorsement.

```
fields : wallet_id(32) ‖ manifest_hash(32) ‖ node_id(u16) ‖ channel_pubkey(33)
         ‖ protocol_version(u32) ‖ endpoints(u32 count, then each as var UTF-8)

preimage:
2222222222222222222222222222222222222222222222222222222222222222
3333333333333333333333333333333333333333333333333333333333333333
0100
03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b
01000000
01000000 0e000000 3132372e302e302e313a39303031

digest: be2aa05e39b0c5858c00f288bc1ca4d7aae22c674c1df19826aac3d12944d18f
```

`protocol_version` is inside these bytes, so an endorsement collected at revision 0 does not
verify at revision 1 — the signature binds the schema revision, not just the membership.

## Vector 4 — Channel envelope

Every peer-to-peer message is signed over this. The `msg_type` is length-prefixed and the nonce
and timestamp are inside the signed bytes, which is what makes replay and cross-type confusion
detectable.

```
fields : msg_type(var) ‖ protocol_version(u32) ‖ wallet_id(32) ‖ manifest_hash(32)
         ‖ from_node(u16) ‖ to_node(u16) ‖ payload(var) ‖ nonce(16) ‖ timestamp(u64)

inputs : msg_type="partial", protocol_version=1, wallet_id=0x22*32,
         manifest_hash=0x33*32, from=1, to=2, payload=b"cGFydGlhbA==",
         nonce=0x44*16, timestamp=1752000000

preimage:
07000000 7061727469616c
01000000
2222222222222222222222222222222222222222222222222222222222222222
3333333333333333333333333333333333333333333333333333333333333333
0100 0200
0c000000 6347467964476c6862413d3d
10000000 44444444444444444444444444444444
00666d6800000000

digest: ef653cb88931e6240d923505944beafe9b9a7057d3c32cfe3fd17a78cd065237
```

## Vector 5 — User sig hash and Vector 6 — Coordinator request

Both are pinned in-tree (`user_sig_hash_vector_is_frozen`, and the commitment-binding tests in
`crates/vault-proto`). The coordinator digest is:

```
tagged_hash("btc-policy/coord-request/v0", wallet_id ‖ canonical_bytes(request))
```

The `wallet_id` prefix is load-bearing: it domain-separates the signature to **one vault**, so a
coordinator signature captured from one vault cannot be replayed against another that happens to
share a coordinator key.

## How to verify these

```
nix develop -c cargo test --locked -p vault-node --lib vector_is_frozen
nix develop -c cargo test --locked -p vault-proto
```

An independent implementation should reproduce every digest above from the field descriptions
alone. If it cannot, one of the two is wrong — and the vectors, not the prose, are normative.

## Caveats

- These vectors pin **manifest schema revision 1** — the value `protocol_version` carries, and
  NOT the routable/authenticated transport v1, which is separate work. The domain tags stay
  `/v0`: they separate domains, not revisions, and retagging them would invalidate every digest
  for no gain. `protocol_version` is inside the manifest preimage, so a revision bump is a new
  manifest and therefore a new vault (see `docs/UPGRADE-AND-ROTATION-POLICY.md`). Revision 0's
  vectors are not reproduced here; sealed hosts take no upgrade-in-place (ADR-0005), so a
  revision-0 vault keeps computing revision-0 bytes with the binary it was sealed with.
- The vectors cover hash **preimages and digests**, not signature encodings. Signatures are
  DER-encoded ECDSA over secp256k1 with the usual Bitcoin conventions.
- Vectors 5 and 6 are referenced rather than reproduced here; a reviewer wanting full
  independence should extract them from the named tests the same way vectors 1–4 were extracted.
