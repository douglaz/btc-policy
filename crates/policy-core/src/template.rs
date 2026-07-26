//! The vault descriptor template (ADR-0013 §1): a fixed, hand-written two-branch
//! `wsh(...)`.
//!
//! ```text
//! or( and( pk(USER), thresh(t, NODE_1, …, NODE_n) ),          # normal branch
//!     and( older(TIMELOCK), thresh(2, REC_A, REC_B, REC_C) ) ) # recovery branch
//! ```
//!
//! The **normal branch** is the everyday spend path: the user key AND a `t`-of-`n`
//! federation quorum. The **recovery branch** is the timelocked FALLBACK exit —
//! after `older(TIMELOCK)` matures, a 2-of-3 recovery keyset moves the funds with
//! NO user key and NO node quorum. It is what a locked-down or otherwise-stuck
//! vault takes (DESIGN.md, Wallet Topology; V0-4b's "funds frozen → recovery").
//!
//! This module is the single source of truth for the template's SHAPE and its
//! recovery timelock, so the demo/setup descriptor builder, the node's startup
//! parse, and the "setup rejects any descriptor outside the template" check all
//! agree by construction rather than by three copies staying in sync.
//!
//! Every key in this template is **definite** — one concrete compressed pubkey per
//! role, never a ranged xpub (2026-07-25, bead btc-policy-9y5.5). The destination
//! allowlist wallets are the opposite and stay ranged; [`parse_vault_template`]
//! records why the two differ and enforces the rule for the vault.
//!
//! rust-miniscript is authoritative for parsing the frozen string; the concrete
//! `wsh(or_i(and_v(...),and_v(...)))` fragment below is the pinned construction the
//! ADR describes (compiled once, then hand-written here so every party derives the
//! identical byte string). [`parse_vault_template`] re-parses it into typed pieces
//! and REJECTS anything off-template — that rejection is the load-bearing
//! guarantee: a descriptor missing the recovery branch would be a vault with no
//! demonstrable exit, and one with a `older(30375)` BLOCK lock (the classic
//! missing-BIP68-flag bug) would arm recovery ~30375 blocks out instead of
//! ~180 days, both silent lockout/loss hazards.

use bitcoin::Sequence;
use miniscript::descriptor::WshInner;
use miniscript::{Descriptor, MiniscriptKey, Terminal};

/// The recovery branch's BIP68 relative timelock, in units of 512 seconds
/// (ADR-0013 §1). The 180-day default is `⌈180·86400 / 512⌉ = 30375` units.
pub const RECOVERY_TIMELOCK_UNITS: u16 = 30375;

/// The RAW consensus `nSequence` the descriptor's `older(...)` argument carries:
/// 30375 units of 512 s with the BIP68 TIME-based type-flag (bit 22) set, i.e.
/// `30375 | (1 << 22) = 4_224_679 = 0x004076a7` (2026-07-17 codex correction).
///
/// rust-miniscript's `older(n)` uses `n` as the raw `nSequence` and does NOT add
/// the type-flag, so the frozen descriptor contains `older(4224679)`, NOT
/// `older(30375)` — the latter is a 30375-**BLOCK** height lock (~7 months of
/// blocks, but a height lock, not a time lock), the wrong policy. Construct the
/// value via [`recovery_sequence`] (which sets the flag through `bitcoin` itself)
/// rather than hand-ORing the bit.
pub const RECOVERY_TIMELOCK_NSEQUENCE: u32 = 4_224_679;

/// Recovery keyset threshold (fixed 2-of-3, ADR-0013 §1).
pub const RECOVERY_THRESHOLD: usize = 2;
/// Recovery keyset size (fixed 2-of-3, ADR-0013 §1).
pub const RECOVERY_KEYS: usize = 3;

/// The recovery branch's relative-lock [`Sequence`], built from the 512-second
/// unit count so the BIP68 time-flag is set by `bitcoin` itself — never a
/// hand-ORed magic bit. Equal to [`RECOVERY_TIMELOCK_NSEQUENCE`] by construction
/// (asserted in this module's tests, and by [`parse_vault_template`] on every
/// descriptor it accepts).
pub fn recovery_sequence() -> Sequence {
    Sequence::from_512_second_intervals(RECOVERY_TIMELOCK_UNITS)
}

/// Build the canonical two-branch vault descriptor STRING (an unchecksummed
/// miniscript expression, ready to `Descriptor::from_str`). `user`, `nodes`, and
/// `recovery` are DEFINITE key expressions — one concrete compressed pubkey per
/// role, in production exactly as in the regtest demo (see
/// [`parse_vault_template`] for why the vault descriptor is definite and the
/// destination allowlist is not). The `older(...)` argument is the raw
/// [`RECOVERY_TIMELOCK_NSEQUENCE`], not the unit count.
///
/// This is the ONE place the fragment shape lives; callers parse the result with
/// the same pinned rust-miniscript every node runs, so the byte string is
/// identical everywhere ([`parse_vault_template`] round-trips it).
pub fn vault_descriptor_string(
    user: &str,
    threshold: usize,
    nodes: &[String],
    recovery: &[String],
) -> String {
    format!(
        "wsh(or_i(and_v(v:pk({user}),multi({threshold},{nodes})),\
         and_v(v:older({timelock}),multi({rec_t},{recovery}))))",
        nodes = nodes.join(","),
        timelock = RECOVERY_TIMELOCK_NSEQUENCE,
        rec_t = RECOVERY_THRESHOLD,
        recovery = recovery.join(","),
    )
}

/// The typed pieces of a valid vault descriptor, extracted from the frozen
/// template by [`parse_vault_template`].
#[derive(Debug, Clone)]
pub struct VaultTemplate<Pk: MiniscriptKey> {
    /// The single normal-branch user key (`pk(USER)`).
    pub user_key: Pk,
    /// `t` — the federation combine threshold from the normal branch's
    /// `multi(t, …)`. A consensus fact about the script, never a config copy.
    pub threshold: usize,
    /// The federation node keys, in descriptor order (the channel derives the
    /// canonical lexicographic order itself; ADR-0013 §1).
    pub node_keys: Vec<Pk>,
    /// The 2-of-3 recovery keys (recovery branch `multi(2, …)`), descriptor order.
    pub recovery_keys: Vec<Pk>,
    /// The recovery branch's raw `older(...)` nSequence. Always
    /// [`RECOVERY_TIMELOCK_NSEQUENCE`] on an accepted descriptor.
    pub recovery_timelock: u32,
}

/// Parse and VALIDATE a descriptor against the fixed vault template (ADR-0013 §1),
/// returning its typed pieces. `Err` — a plain human-readable string — means the
/// descriptor is off-template and must be rejected at setup / startup.
///
/// The shape required, exactly:
/// `wsh(or_i(and_v(v:pk(USER),multi(t,NODES…)),and_v(v:older(4224679),multi(2,REC_A,REC_B,REC_C))))`.
/// Any other top-level connective, a missing recovery branch, a recovery keyset
/// that is not 2-of-3, or a timelock other than the BIP68 TIME-based
/// [`RECOVERY_TIMELOCK_NSEQUENCE`] (in particular the `older(30375)` block-lock
/// mistake) is rejected. This is the "setup rejects any descriptor outside this
/// template" enforcement, reused verbatim as the node's startup template check.
pub fn parse_vault_template<Pk: MiniscriptKey>(
    descriptor: &Descriptor<Pk>,
) -> Result<VaultTemplate<Pk>, String> {
    let template_err = || -> String {
        "descriptor is not the vault template \
         wsh(or_i(and_v(v:pk(USER),multi(t,NODES...)),\
         and_v(v:older(4224679),multi(2,REC_A,REC_B,REC_C))))"
            .to_string()
    };
    let Descriptor::Wsh(wsh) = descriptor else {
        return Err(template_err());
    };
    let WshInner::Ms(ms) = wsh.as_inner() else {
        return Err(template_err());
    };
    // The two branches: `or_i(NORMAL, RECOVERY)`. `or_i` puts an explicit
    // OP_IF/OP_ELSE selector in the witness, which is exactly what makes a
    // recovery spend branch-identifiable on-chain (see the watchtower).
    let Terminal::OrI(normal, recovery) = &ms.node else {
        return Err(template_err());
    };

    // --- normal branch: and_v(v:pk(USER), multi(t, NODES...)) ---
    let Terminal::AndV(left, right) = &normal.node else {
        return Err(template_err());
    };
    // `v:pk(USER)` parses as Verify(Check(PkK(USER))).
    let Terminal::Verify(checked) = &left.node else {
        return Err(template_err());
    };
    let Terminal::Check(pk) = &checked.node else {
        return Err(template_err());
    };
    let Terminal::PkK(user_key) = &pk.node else {
        return Err(template_err());
    };
    let Terminal::Multi(nodes) = &right.node else {
        return Err(template_err());
    };

    // --- recovery branch: and_v(v:older(TIMELOCK), multi(2, REC...)) ---
    let Terminal::AndV(rec_left, rec_right) = &recovery.node else {
        return Err(template_err());
    };
    let Terminal::Verify(older) = &rec_left.node else {
        return Err(template_err());
    };
    let Terminal::Older(timelock) = &older.node else {
        return Err(template_err());
    };
    let Terminal::Multi(recovery_keys) = &rec_right.node else {
        return Err(template_err());
    };

    // The recovery timelock must be the BIP68 TIME-based value, not a block lock.
    let recovery_timelock = timelock.to_consensus_u32();
    if recovery_timelock != RECOVERY_TIMELOCK_NSEQUENCE {
        return Err(format!(
            "recovery branch timelock is older({recovery_timelock}), not the required BIP68 \
             time-based older({RECOVERY_TIMELOCK_NSEQUENCE}) (30375 units of 512s + type-flag \
             bit 22); older(30375) would be a 30375-BLOCK height lock, the wrong policy"
        ));
    }
    if recovery_keys.k() != RECOVERY_THRESHOLD || recovery_keys.n() != RECOVERY_KEYS {
        return Err(format!(
            "recovery keyset is {}-of-{}, not the fixed 2-of-3 (ADR-0013 §1)",
            recovery_keys.k(),
            recovery_keys.n()
        ));
    }

    // Reject a degenerate KEY STRUCTURE on the PERMANENT trust root (static policy
    // forever — set once at sealed setup, never fixable). miniscript parses a
    // `multi(...)` with duplicate keys, and a duplicate silently weakens the
    // threshold (one signer's key fills multiple slots — `multi(2,R,R,S)` is really
    // 1-of-2) AND can strand funds (losing that key drops two slots at once); a key
    // shared across roles (USER == a node, or a recovery key doubling as a hot key)
    // double-counts and defeats the branch separation. Every vault key — the user
    // key, each node key, each recovery key — must be DISTINCT.
    let mut seen = std::collections::HashSet::new();
    for (role, key) in std::iter::once(("user", user_key))
        .chain(nodes.data().iter().map(|k| ("node", k)))
        .chain(recovery_keys.data().iter().map(|k| ("recovery", k)))
    {
        // The VAULT descriptor is DEFINITE: exactly one concrete public key per
        // role, never a ranged/extended key expression (2026-07-25, bead
        // btc-policy-9y5.5; supersedes ADR-0013 §1's original "origins/derivation-
        // paths required, wildcard `/*` ranged" for the vault descriptor ONLY).
        //
        // Three reasons, in the order they bite:
        //  1. Every node parses the frozen descriptor as a concrete
        //     `Descriptor<PublicKey>` at startup for the witness script, the user
        //     key, and the sighash. A ranged vault descriptor therefore does not
        //     load at all — accepting one here would let setup seal a vault no node
        //     can ever boot against, which is a permanent, unfixable brick (static
        //     policy forever, sealed hosts).
        //  2. The setup ceremony now generates each node key ON THE NODE, and a
        //     node births ONE key, not an xpub range. There is nothing left for a
        //     range to express.
        //  3. `node_id` is the key's position in the canonical LEXICOGRAPHIC order.
        //     ADR-0013 §1 had to define that over the full key-EXPRESSION string
        //     precisely because derived pubkeys of a ranged key are index-dependent
        //     and so ill-defined; with definite keys the expression IS the pubkey,
        //     so the order is well-defined with no caveat left to get wrong.
        //
        // This rule is about the vault descriptor alone. The destination allowlist
        // wallets (hot + escape) stay ranged — they legitimately derive a fresh
        // address per spend within `max_derivation_index` — and nothing here
        // touches them.
        if key.num_der_paths() != 0 {
            return Err(format!(
                "vault descriptor {role} key {key} is a ranged/extended key expression; the \
                 VAULT descriptor must be DEFINITE (one concrete public key per role) because \
                 every node parses it as a concrete descriptor at startup. Destination \
                 allowlist wallets (hot, escape) stay ranged — this rule is only the vault"
            ));
        }
        let key = key.to_string();
        if !seen.insert(key.clone()) {
            return Err(format!(
                "key {key} appears more than once (in the {role} set) — every vault key \
                 (user, {}-of-{} nodes, 2-of-3 recovery) must be distinct; a duplicate \
                 silently weakens the threshold and risks permanent loss",
                nodes.k(),
                nodes.n()
            ));
        }
    }
    // A zero normal threshold would let anyone spend the vault with no node signature
    // at all (miniscript already guarantees k <= n). The user key + `thresh` still
    // gate spends, but t must be a real quorum floor.
    if nodes.k() < 1 {
        return Err(format!(
            "normal node threshold is {}, must be at least 1 (a 0-of-n quorum needs no \
             node signature)",
            nodes.k()
        ));
    }

    Ok(VaultTemplate {
        user_key: user_key.clone(),
        threshold: nodes.k(),
        node_keys: nodes.data().to_vec(),
        recovery_keys: recovery_keys.data().to_vec(),
        recovery_timelock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use miniscript::DescriptorPublicKey;
    use std::str::FromStr;

    fn pk(seed: u8) -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).expect("sk");
        PublicKey::from_secret_key(&secp, &sk).to_string()
    }

    fn keys(seeds: std::ops::Range<u8>) -> Vec<String> {
        seeds.map(pk).collect()
    }

    /// An origin'd extended key expression — the shape a production vault key would
    /// have had under ADR-0013 §1's original ranged-xpub wording. Built from a real
    /// master key so the string is a genuine xpub, not a lookalike that miniscript
    /// would reject for its checksum before the template check ever runs.
    fn xkey(seed: u8, suffix: &str) -> String {
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::NetworkKind;
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(NetworkKind::Main, &[seed; 32]).expect("master");
        format!(
            "[d34db33f/84h/0h/0h]{}{suffix}",
            Xpub::from_priv(&secp, &xpriv)
        )
    }

    fn template_desc() -> String {
        vault_descriptor_string(&pk(1), 3, &keys(2..7), &keys(20..23))
    }

    #[test]
    fn recovery_sequence_encodes_the_bip68_time_flag_not_a_block_lock() {
        // 30375 units of 512s WITH the time-flag (bit 22) is 4224679; the bare
        // unit count 30375 would be a block-height lock — the exact bug the
        // 2026-07-17 correction names.
        assert_eq!(
            recovery_sequence().to_consensus_u32(),
            RECOVERY_TIMELOCK_NSEQUENCE
        );
        assert_eq!(RECOVERY_TIMELOCK_NSEQUENCE, 30375 | (1 << 22));
        assert!(recovery_sequence().is_relative_lock_time());
        assert!(
            recovery_sequence().is_time_locked(),
            "must be a TIME lock, not height"
        );
    }

    #[test]
    fn the_template_string_parses_and_round_trips_to_its_pieces() {
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&template_desc()).expect("parse");
        let t = parse_vault_template(&desc).expect("on-template");
        assert_eq!(t.threshold, 3);
        assert_eq!(t.node_keys.len(), 5);
        assert_eq!(t.recovery_keys.len(), 3);
        assert_eq!(t.recovery_timelock, RECOVERY_TIMELOCK_NSEQUENCE);
        assert_eq!(t.user_key.to_string(), pk(1));
    }

    #[test]
    fn a_descriptor_with_no_recovery_branch_is_rejected() {
        // The old single-branch first-light shape: normal path only, no exit.
        let single = format!(
            "wsh(and_v(v:pk({}),multi(3,{})))",
            pk(1),
            keys(2..7).join(",")
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&single).expect("parse");
        assert!(
            parse_vault_template(&desc).is_err(),
            "missing recovery branch must reject"
        );
    }

    #[test]
    fn a_block_height_timelock_is_rejected_as_off_template() {
        // older(30375) — the missing-BIP68-flag bug: a 30375-BLOCK height lock.
        let block_lock = format!(
            "wsh(or_i(and_v(v:pk({}),multi(3,{})),and_v(v:older(30375),multi(2,{}))))",
            pk(1),
            keys(2..7).join(","),
            keys(20..23).join(","),
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&block_lock).expect("parse");
        let err = parse_vault_template(&desc).expect_err("block-height lock must reject");
        assert!(
            err.contains("BLOCK") || err.contains("block"),
            "err names the block lock: {err}"
        );
    }

    #[test]
    fn a_duplicate_recovery_key_is_rejected() {
        // multi(2, R, R, S): a single R fills both required slots -> really 1-of-2,
        // and losing R strands the funds. The permanent trust root must refuse it.
        let dup_recovery = format!(
            "wsh(or_i(and_v(v:pk({}),multi(3,{})),and_v(v:older({}),multi(2,{},{},{}))))",
            pk(1),
            keys(2..7).join(","),
            RECOVERY_TIMELOCK_NSEQUENCE,
            pk(20),
            pk(20),
            pk(22),
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&dup_recovery).expect("parse");
        let err = parse_vault_template(&desc).expect_err("duplicate recovery key must reject");
        assert!(
            err.contains("distinct") || err.contains("more than once"),
            "{err}"
        );
    }

    #[test]
    fn a_duplicate_node_key_is_rejected() {
        let dup_node = format!(
            "wsh(or_i(and_v(v:pk({}),multi(3,{},{},{},{},{})),and_v(v:older({}),multi(2,{}))))",
            pk(1),
            pk(2),
            pk(2),
            pk(4),
            pk(5),
            pk(6),
            RECOVERY_TIMELOCK_NSEQUENCE,
            keys(20..23).join(","),
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&dup_node).expect("parse");
        assert!(
            parse_vault_template(&desc).is_err(),
            "duplicate node key must reject"
        );
    }

    #[test]
    fn a_user_key_reused_as_a_node_is_rejected() {
        // USER == NODE_1 double-counts the user toward the node quorum.
        let overlap = format!(
            "wsh(or_i(and_v(v:pk({}),multi(3,{},{},{},{},{})),and_v(v:older({}),multi(2,{}))))",
            pk(2), // user
            pk(2), // node 1 == user
            pk(3),
            pk(4),
            pk(5),
            pk(6),
            RECOVERY_TIMELOCK_NSEQUENCE,
            keys(20..23).join(","),
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&overlap).expect("parse");
        assert!(
            parse_vault_template(&desc).is_err(),
            "user key reused as a node must reject"
        );
    }

    #[test]
    fn a_non_2_of_3_recovery_keyset_is_rejected() {
        let three_of_three = format!(
            "wsh(or_i(and_v(v:pk({}),multi(3,{})),and_v(v:older({}),multi(3,{}))))",
            pk(1),
            keys(2..7).join(","),
            RECOVERY_TIMELOCK_NSEQUENCE,
            keys(20..23).join(","),
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&three_of_three).expect("parse");
        assert!(
            parse_vault_template(&desc).is_err(),
            "3-of-3 recovery must reject"
        );
    }

    /// A ranged VAULT descriptor is rejected at template parse (bead 9y5.5,
    /// deliverable 4). This is the resolution of the ranged-xpub question: setup
    /// refuses the shape rather than the node discovering at startup that the
    /// descriptor it was sealed with does not parse as a concrete descriptor — by
    /// which point the vault is already frozen and the hosts already sealed.
    #[test]
    fn a_ranged_vault_descriptor_is_rejected() {
        // A well-formed origin'd ranged xpub in the NODE position: exactly what a
        // production descriptor would have looked like under ADR-0013 §1's original
        // wording, and exactly what `Descriptor::<PublicKey>::from_str` cannot load.
        let xpub = xkey(9, "/0/*");
        let ranged = format!(
            "wsh(or_i(and_v(v:pk({}),multi(3,{},{},{},{},{})),and_v(v:older({}),multi(2,{}))))",
            pk(1),
            xpub,
            pk(3),
            pk(4),
            pk(5),
            pk(6),
            RECOVERY_TIMELOCK_NSEQUENCE,
            keys(20..23).join(","),
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&ranged).expect("parse");
        let err = parse_vault_template(&desc).expect_err("ranged vault descriptor must reject");
        assert!(
            err.contains("DEFINITE") && err.contains("node"),
            "err names the definiteness rule and the offending role: {err}"
        );
    }

    /// The same rule, on the USER key and with no wildcard: an xpub is not definite
    /// even when it is not ranged, because the node still cannot parse it as a
    /// concrete key. `num_der_paths` — not `has_wildcard` — is the predicate.
    #[test]
    fn a_wildcardless_xpub_vault_key_is_still_rejected() {
        let xpub = xkey(11, "/0/7");
        let fixed = format!(
            "wsh(or_i(and_v(v:pk({}),multi(3,{})),and_v(v:older({}),multi(2,{}))))",
            xpub,
            keys(2..7).join(","),
            RECOVERY_TIMELOCK_NSEQUENCE,
            keys(20..23).join(","),
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&fixed).expect("parse");
        let err = parse_vault_template(&desc).expect_err("xpub vault key must reject");
        assert!(err.contains("DEFINITE") && err.contains("user"), "{err}");
    }

    #[test]
    fn a_bare_wpkh_descriptor_is_rejected() {
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({})", pk(1)))
            .expect("parse");
        assert!(
            parse_vault_template(&desc).is_err(),
            "a non-wsh descriptor is off-template"
        );
    }

    /// A fast (no-bitcoind) satisfaction test that pins TWO cross-module contracts
    /// at once: (1) the recovery branch requires 2-of-3 recovery signatures + the
    /// matured relative-lock sequence, and (2) the witness's SECOND-TO-LAST element
    /// is the `or_i` branch selector — EMPTY for the recovery (ELSE) branch, `01`
    /// for the normal (IF) branch. Contract (2) is exactly what the watchtower's
    /// `is_recovery_branch` reads on-chain, so pinning it here catches a
    /// rust-miniscript upgrade that reshapes the witness before it silently
    /// mislabels a recovery spend.
    #[test]
    fn recovery_branch_needs_two_of_three_and_carries_the_empty_selector() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::Message;
        use bitcoin::sighash::SighashCache;
        use bitcoin::transaction::Version;
        use bitcoin::{
            Amount, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn,
            TxOut, Txid, Witness,
        };
        use miniscript::psbt::PsbtExt;

        // `PublicKey` in this test module is `secp256k1::PublicKey`; the descriptor
        // and PSBT partial_sigs use `bitcoin::PublicKey`, so both are named in full.
        fn keypair(seed: u8) -> (SecretKey, PublicKey) {
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[seed; 32]).expect("sk");
            (sk, PublicKey::from_secret_key(&secp, &sk))
        }

        let secp = Secp256k1::new();
        let desc =
            Descriptor::<bitcoin::PublicKey>::from_str(&template_desc()).expect("concrete parse");
        let witness_script = desc.explicit_script().expect("witness script");
        let vault_spk = desc.script_pubkey();
        let user = keypair(1);
        let nodes: Vec<(SecretKey, PublicKey)> = (2u8..7).map(keypair).collect();
        let recovery: Vec<(SecretKey, PublicKey)> = (20u8..23).map(keypair).collect();

        // Build a spend with `sequence`, sign it with `signers`, and finalize.
        let finalize =
            |sequence: Sequence, signers: &[(SecretKey, PublicKey)]| -> Option<Witness> {
                let tx = Transaction {
                    version: Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint::new(Txid::from_byte_array([9u8; 32]), 0),
                        script_sig: ScriptBuf::new(),
                        sequence,
                        witness: Witness::new(),
                    }],
                    output: vec![TxOut {
                        script_pubkey: vault_spk.clone(),
                        value: Amount::from_sat(90_000),
                    }],
                };
                let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned");
                psbt.inputs[0].witness_utxo = Some(TxOut {
                    script_pubkey: vault_spk.clone(),
                    value: Amount::from_sat(100_000),
                });
                psbt.inputs[0].witness_script = Some(witness_script.clone());
                let unsigned = psbt.unsigned_tx.clone();
                let sighash = SighashCache::new(&unsigned)
                    .p2wsh_signature_hash(
                        0,
                        &witness_script,
                        Amount::from_sat(100_000),
                        EcdsaSighashType::All,
                    )
                    .expect("sighash");
                for (sk, pk) in signers {
                    let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), sk);
                    psbt.inputs[0].partial_sigs.insert(
                        bitcoin::PublicKey::new(*pk),
                        bitcoin::ecdsa::Signature {
                            signature: sig,
                            sighash_type: EcdsaSighashType::All,
                        },
                    );
                }
                psbt.finalize_mut(&Secp256k1::verification_only()).ok()?;
                Some(psbt.extract_tx().expect("extract").input[0].witness.clone())
            };

        // 2-of-3 recovery + the matured relative-lock sequence finalizes; its
        // witness carries the EMPTY recovery selector second-from-last.
        let rec_witness =
            finalize(recovery_sequence(), &recovery[..2]).expect("2-of-3 recovery must finalize");
        assert!(
            rec_witness.second_to_last().expect("selector").is_empty(),
            "the recovery (or_i ELSE) branch selector must be empty — the watchtower's signal"
        );

        // 1-of-3 does NOT satisfy the recovery branch.
        assert!(
            finalize(recovery_sequence(), &recovery[..1]).is_none(),
            "1-of-3 recovery must not finalize"
        );

        // The normal branch (user + 3 nodes, no relative lock) finalizes with a
        // NON-empty `01` selector — never mistaken for recovery.
        let mut normal_signers = vec![user];
        normal_signers.extend_from_slice(&nodes[..3]);
        let normal_witness =
            finalize(Sequence::MAX, &normal_signers).expect("user + 3 nodes must finalize");
        assert_eq!(
            normal_witness.second_to_last().expect("selector"),
            [0x01],
            "the normal (or_i IF) branch selector is 01, never the empty recovery selector"
        );
    }
}
