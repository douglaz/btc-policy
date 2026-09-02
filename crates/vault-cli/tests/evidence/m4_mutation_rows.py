#!/usr/bin/env python3
"""The M4 mutation row definitions, TRACKED and checkout-portable.

This file is test evidence, not production code: it carries the exact final row
definitions M4-SA inherited, the rows M4-SA owns, and the rows M4-SBR owns, so a later
governed run depends on this repository alone. The ignored provenance artifacts that
produced the inherited rows are recorded in [`SOURCES`] by path and SHA-256 and are NOT
runtime inputs. Each child's rows live in their own ordered list — `M4SA_OWNED` and
`M4SB_OWNED` — and `rows()` is their union with `INHERITED`, in that order.

Provenance. The 91 inherited rows are the exact final union the qhe final-byte harness
produced: the 50 M3 rows that governed M3b's landed bytes (with `m30` re-anchored onto the
Core funnel's `refuse` closure by the ratified qhe union), the 37 ratified qhe rows (with
`q04` and `q22` re-anchored onto the strengthened pointer-AND-capacity assertion), and the
four rows that harness owned (`q38`, `q39`, `q40`, `q41`). They were promoted mechanically,
never transcribed: the promoter imported the harness and serialized what it returned.

Row state is one of exactly two values.

  * `ACTIVE` — the definition runs as written against the current tracked bytes.
  * `REANCHORED_FROM=<origin>` — the prior exact definition no longer occurs exactly once,
    or no longer compiles, because the property it names genuinely moved under M4-SA's
    production edits. The prior definition is recorded verbatim in `prior`, and `origin`
    names the ignored artifact that definition came from. A purported re-anchor whose
    prior and active definitions are byte-identical is a STOP, and [`verify`] refuses it.

`SUPERSEDED_BY` is deliberately absent: M4-C owns the first real superseded dormancy row,
and speculative status machinery does not belong here.

Git object identity, the recorded source hashes and the verbatim prior definitions own
provenance. There is deliberately no second self-hash of this data inside this file.

Run it to verify itself:

    python3 crates/vault-cli/tests/evidence/m4_mutation_rows.py verify
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]

# (path relative to the read-only source worktree, sha256 of the bytes actually promoted)
SOURCES = [
    ('.rb-lite/runs/20260826T144314Z-qhe-final-byte-r6/qhe-final-red-first.py', '42cc4118ff046311b9473b3a89a9b4f62ab50370e6120de62af9eb834792cd33'),
    ('.rb-lite/runs/20260826T0553Z-qhe-union-final/qhe-red-first.py', '48dfe8ea64b0a73844dd2ff823a46748ca64bc4d58f7a6e669f7db30d6c9ea61'),
    ('.rb-lite/runs/20260825T1932Z-m3b-zero-final/red-first.py', 'bd3e0badfbbe931b8057e62f31136085b255aa12ff0680f74b9aefafc4c1fc8b'),
]

# The 91 rows M4-SA inherited: 50 M3 plus 41 qhe, promoted mechanically from the
# sources above. Keys: the row id, its state, the file it edits, its edits IN
# ORDER, the focused unpiped argv command, the test filter, and the diagnostic the
# RED run must print. The same command and filter are the restored-green control.
# Optional `independent=True` instead applies each edit separately to the original
# bytes, requiring one red run per edit rather than one combined ordered mutation.
INHERITED = [
    {
        "id": 'm01-mempool-spent-coin-silently-excluded',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    let coins = sorted_unique(scan.coins, vault_spk)?;',
                '    let mut coins = sorted_unique(scan.coins, vault_spk)?;\n    coins.retain(|coin| core.txout(coin.outpoint).ok().flatten().is_some());',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::a_mempool_spent_scanned_coin',
        "needle": 'at the opening read must be refused',
    },
    {
        "id": 'm03-feerate-truncated-instead-of-ceiled',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    let sat_vb = sat_kvb.div_ceil(1000);',
                '    let sat_vb = sat_kvb / 1000;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_primary_rate_is_the_estimate',
        "needle": 'primary Some(2001)',
    },
    {
        "id": 'm04-full-prevtx-projection-drops-the-second-psbt-set',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '.and_then(|size| size.checked_mul(2 * members.len() as u64))',
                '.and_then(|size| size.checked_mul(members.len() as u64))',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_projected_full_prevtx_bytes',
        "needle": 'a fifth candidate on one parent must be refused',
    },
    {
        "id": 'm05-projection-cap-not-enforced',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '        if bytes > MAX_COMPOSER_FULL_PREVTX_BYTES {\n            return bad(format!(',
                '        if bytes > MAX_COMPOSER_FULL_PREVTX_BYTES && false {\n            return bad(format!(',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_projected_full_prevtx_bytes',
        "needle": 'must be refused',
    },
    {
        "id": 'm06-vsize-preflight-moved-after-the-candidate-rpcs',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    let primary_vsize = finalized_vsize(weight, &primary.unsigned_tx)?;\n    let escape_vsize = finalized_vsize(weight, &escape.unsigned_tx)?;\n\n    let held = candidates(core, &coins, &mut tips)?;',
                '    let held = candidates(core, &coins, &mut tips)?;\n    let primary_vsize = finalized_vsize(weight, &primary.unsigned_tx)?;\n    let escape_vsize = finalized_vsize(weight, &escape.unsigned_tx)?;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_hundred_thousand_vbyte_bound',
        "needle": 'no candidate or parent RPC',
    },
    {
        "id": 'm07-held-contradiction-retried-without-tip-movement',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    match held {\n        Err(stable) => bad(stable),',
                '    match held {\n        Err(_) => Ok(None),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::only_observed_tip_movement',
        "needle": 'a null opening read must be refused',
    },
    {
        "id": 'm08-tip-movement-made-terminal-instead-of-retryable',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    if tips.iter().any(|tip| *tip != before) {\n        return Ok(None);\n    }',
                '    if tips.iter().any(|tip| *tip != before) {\n        return bad("the tip moved".into());\n    }',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::three_passes_recover',
        "needle": 'the view must prepare',
    },
    {
        "id": 'm10-closing-candidate-read-dropped',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    // The CLOSING read of every selected candidate.\n    for (coin, opened) in coins.iter().zip(&opening) {',
                '    // The CLOSING read of every selected candidate.\n    for (coin, opened) in coins.iter().zip(&opening).take(0) {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::only_observed_tip_movement',
        "needle": 'a null closing read must be refused',
    },
    {
        "id": 'm11-chain-identity-check-dropped',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    vault_node::chain::verify_chain_identity(&info.identity, network)\n        .map_err(|_| format!("this Core is not the sealed {sealed}; its own text is withheld"))?;',
                '    let _ = (&info.identity, network, sealed);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_sealed_network_is_bound',
        "needle": 'must be refused',
    },
    {
        "id": 'm12-initial-block-download-check-dropped',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    if info.initial_block_download {',
                '    if false && info.initial_block_download {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::only_observed_tip_movement',
        "needle": 'initial block download',
    },
    {
        "id": 'm13-null-result-accepted-for-every-method',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '        (None, None) => match absent {\n            Absent::NullResult if status == 200 && has_result => Ok(Value::Null),',
                '        (None, None) => match absent {\n            _ if status == 200 && has_result => Ok(Value::Null),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::each_absence_is_answered',
        "needle": 'a null result is no generic success',
    },
    {
        "id": 'm14-fixed-request-id-echo-not-required',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '    if reply.get("id").and_then(Value::as_str) != Some(RPC_ID) {\n        return Err(refuse("the reply does not echo this request\'s id".into()));\n    }',
                '',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::every_logical_envelope_defect',
        "needle": 'a foreign id must be refused',
    },
    {
        "id": 'm15-cookie-cached-at-construction',
        "state": 'REANCHORED_FROM=20260825T1932Z-m3b-zero-final/red-first.py',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '        let read = crate::sealed::read_core_cookie(&self.cookie)?;',
                '        let read = crate::sealed::read_core_cookie(&self.cookie)\n            .unwrap_or_else(|_| zeroize::Zeroizing::new(String::from("__cookie__:stale")));',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_cookie_is_read_per_call',
        "needle": 'a removed cookie stops the next call',
        "prior": {
            "file": 'crates/vault-cli/src/core_view.rs',
            "edits": [
                [
                    '        let read = crate::sealed::read_secret(&self.cookie)?;',
                    '        let read = crate::sealed::read_secret(&self.cookie)\n            .unwrap_or_else(|_| zeroize::Zeroizing::new(String::from("__cookie__:stale")));',
                ],
            ],
            "command": [
                'cargo',
                'test',
                '--locked',
                '-p',
                'vault-cli',
                '--bin',
                'btc-vault',
            ],
            "filter": 'core_view::tests::the_cookie_is_read_per_call',
            "needle": 'a removed cookie stops the next call',
        },
    },
    {
        "id": 'm16-loopback-requirement-dropped',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '        if !addr.ip().is_loopback() {',
                '        if false && !addr.ip().is_loopback() {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::a_non_loopback_core_address',
        "needle": 'a routable Core address must be refused',
    },
    {
        "id": 'm17-crlf-free-basic-auth-check-dropped',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                "        if credential.contains(['\\r', '\\n']) {",
                "        if false && credential.contains(['\\r', '\\n']) {",
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_cookie_is_read_per_call',
        "needle": 'a CR/LF cookie reached the wire',
    },
    {
        "id": 'm18-btc-amounts-hand-multiplied-instead-of-checked',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '    Amount::from_btc(btc).map_err(|e| missing(&format!("{what} is not a usable amount: {e}")))',
                '    Ok(Amount::from_sat((btc * 100_000_000.0) as u64))',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::core_btc_numbers_convert',
        "needle": 'must fail',
    },
    {
        "id": 'm19-coinbase-maturity-check-dropped',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '        if view.coinbase && view.confirmations < COINBASE_MATURITY {',
                '        if false && view.coinbase && view.confirmations < COINBASE_MATURITY {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::full_parents_are_block_qualified',
        "needle": 'a 99-confirmation coinbase must be refused',
    },
    {
        "id": 'm20-parent-txid-not-recomputed',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '        if parent.compute_txid() != txid {',
                '        if false && parent.compute_txid() != txid {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::full_parents_are_block_qualified',
        "needle": 'must be refused',
    },
    {
        "id": 'm23-scan-order-kept-instead-of-canonical-order',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    coins.sort_by_key(|coin| coin.outpoint);',
                '    let _ = &mut coins;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_scan_order_never_reaches_the_pair',
        "needle": 'scan order leaked',
    },
    {
        "id": 'm24-duplicate-scan-record-admitted',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '        .any(|pair| pair[0].outpoint == pair[1].outpoint)',
                '        .any(|pair| pair[0].outpoint != pair[0].outpoint)',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_scan_order_never_reaches_the_pair',
        "needle": 'a duplicate scan record must be refused',
    },
    {
        "id": 'm26-reused-helper-sequence-field-mutated',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/fed.rs',
        "edits": [
            [
                '                sequence: Sequence::MAX,\n                witness: Witness::new(),\n            })\n            .collect(),',
                '                sequence: Sequence::from_consensus(ESCAPE_RBF_SEQUENCE),\n                witness: Witness::new(),\n            })\n            .collect(),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::',
        "needle": 'pinned version 2, lock 0, final unsigned',
    },
    {
        "id": 'm29-live-coinbase-maturity-check-dropped',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '        if view.coinbase && view.confirmations < COINBASE_MATURITY {',
                '        if false && view.coinbase && view.confirmations < COINBASE_MATURITY {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": '--ignored --test-threads=1 a_coinbase_vault_coin',
        "needle": 'a 99-confirmation coinbase must be refused',
    },
    {
        "id": 'm30-transport-failure-does-not-name-its-exchange',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '        let refuse = |what: String| -> Error { format!("core {method}: {what}").into() };',
                '        let refuse = |what: String| -> Error { what.into() };',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::a_transport_failure_names',
        "needle": 'a transport failure did not name its exchange',
    },
    {
        "id": 'm31-scan-tip-binding-deferred-past-the-stable-set-refusals',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                "    // Step 2 binds the scan's OWN tip HERE, ahead of the stable-set refusals below, so a\n    // set read across a reorg is retried rather than refused as though the chain had held\n    // still. Movement observed LATER outranks the HELD contradictions alone, at the closing\n    // tip; the classes the bead pins terminal — immaturity, size, projection — stay terminal.\n    if scan.best_block != before {\n        return Ok(None);\n    }\n    let mut tips = Vec::new();",
                '    let mut tips = vec![scan.best_block];',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_scan_order_never_reaches_the_pair',
        "needle": 'must be retried, not refused',
    },
    {
        "id": 'm32-projection-checked-after-the-fetch-loop',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '        if bytes > MAX_COMPOSER_FULL_PREVTX_BYTES {\n            return bad(format!(\n                "the selected coins project {bytes} gross full-prevtx bytes across both PSBT \\\n                 sets, over the {MAX_COMPOSER_FULL_PREVTX_BYTES} byte bound"\n            ));\n        }\n        projected = bytes;\n        if parent.compute_txid() != txid {\n            return Ok(Err("a fetched full transaction hashes elsewhere".into()));\n        }\n        for index in members {\n            let vout = coins[index].outpoint.vout as usize;\n            let agrees = parent.output.get(vout).is_some_and(|out| {\n                out.value == coins[index].value && out.script_pubkey == coins[index].script\n            });\n            if !agrees {\n                return Ok(Err(format!(\n                    "a fetched full transaction contradicts vout {vout}"\n                )));\n            }\n        }\n        // MOVED, never cloned: the only copy this bracket makes is the one\n        // [`CompletedInventory::full_parent`] hands out after acceptance.\n        parents.insert(txid, parent);\n    }',
                '        projected = bytes;\n        if parent.compute_txid() != txid {\n            return Ok(Err("a fetched full transaction hashes elsewhere".into()));\n        }\n        for index in members {\n            let vout = coins[index].outpoint.vout as usize;\n            let agrees = parent.output.get(vout).is_some_and(|out| {\n                out.value == coins[index].value && out.script_pubkey == coins[index].script\n            });\n            if !agrees {\n                return Ok(Err(format!(\n                    "a fetched full transaction contradicts vout {vout}"\n                )));\n            }\n        }\n        parents.insert(txid, parent);\n    }\n    if projected > MAX_COMPOSER_FULL_PREVTX_BYTES {\n        return bad(format!(\n            "the selected coins project {projected} gross full-prevtx bytes across both PSBT \\\n             sets, over the {MAX_COMPOSER_FULL_PREVTX_BYTES} byte bound"\n        ));\n    }',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::the_projected_full_prevtx_bytes',
        "needle": 'no later parent may be fetched',
    },
    {
        "id": 'm33-reused-helper-version-field-mutated',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/fed.rs',
        "edits": [
            [
                '        version: Version::TWO,',
                '        version: Version::ONE,',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::',
        "needle": 'pinned version 2, lock 0, final unsigned',
    },
    {
        "id": 'm34-reused-helper-locktime-field-mutated',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/fed.rs',
        "edits": [
            [
                '        lock_time: LockTime::ZERO,',
                '        lock_time: LockTime::from_consensus(1),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::',
        "needle": 'pinned version 2, lock 0, final unsigned',
    },
    {
        "id": 'm35-reused-helper-witness-field-mutated',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/fed.rs',
        "edits": [
            [
                '        psbt.inputs[index].witness_script = Some(witness_script.clone());',
                '        psbt.inputs[index].witness_script = Some(witness_script.clone());\n        psbt.unsigned_tx.input[index].witness = Witness::from_slice(&[[0u8; 1]]);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::',
        "needle": 'pinned version 2, lock 0, final unsigned',
    },
    {
        "id": 'm48-reused-helper-scriptsig-field-mutated',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/fed.rs',
        "edits": [
            [
                '        psbt.inputs[index].witness_utxo = Some(utxo.txout.clone());',
                '        psbt.inputs[index].witness_utxo = Some(utxo.txout.clone());\n        psbt.unsigned_tx.input[index].script_sig = ScriptBuf::from_bytes(vec![0x51]);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::',
        "needle": 'pinned version 2, lock 0, final unsigned',
    },
    {
        "id": 'm36-core-error-text-echoed-verbatim-again',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '            _ => Err(refuse(format!("refused: code {coded:?}"))),',
                '            _ => Err(refuse(format!("refused: {:?}", reply.get("error")))),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_cookie_is_read_per_call',
        "needle": 'put the credential in the diagnostic',
    },
    {
        "id": 'm37-coded-absence-accepted-under-a-200',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '            Absent::Code(code) if status != 200 && coded == Some(code) => Ok(Value::Null),',
                '            Absent::Code(code) if coded == Some(code) => Ok(Value::Null),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::each_absence_is_answered',
        "needle": 'under a 200 must be refused',
    },
    {
        "id": 'm38-missing-result-member-read-as-the-declared-null',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '    let has_result = reply.get("result").is_some();',
                '    let has_result = true;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::each_absence_is_answered',
        "needle": 'no result member is no declared absence',
    },
    {
        "id": 'm39-redaction-swallows-the-numeric-code-too',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '            _ => Err(refuse(format!("refused: code {coded:?}"))),',
                '            _ => Err(refuse("refused".to_string())),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_cookie_is_read_per_call',
        "needle": 'redaction must not cost the numeric code',
    },
    {
        "id": 'm40-over-precise-rate-rounded-instead-of-refused',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '    Amount::from_btc(btc).map_err',
                '    Amount::from_btc((btc * 100_000_000.0).round() / 100_000_000.0).map_err',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_measured_f64_sub_resolution_lexical_residual',
        "needle": '0.000000001 must be refused',
    },
    {
        "id": 'm41-gettxout-coinbase-flag-defaulted-instead-of-required',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '            coinbase: view\n                .get("coinbase")\n                .and_then(Value::as_bool)\n                .ok_or_else(|| missing("gettxout has no boolean coinbase"))?,',
                '            coinbase: view.get("coinbase").and_then(Value::as_bool).unwrap_or(false),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::every_typed_decoder_refuses_a_malformed_payload',
        "needle": 'no coinbase flag must be refused',
    },
    {
        "id": 'm42-scantxoutset-success-gate-dropped',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '        if scan.get("success").and_then(Value::as_bool) != Some(true) {',
                '        if false {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::every_typed_decoder_refuses_a_malformed_payload',
        "needle": 'a scan that did not succeed must be refused',
    },
    {
        "id": 'm43-any-error-code-read-as-the-declared-absence',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '            Absent::Code(code) if status != 200 && coded == Some(code) => Ok(Value::Null),',
                '            Absent::Code(_) if status != 200 && coded.is_some() => Ok(Value::Null),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::pruned_block_data_is_terminal',
        "needle": 'missing block data must be refused',
    },
    {
        "id": 'm44-non-object-estimate-result-accepted',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '        let estimate = estimate\n            .as_object()\n            .ok_or_else(|| missing("estimatesmartfee is not an object"))?;',
                '        let empty = serde_json::Map::new();\n        let estimate = estimate.as_object().unwrap_or(&empty);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::core_btc_numbers_convert',
        "needle": 'an array result must be refused',
    },
    {
        "id": 'm45-full-parent-cloned-during-the-fetch',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '        // MOVED, never cloned: the only copy this bracket makes is the one\n        // [`CompletedInventory::full_parent`] hands out after acceptance.\n        parents.insert(txid, parent);',
                '        parents.insert(txid, clone_full_parent(&parent));',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::full_parent_clones_',
        "needle": 'no full parent may be cloned before the projection completes',
    },
    {
        "id": 'm46-gettxout-stops-asking-about-the-mempool',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '        let params = json!([outpoint.txid.to_string(), outpoint.vout, true]);',
                '        let params = json!([outpoint.txid.to_string(), outpoint.vout, false]);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_seam_issues_exactly_the_eight_closed_reads',
        "needle": 'gettxout must ask WITH the mempool',
    },
    {
        "id": 'm47-fee-signals-read-before-the-bracket',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    let mut accepted = None;\n    for _ in 0..INVENTORY_PASSES {\n        accepted = pass(core, network, &witness_script, &canonical, weight)?;\n        if accepted.is_some() {\n            break;\n        }\n    }\n    let Some(bracket) = accepted else {\n        return bad(format!(\n            "the Core view did not hold still for {INVENTORY_PASSES} passes: the tip moved \\\n             during every inventory bracket"\n        ));\n    };\n\n    // The fee signals are a LIVENESS snapshot taken after the accepted bracket and its\n    // completed projection, not part of the coin-consistency proof: later floor movement\n    // can make the pair slow or non-relaying, never redirect value.\n    let estimate = core.fee_estimate()?;\n    let floors = core.fee_floors()?;',
                '    let early_estimate = core.fee_estimate();\n    let early_floors = core.fee_floors();\n    let mut accepted = None;\n    for _ in 0..INVENTORY_PASSES {\n        accepted = pass(core, network, &witness_script, &canonical, weight)?;\n        if accepted.is_some() {\n            break;\n        }\n    }\n    let Some(bracket) = accepted else {\n        return bad(format!(\n            "the Core view did not hold still for {INVENTORY_PASSES} passes: the tip moved \\\n             during every inventory bracket"\n        ));\n    };\n\n    let estimate = early_estimate?;\n    let floors = early_floors?;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::a_broken_fee_signal_is_terminal',
        "needle": 'the fee reads follow the whole bracket',
    },
    {
        "id": 'm49-identity-refusal-echoes-the-peers-own-chain-text',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    vault_node::chain::verify_chain_identity(&info.identity, network)\n        .map_err(|_| format!("this Core is not the sealed {sealed}; its own text is withheld"))?;',
                '    let _ = sealed;\n    vault_node::chain::verify_chain_identity(&info.identity, network)?;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'inventory::tests::a_reflected_credential',
        "needle": 'reflected the credential into the diagnostic',
    },
    {
        "id": 'm50-duplicate-scan-refusal-echoes-the-peers-own-outpoint',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/inventory.rs',
        "edits": [
            [
                '    if coins\n        .windows(2)\n        .any(|pair| pair[0].outpoint == pair[1].outpoint)\n    {\n        return bad("scantxoutset reported one outpoint twice".into());\n    }',
                '    if let Some(pair) = coins\n        .windows(2)\n        .find(|pair| pair[0].outpoint == pair[1].outpoint)\n    {\n        return bad(format!("scantxoutset reported {} twice", pair[0].outpoint));\n    }',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'a_hostile_core_cannot_reflect',
        "needle": 'reflected the credential into the diagnostic',
    },
    {
        "id": 'm02-sealed-escape-floor-max-bypassed',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/compose.rs',
        "edits": [
            [
                '    let escape_rate = rate.max(vault.escape_feerate_floor);',
                '    let escape_rate = rate;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'the_sealed_escape_floor_maxes_the_primary_rate',
        "needle": 'escape fee Some(1000)/1000/9',
    },
    {
        "id": 'm09-coverage-equality-refused-instead-of-passing',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/compose.rs',
        "edits": [
            [
                '    if covered < required {',
                '    if covered <= required {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'the_sealed_coverage_percentage_passes_at_equality',
        "needle": 'the composition must succeed',
    },
    {
        "id": 'm21-explicit-sighash-all-omitted',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/compose.rs',
        "edits": [
            [
                '            psbt.inputs[index].sighash_type = Some(EcdsaSighashType::All.into());',
                '            let _ = EcdsaSighashType::All;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'the_composed_pair_carries_every_full_parent',
        "needle": 'must declare SIGHASH_ALL explicitly',
    },
    {
        "id": 'm22-verified-full-parent-not-attached',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/compose.rs',
        "edits": [
            [
                '            psbt.inputs[index].non_witness_utxo = Some(parent);',
                '            let _ = parent;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'the_composed_pair_carries_every_full_parent',
        "needle": 'has no full previous transaction',
    },
    {
        "id": 'm25-mandatory-change-dust-check-bypassed',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/compose.rs',
        "edits": [
            [
                '    let values = [amount, change_value, sweep];',
                '    let values = [amount, Amount::MAX, sweep];',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'each_of_the_three_outputs_clears_its_own_script_dust_minimum',
        "needle": 'dust vault change must be refused',
    },
    {
        "id": 'm27-final-hot-escape-verdict-bypassed',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/compose.rs',
        "edits": [
            [
                '        if class != expected {',
                '        if false && class != expected {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'a_foreign_network_refuses_before_core',
        "needle": 'an escape primary must be refused',
    },
    {
        "id": 'm28-require-network-bypassed',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/compose.rs',
        "edits": [
            [
                '    let destination = parsed\n        .require_network(network)\n        .map_err(|_| format!("that is not an address on the sealed {network} network"))?\n        .script_pubkey();',
                '    let destination = parsed.assume_checked().script_pubkey();',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'a_foreign_network_refuses_before_core',
        "needle": 'a foreign-network address must be refused',
    },
    {
        "id": 'q01-deadline-restarted-at-every-phase',
        "state": 'REANCHORED_FROM=20260826T0553Z-qhe-union-final/qhe-red-first.py',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let left = || match deadline.checked_duration_since(now()) {\n        Some(left) if !left.is_zero() => Some(left),\n        _ => None,\n    };',
                '    let left = || Some(CONNECT_CEILING);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_bounded_deadline_starts_before_connect',
        "needle": 'must not connect',
        "prior": {
            "file": 'crates/vault-cli/src/http.rs',
            "edits": [
                [
                    '    let left = || match budget.checked_sub(now().saturating_duration_since(start)) {\n        Some(left) if !left.is_zero() => Some(left),\n        _ => None,\n    };',
                    '    let left = || Some(budget);',
                ],
            ],
            "command": [
                'cargo',
                'test',
                '--locked',
                '-p',
                'vault-cli',
                '--bin',
                'btc-vault',
            ],
            "filter": 'http::tests::the_bounded_deadline_starts_before_connect',
            "needle": 'must not connect',
        },
    },
    {
        "id": 'q02-deadline-does-not-cover-connect',
        "state": 'REANCHORED_FROM=20260826T0553Z-qhe-union-final/qhe-red-first.py',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let Some(first) = left() else {\n        return Attempt::NotSent(format!("connect {addr}: the deadline expired first").into());\n    };',
                '    let first = CONNECT_CEILING;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_bounded_deadline_starts_before_connect',
        "needle": 'an expired deadline must not connect',
        "prior": {
            "file": 'crates/vault-cli/src/http.rs',
            "edits": [
                [
                    '    let Some(first) = left() else {\n        return Attempt::NotSent(format!("connect {addr}: the deadline expired first").into());\n    };',
                    '    let first = budget;',
                ],
            ],
            "command": [
                'cargo',
                'test',
                '--locked',
                '-p',
                'vault-cli',
                '--bin',
                'btc-vault',
            ],
            "filter": 'http::tests::the_bounded_deadline_starts_before_connect',
            "needle": 'an expired deadline must not connect',
        },
    },
    {
        "id": 'q03-cap-truncates-instead-of-refusing',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        if filled == raw.len() {\n            break Err(format!("response from {addr} is over its {cap}-byte cap"));\n        }',
                '',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_whole_raw_response_is_capped',
        "needle": 'not a shorter response',
    },
    {
        "id": 'q04-cap-plus-one-detection-off-by-one',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let mut raw = Zeroizing::new(vec![0u8; cap + 1]);',
                '    let mut raw = Zeroizing::new(vec![0u8; cap]);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_whole_raw_response_is_capped',
        "needle": 'the bounded response allocation must never move or grow',
    },
    {
        "id": 'q05-parseable-prefix-accepted-as-completion',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        match stream.read(&mut raw[filled..]) {',
                '        if position(&raw[..filled], b"\\r\\n\\r\\n").is_some() {\n            break Ok(());\n        }\n        match stream.read(&mut raw[filled..]) {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::a_peer_that_answers_fully_and_holds_open',
        "needle": 'not a complete response',
    },
    {
        "id": 'q06-bounded-status-parsed-loosely',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let status = strict_status(raw).ok_or_else(|| bad("its status line is not strict HTTP/1.x"))?;',
                '    let status = status_of(raw).ok_or_else(|| bad("its status line is not strict HTTP/1.x"))?;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::only_a_strict_http_1_0_or_1_1_status_line_is_a_status',
        "needle": 'must decide nothing',
    },
    {
        "id": 'q07-status-code-range-not-checked',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    (100..=599).contains(&code).then_some(code)',
                '    Some(code)',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::only_a_strict_http_1_0_or_1_1_status_line_is_a_status',
        "needle": 'is not a status',
    },
    {
        "id": 'q08-transfer-encoding-accepted',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        if name.eq_ignore_ascii_case(b"transfer-encoding") {',
                '        if false && name.eq_ignore_ascii_case(b"transfer-encoding") {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_header_content_length_and_transfer_encoding_defect',
        "needle": 'must keep its status and drop its body',
    },
    {
        "id": 'q09-header-names-matched-case-sensitively',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        if name.eq_ignore_ascii_case(b"transfer-encoding") {',
                '        if name == b"Transfer-Encoding" {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_header_content_length_and_transfer_encoding_defect',
        "needle": 'a lower-case transfer-encoding beside a valid length',
    },
    {
        "id": 'q10-duplicate-content-length-admitted',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            if declared.is_some() {\n                return Err(bad("it carries more than one Content-Length"));\n            }',
                '',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_header_content_length_and_transfer_encoding_defect',
        "needle": 'two equal Content-Lengths',
    },
    {
        "id": 'q11-declared-length-not-matched-against-the-body',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    if declared.is_some_and(|declared| declared != body.len()) {',
                '    if false && declared.is_some_and(|declared| declared != body.len()) {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_header_content_length_and_transfer_encoding_defect',
        "needle": 'a Content-Length under the body',
    },
    {
        "id": 'q12-content-length-parsed-permissively',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {\n        return None;\n    }',
                '',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_header_content_length_and_transfer_encoding_defect',
        "needle": 'a signed Content-Length',
    },
    {
        "id": 'q13-header-line-syntax-not-validated',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        if name.is_empty() || !name.iter().all(|byte| is_token(*byte)) {',
                '        if false && (name.is_empty() || !name.iter().all(|byte| is_token(*byte))) {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_header_content_length_and_transfer_encoding_defect',
        "needle": 'whitespace before the colon',
    },
    {
        "id": 'q14-post-connect-timeout-classified-not-sent',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        let Some(left) = left() else {\n            return no_status(format!("write request to {addr}: the deadline expired"));\n        };',
                '        let Some(left) = left() else {\n            return Err(Attempt::NotSent(\n                format!("write request to {addr}: the deadline expired").into(),\n            ));\n        };',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::a_deadline_spent_after_connect_is_no_status',
        "needle": 'never NotSent',
    },
    {
        "id": 'q15-credential-header-formatted-into-an-ordinary-string',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        pieces.push(b"Authorization: Basic ");\n        pieces.push(credentials.as_bytes());\n        pieces.push(b"\\r\\n");',
                '        let header = format!("Authorization: Basic {credentials}\\r\\n");\n        pieces.push(Box::leak(header.into_boxed_str()).as_bytes());',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::one_exactly_reserved_zeroizing_allocation',
        "needle": 'never formatted',
    },
    {
        "id": 'q16-request-allocation-not-reserved',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let mut request = Zeroizing::new(Vec::with_capacity(capacity));',
                '    let mut request = Zeroizing::new(Vec::new());',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::one_exactly_reserved_zeroizing_allocation',
        "needle": 'exactly reserved and never move',
    },
    {
        "id": 'q17-ingress-put-back-on-the-legacy-transport',
        "state": 'REANCHORED_FROM=20260826T0553Z-qhe-union-final/qhe-red-first.py',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '    http::post_attempt(addr, "/sign", body, None, http::Policy::ingress(deadline))',
                '    http::post_attempt(addr, "/sign", body, None, http::Policy::Legacy(PER_ENDPOINT))',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::a_dripping_first_endpoint_costs_one_aggregate',
        "needle": 'one deadline, not its own patience',
        "prior": {
            "file": 'crates/vault-cli/src/ingress.rs',
            "edits": [
                [
                    '        let attempt =\n            http::post_attempt(*addr, "/sign", &body, None, http::Policy::ingress(timeout));',
                    '        let attempt =\n            http::post_attempt(*addr, "/sign", &body, None, http::Policy::Legacy(timeout));',
                ],
            ],
            "command": [
                'cargo',
                'test',
                '--locked',
                '-p',
                'vault-cli',
                '--bin',
                'btc-vault',
            ],
            "filter": 'ingress::tests::a_dripping_first_endpoint_cannot_suppress',
            "needle": 'one deadline, not its own patience',
        },
    },
    {
        "id": 'q18-peer-commitment-string-retained',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '                    })) if commitment_id == expected_commitment_id => {',
                '                    })) => {\n                        let expected_commitment_id = commitment_id;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::no_peer_chosen_text_survives',
        "needle": "the retained id must be the caller's own",
    },
    {
        "id": 'q19-core-reply-decoded-lossily',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '        let text = std::str::from_utf8(&bytes)\n            .map_err(|e| refuse(format!("the reply is not UTF-8: {e}")))?;',
                '        let text = &String::from_utf8_lossy(&bytes).into_owned();',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_core_funnel_decodes_strictly',
        "needle": 'refused at the transport',
    },
    {
        "id": 'q20-core-policy-not-derived-from-the-method',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '            http::Policy::core(method),',
                '            http::Policy::core("scantxoutset"),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_one_funnel_selects_its_policy_from_the_method',
        "needle": 'must be derived from the method',
    },
    {
        "id": 'q21-terminal-eof-not-rechecked-against-the-deadline',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            Ok(0) if left().is_none() => {\n                break Err(format!("response from {addr}: the deadline expired"))\n            }\n            Ok(0) => break Ok(()),',
                '            Ok(0) => break Ok(()),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::an_eof_observed_after_the_deadline_is_not_a_completed_response',
        "needle": 'not completion inside it',
    },
    {
        "id": 'q22-cap-allows-the-head-its-own-slack',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let mut raw = Zeroizing::new(vec![0u8; cap + 1]);',
                '    let mut raw = Zeroizing::new(vec![0u8; cap + 1 + 4096]);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_cap_counts_the_headers_and_not_only_the_body',
        "needle": 'the bounded response allocation must never move or grow',
    },
    {
        "id": 'q23-bounded-response-buffer-grows-instead-of-refusing',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        if filled == raw.len() {\n            break Err(format!("response from {addr} is over its {cap}-byte cap"));\n        }',
                '        if filled == raw.len() {\n            let grown = raw.len() * 2;\n            raw.resize(grown, 0);\n        }',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_whole_raw_response_is_capped',
        "needle": 'the bounded response allocation must never move',
    },
    {
        "id": 'q24-core-funnel-put-back-on-the-legacy-transport',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/core_view.rs',
        "edits": [
            [
                '            http::Policy::core(method),',
                '            http::Policy::Legacy(std::time::Duration::from_secs(600)),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_core_funnel_decodes_strictly',
        "needle": 'a chunked reply must be refused',
    },
    {
        "id": 'q25-scan-deadline-given-to-every-core-method',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            _ => CORE_DEADLINE,',
                '            _ => CORE_SCAN_DEADLINE,',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_policy_is_the_one_its_caller_was_given',
        "needle": 'getblockchaininfo',
    },
    {
        "id": 'q26-scantxoutset-demoted-to-the-ordinary-core-deadline',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            "scantxoutset" => CORE_SCAN_DEADLINE,',
                '            "scantxoutset" => CORE_DEADLINE,',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_policy_is_the_one_its_caller_was_given',
        "needle": 'scantxoutset is the ONE long Core deadline',
    },
    {
        "id": 'q27-core-cap-loosened-past-16-mib',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            cap: CORE_CAP,',
                '            cap: 4 * CORE_CAP,',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'core_view::tests::the_core_funnel_decodes_strictly',
        "needle": 'must be refused BY THE CAP',
    },
    {
        "id": 'q28-legacy-callers-switched-to-the-bounded-policy',
        "state": 'REANCHORED_FROM=20260826T0553Z-qhe-union-final/qhe-red-first.py',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        Policy::Legacy(timeout) => legacy(addr, request, timeout),',
                '        Policy::Legacy(timeout) => bounded(addr, request, Instant::now() + timeout, INGRESS_CAP, &Instant::now),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'fed::tests::the_readiness_probe_still_reads_a_slow_node_to_close',
        "needle": 'still a serving node',
        "prior": {
            "file": 'crates/vault-cli/src/http.rs',
            "edits": [
                [
                    '        Policy::Legacy(timeout) => legacy(addr, request, timeout),',
                    '        Policy::Legacy(timeout) => bounded(addr, request, timeout, INGRESS_CAP, &Instant::now),',
                ],
            ],
            "command": [
                'cargo',
                'test',
                '--locked',
                '-p',
                'vault-cli',
                '--bin',
                'btc-vault',
            ],
            "filter": 'fed::tests::the_readiness_probe_still_reads_a_slow_node_to_close',
            "needle": 'still a serving node',
        },
    },
    {
        "id": 'q29-ingress-cap-loosened-past-64-kib',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            cap: INGRESS_CAP,',
                '            cap: CORE_CAP,',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::the_sticky_disposition_follows_the_typed_transport_phases',
        "needle": 'a 200 past the 64 KiB cap: payload',
    },
    {
        "id": 'q30-zero-progress-write-classified-not-sent',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            Ok(0) => return no_status(format!("write request to {addr}: no progress")),',
                '            Ok(0) => return Err(Attempt::NotSent(format!("write request to {addr}: no progress").into())),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_write_loop_outcome_including_zero_progress_is_never_not_sent',
        "needle": 'claimed reissue authority',
    },
    {
        "id": 'q31-interrupted-write-reported-instead-of-retried',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            Err(e) if e.kind() == ErrorKind::Interrupted => continue,\n            Err(e) => return no_status(format!("write request to {addr}: {e}")),',
                '            Err(e) => return no_status(format!("write request to {addr}: {e}")),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_write_loop_outcome_including_zero_progress_is_never_not_sent',
        "needle": 'an interrupted write is retried, not reported',
    },
    {
        "id": 'q32-partial-write-treated-as-a-whole-one',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            Ok(bytes) => written += bytes,',
                '            Ok(_) => written = request.len(),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_write_loop_outcome_including_zero_progress_is_never_not_sent',
        "needle": 'the whole request, written once',
    },
    {
        "id": 'q33-legacy-malformed-status-diagnostic-collapsed',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '            Ok(_) if separator.is_some() => {\n                format!("malformed HTTP status line from {addr}").into()\n            }\n            Ok(_) => format!("malformed HTTP response from {addr}").into(),',
                '            Ok(_) => format!("malformed HTTP response from {addr}").into(),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::legacy_names_a_malformed_status_line_apart_from_a_malformed_response',
        "needle": 'is a STATUS-LINE defect',
    },
    {
        "id": 'q34-read-loop-restarts-the-budget-for-every-read',
        "state": 'REANCHORED_FROM=20260826T0553Z-qhe-union-final/qhe-red-first.py',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '        let Some(wait) = left() else {\n            break Err(format!("response from {addr}: the deadline expired"));\n        };',
                '        let wait = CONNECT_CEILING;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_deadline_covers_the_status_header_and_body_reads_alike',
        "needle": 'a deadline spent before a strict status line decides nothing',
        "prior": {
            "file": 'crates/vault-cli/src/http.rs',
            "edits": [
                [
                    '        let Some(wait) = left() else {\n            break Err(format!("response from {addr}: the deadline expired"));\n        };',
                    '        let wait = budget;',
                ],
            ],
            "command": [
                'cargo',
                'test',
                '--locked',
                '-p',
                'vault-cli',
                '--bin',
                'btc-vault',
            ],
            "filter": 'http::tests::the_deadline_covers_the_status_header_and_body_reads_alike',
            "needle": 'a deadline spent before a strict status line decides nothing',
        },
    },
    {
        "id": 'q35-borrowed-answer-drifts-from-the-protocol-wire-shape',
        "state": 'ACTIVE',
        "file": 'crates/vault-proto/src/lib.rs',
        "edits": [
            [
                '    #[serde(rename = "accepted")]\n    Accepted(Accepted),',
                '    #[serde(rename = "accepted_v2")]\n    Accepted(Accepted),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::borrowed_answer_stays_in_lockstep_with_the_protocol_wire_shape',
        "needle": 'borrowed answer must decode protocol acceptance',
    },
    {
        "id": 'q36-head-crlf-rule-admits-a-lone-cr',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                "        b'\\r' => head.get(at + 1) != Some(&b'\\n'),\n",
                '',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_header_content_length_and_transfer_encoding_defect',
        "needle": 'a status line ended with a bare CR, hiding a Transfer-Encoding',
    },
    {
        "id": 'q37-head-crlf-rule-admits-a-lone-lf',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                "        b'\\n' => at == 0 || head[at - 1] != b'\\r',\n",
                '',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::every_header_content_length_and_transfer_encoding_defect',
        "needle": 'a status line ended with a bare LF, hiding a Transfer-Encoding',
    },
    {
        "id": 'q38-bounded-response-buffer-grown-by-a-push-before-the-assertion',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    // Both halves, because a pointer alone is not the invariant: `realloc` on an\n',
                '    raw.push(0);\n    // Both halves, because a pointer alone is not the invariant: `realloc` on an\n',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_whole_raw_response_is_capped',
        "needle": 'the bounded response allocation must never move or grow',
    },
    {
        "id": 'q39-bounded-response-capacity-over-allocated-with-a-stable-pointer',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let mut raw = Zeroizing::new(vec![0u8; cap + 1]);\n',
                '    let mut raw = Zeroizing::new(Vec::<u8>::with_capacity(cap + 2));\n    raw.resize(cap + 1, 0u8);\n',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_whole_raw_response_is_capped',
        "needle": 'the bounded response allocation must never move or grow',
    },
    {
        "id": 'q40-cap-plus-one-detection-off-by-one-in-allocation-and-assertion',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let mut raw = Zeroizing::new(vec![0u8; cap + 1]);\n',
                '    let mut raw = Zeroizing::new(vec![0u8; cap]);\n',
            ],
            [
                '        (allocation, cap + 1),\n',
                '        (allocation, cap),\n',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_whole_raw_response_is_capped',
        "needle": 'and its whole body arrived',
    },
    {
        "id": 'q41-cap-allows-the-head-its-own-slack-in-allocation-and-assertion',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                '    let mut raw = Zeroizing::new(vec![0u8; cap + 1]);\n',
                '    let mut raw = Zeroizing::new(vec![0u8; cap + 1 + 4096]);\n',
            ],
            [
                '        (allocation, cap + 1),\n',
                '        (allocation, cap + 1 + 4096),\n',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'http::tests::the_cap_counts_the_headers_and_not_only_the_body',
        "needle": 'the cap covers the headers too',
    },
]

# The rows M4-SA owns. Each restores one behaviour that child introduced.
M4SA_OWNED = [
    {
        "id": 'M4-25-aggregate-deadline-rebuilt-from-a-remaining-duration',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '    let mut attempts = Vec::new();\n    for addr in endpoints {',
                '    let mut attempts = Vec::new();\n    let remaining = aggregate.saturating_duration_since(now());\n    for addr in endpoints {',
            ],
            [
                '        let deadline = now()\n            .checked_add(PER_ENDPOINT)\n            .unwrap_or(aggregate)\n            .min(aggregate);',
                '        let deadline = now() + remaining;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::every_endpoint_is_handed_the_minimum',
        "needle": 'each endpoint is handed min(now + 60s, aggregate), and no rebased duration',
    },
    {
        "id": 'M4-26-endpoint-handed-the-aggregate-instead-of-its-own-slice',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '        let deadline = now()\n            .checked_add(PER_ENDPOINT)\n            .unwrap_or(aggregate)\n            .min(aggregate);',
                '        let deadline = aggregate;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::every_endpoint_is_handed_the_minimum',
        "needle": 'each endpoint is handed min(now + 60s, aggregate), and no rebased duration',
    },
    {
        "id": 'M4-27-sticky-advancement-moved-below-status-decoding',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '        // A request byte may already have reached this node, so reissue authority ends\n        // HERE — before any status or body is decoded, and for 400 and 413 alike. Sticky:\n        // no arm below restores it.\n        if !matches!(attempt, Attempt::NotSent(_)) {\n            delivery = Delivery::PossiblyDeliveredExact;\n        }\n        match attempt {',
                '        match attempt {',
            ],
            [
                '            } => {\n                match answer.as_deref().map(|bytes| serde_json::from_slice(bytes)) {',
                '            } => {\n                delivery = Delivery::PossiblyDeliveredExact;\n                match answer.as_deref().map(|bytes| serde_json::from_slice(bytes)) {',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::the_sticky_disposition_follows_the_typed_transport_phases',
        "needle": 'connect refused, then a 400: disposition',
    },
    {
        "id": 'M4-28-a-first-413-suppresses-the-next-endpoint',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '            // No status, 400, 413 and every other status: each is already sticky above and\n            // decides nothing more, so 400 and 413 alike go on to the next endpoint.\n            _ => {}',
                '            Attempt::Status { status: 413, .. } => break,\n            _ => {}',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::the_sticky_disposition_follows_the_typed_transport_phases',
        "needle": 'a first 413 does not suppress the next: payload',
    },
    {
        "id": 'M4-29-replay-judged-after-its-own-attempt-advanced-the-state',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '                            && prior == Delivery::PossiblyDeliveredExact =>',
                '                            && delivery == Delivery::PossiblyDeliveredExact =>',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::the_sticky_disposition_follows_the_typed_transport_phases',
        "needle": 'a first-attempt replay continues: payload',
    },
    {
        "id": 'M4-47-core-cookie-returns-to-an-unbounded-read',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/sealed.rs',
        "edits": [
            [
                '    read_file(path, Some(MAX_CORE_COOKIE_BYTES))',
                '    read_file(path, None)',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'the_core_cookie_read_is_bounded_at_its_cap',
        "needle": 'cap + 1 must be refused',
    },
    {
        "id": 'M4SA-R01-replay-judged-on-a-parallel-state-excluding-a-400',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '        let prior = delivery;',
                '        let prior = match attempts.last() {\n            Some(EndpointFact { outcome: Outcome::Status(400), .. }) => Delivery::DefinitelyNotSent,\n            _ => delivery,\n        };',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::the_sticky_disposition_follows_the_typed_transport_phases',
        "needle": "a 400, then a peer's replay, stops: payload",
    },
    {
        "id": 'M4SA-R02-a-purported-re-anchor-is-byte-identical-to-its-active-definition',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/tests/evidence/m4_mutation_rows.py',
        "edits": [
            [
                '                    \'    let Some(first) = left() else {\\n        return Attempt::NotSent(format!("connect {addr}: the deadline expired first").into());\\n    };\',\n                    \'    let first = budget;\',',
                '                    \'    let Some(first) = left() else {\\n        return Attempt::NotSent(format!("connect {addr}: the deadline expired first").into());\\n    };\',\n                    \'    let first = CONNECT_CEILING;\',',
            ],
        ],
        "command": [
            'python3',
            'crates/vault-cli/tests/evidence/m4_mutation_rows.py',
        ],
        "filter": 'verify',
        "needle": 'the re-anchor is byte-identical to its active definition',
    },
    {
        "id": 'M4SA-R03-aggregate-ceiling-removed',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/ingress.rs',
        "edits": [
            [
                '        let deadline = now()\n            .checked_add(PER_ENDPOINT)\n            .unwrap_or(aggregate)\n            .min(aggregate);',
                '        let deadline = now()\n            .checked_add(PER_ENDPOINT)\n            .unwrap_or(aggregate);',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'ingress::tests::every_endpoint_is_handed_the_minimum',
        "needle": 'each endpoint is handed min(now + 60s, aggregate), and no rebased duration',
    },
]

# The rows M4-SBR owns. Each restores one behaviour that child introduces.
M4SB_OWNED = [
    {
        "id": 'M4-18-credential-authentication-returns-secret-authority',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/sealed.rs',
        "edits": [
            [
                '    pub(crate) fn authenticate_spend(',
                '    pub(crate) fn seckey(&self) -> SecretKey {\n        SecretKey::from_slice(self.seckey.as_slice()).expect("validated at load")\n    }\n    pub(crate) fn authenticate_spend(',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'sealed::tests::the_credential_authenticates_in_place',
        "needle": "the credential's public surface moved",
    },
    {
        "id": 'M4-20-direct-spend-bypasses-signature-and-policy-version-verification',
        "state": 'ACTIVE',
        "file": 'crates/vault-node/src/lib.rs',
        "edits": [
            [
                '    // The authenticated request must also name this node\'s baked-at-setup policy.\n    let claimed = request.policy_version();\n    if claimed != node.policy_version {\n        let configured = node.policy_version;\n        let detail =\n            format!("request policy_version {claimed} is not this node\'s configured {configured}");\n        let refused = refusal(RefusalCode::PsbtInconsistent, "policy_version", detail);\n        return Err(refused);\n    }\n    Ok(())',
                '    Ok(())',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-node',
            '--lib',
        ],
        "filter": 'policy_version_direct_routes::a_direct_spend_naming_another_policy_version',
        "needle": 'a spend for policy_version 2 must be refused',
    },
    {
        "id": 'M4-21-direct-refresh-bypasses-signature-and-policy-version-verification',
        "state": 'ACTIVE',
        "file": 'crates/vault-node/src/lib.rs',
        "edits": [
            [
                '    // The authenticated request must also name this node\'s baked-at-setup policy.\n    let claimed = request.policy_version();\n    if claimed != node.policy_version {\n        let configured = node.policy_version;\n        let detail =\n            format!("request policy_version {claimed} is not this node\'s configured {configured}");\n        let refused = refusal(RefusalCode::PsbtInconsistent, "policy_version", detail);\n        return Err(refused);\n    }\n    Ok(())',
                '    Ok(())',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-node',
            '--lib',
        ],
        "filter": 'policy_version_direct_routes::a_direct_refresh_naming_another_policy_version',
        "needle": 'a refresh for policy_version 2 must be refused',
    },
    {
        "id": 'M4-22-fresh-relay-receipt-bypasses-signature-and-policy-version-verification',
        "state": 'ACTIVE',
        "file": 'crates/vault-node/src/lib.rs',
        "edits": [
            [
                '    // The authenticated request must also name this node\'s baked-at-setup policy.\n    let claimed = request.policy_version();\n    if claimed != node.policy_version {\n        let configured = node.policy_version;\n        let detail =\n            format!("request policy_version {claimed} is not this node\'s configured {configured}");\n        let refused = refusal(RefusalCode::PsbtInconsistent, "policy_version", detail);\n        return Err(refused);\n    }\n    Ok(())',
                '    Ok(())',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-node',
            '--lib',
        ],
        "filter": 'channel::policy_version_relay_routes::a_relayed_spend_for_another_policy_version',
        "needle": 'a relayed mismatch may create no receipt state and pay no carrier KDF',
    },
    {
        "id": 'M4-23-outer-stale-receipt-bypasses-signature-and-policy-version-verification',
        "state": 'ACTIVE',
        "file": 'crates/vault-node/src/lib.rs',
        "edits": [
            [
                '    // The authenticated request must also name this node\'s baked-at-setup policy.\n    let claimed = request.policy_version();\n    if claimed != node.policy_version {\n        let configured = node.policy_version;\n        let detail =\n            format!("request policy_version {claimed} is not this node\'s configured {configured}");\n        let refused = refusal(RefusalCode::PsbtInconsistent, "policy_version", detail);\n        return Err(refused);\n    }\n    Ok(())',
                '    Ok(())',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-node',
            '--lib',
        ],
        "filter": 'channel::policy_version_relay_routes::an_outer_stale_spend_for_another_policy_version',
        "needle": 'an outer-stale mismatch may derive nothing and claim no holder slot',
    },
    {
        "id": 'M4-46-rebuilt-user-scalar-exists-outside-raii-erasure-guard',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/signer.rs',
        "edits": [
            [
                '        // Rebuilt INSIDE the guard, so it is erased on this return and on an unwind.\n        let scalar = Scalar::from_bytes(&self.secret)?;',
                '        let raw = bitcoin::secp256k1::SecretKey::from_slice(self.secret.as_slice())?;\n        let scalar = Scalar::from_bytes(&Zeroizing::new(raw.secret_bytes()))?;',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'signer::tests::the_signer_erases_its_parsed_key',
        "needle": 'a user scalar outside the guard: SecretKey',
    },
    {
        "id": 'M4SB-R01-scalar-exposes-forbidden-secret-authority',
        "state": 'ACTIVE',
        "file": 'crates/vault-cli/src/http.rs',
        "edits": [
            [
                "pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;",
                "pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;\n\npub(crate) struct Scalar(bitcoin::secp256k1::SecretKey);",
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--bin',
            'btc-vault',
        ],
        "filter": 'sealed::tests::the_scalar_guard_is_the_sole_secret_owner',
        "needle": 'exactly one workspace implementation may own a secret under this name',
    },
    {
        "id": 'M4SB-R02-policy-version-mismatch-moves-below-nonce-or-state-mutation',
        "state": 'ACTIVE',
        "file": 'crates/vault-node/src/lib.rs',
        "edits": [
            [
                '    // The authenticated request must also name this node\'s baked-at-setup policy.\n    let claimed = request.policy_version();\n    if claimed != node.policy_version {\n        let configured = node.policy_version;\n        let detail =\n            format!("request policy_version {claimed} is not this node\'s configured {configured}");\n        let refused = refusal(RefusalCode::PsbtInconsistent, "policy_version", detail);\n        return Err(refused);\n    }\n    Ok(())',
                '    Ok(())',
            ],
            [
                '        NonceDecision::Accepted => Ok((\n            nonces.effective_now(now),\n            nonces.carrier_deadline(request.nonce()),\n        )),',
                '        NonceDecision::Accepted if request.policy_version() == node.policy_version => Ok((\n            nonces.effective_now(now),\n            nonces.carrier_deadline(request.nonce()),\n        )),\n        NonceDecision::Accepted => Err(refusal(\n            RefusalCode::PsbtInconsistent,\n            "policy_version",\n            format!("request policy_version {} is not sealed", request.policy_version()),\n        )),',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-node',
            '--lib',
        ],
        "filter": 'policy_version_direct_routes::a_direct_spend_naming_another_policy_version',
        "needle": 'a refused spend may consume no nonce, candidate or PIN attempt',
    },
    {
        "id": 'M4SB-R03-psbtinconsistent-defining-docs-omit-policy-version',
        "state": 'ACTIVE',
        "file": 'docs/adr/0013-concrete-protocol-schemas.md',
        # Each edit is its OWN red case against the pristine source, not one combined
        # mutation: the bead requires this row to fail against EACH omission, and a single
        # mutation that drops both facts at once leaves either one of them unproven.
        "independent": True,
        "edits": [
            [
                '(`PSBT_INCONSISTENT`, `check = "policy_version"`)',
                '(`PSBT_INCONSISTENT`)',
            ],
            [
                'only terminal Lockdown (`FRAUD_SUSPECTED`, ADR-0008) short-circuits ahead of it',
                'nothing short-circuits ahead of it',
            ],
        ],
        "command": [
            'cargo',
            'test',
            '--locked',
            '-p',
            'vault-cli',
            '--test',
            'core_view',
            '--',
        ],
        "filter": 'the_defining_protocol_docs_adjudicate_policy_version',
        "needle": 'states the refusal but not',
    },
]


def rows():
    """Every row this repository defines: the 91 inherited plus each child's own."""
    return INHERITED + M4SA_OWNED + M4SB_OWNED


def verify(root=ROOT):
    """Mechanically check the promotion and the re-anchor rule. Returns a list of faults.

    Every check here is a STOP condition the bead names: a missing or duplicate id, an
    edit whose exact target does not occur exactly once in the ORIGINAL bytes, an
    ambiguous multi-edit order, an edit that changes nothing, a command that is not a
    focused unpiped argv, a missing red diagnostic or restored-green command, and a
    purported re-anchor whose prior and active definitions are identical.
    """
    faults = []
    if len(INHERITED) != 91:
        faults.append(f"the inherited suite is {len(INHERITED)} rows, not 91")
    ids = [row["id"] for row in rows()]
    for rid in sorted(set(ids)):
        if ids.count(rid) != 1:
            faults.append(f"{rid}: the row id appears {ids.count(rid)} times")
    for row in rows():
        rid = row["id"]
        state = row["state"]
        if state != "ACTIVE" and not state.startswith("REANCHORED_FROM="):
            faults.append(f"{rid}: {state!r} is neither ACTIVE nor REANCHORED_FROM=<origin>")
        if not row["needle"]:
            faults.append(f"{rid}: no red diagnostic is required")
        command = row["command"]
        if not isinstance(command, list) or not command:
            faults.append(f"{rid}: the command must be an argv list, not a shell string")
        elif any("|" in word for word in [*command, row["filter"]]):
            faults.append(f"{rid}: the command or filter is piped")
        elif not row["filter"].strip():
            faults.append(f"{rid}: the command is not focused on a filter")
        text = (root / row["file"]).read_text()
        independent = row.get("independent", False)
        if independent and len(row["edits"]) < 2:
            faults.append(f"{rid}: an independent row needs more than one red case")
        applied = text
        for index, (old, new) in enumerate(row["edits"]):
            if old == new:
                faults.append(f"{rid}: edit {index} changes nothing")
            if text.count(old) != 1:
                faults.append(
                    f"{rid}: edit {index} has {text.count(old)} exact targets in {row['file']}"
                )
            if independent:
                # Each edit is its own mutation of the ORIGINAL bytes, so there is no order
                # to be ambiguous: uniqueness against `text` above is the whole requirement.
                continue
            # Order matters: each edit is applied to the result of the one before it, so a
            # later target that has already been consumed is an ambiguous order, not a row.
            if applied.count(old) != 1:
                faults.append(f"{rid}: edit {index} is not unique after the edits before it")
            applied = applied.replace(old, new, 1)
        if state.startswith("REANCHORED_FROM="):
            prior = row.get("prior")
            if not prior:
                faults.append(f"{rid}: a re-anchor records no prior definition")
            elif _definition(prior) == _definition(row):
                faults.append(f"{rid}: the re-anchor is byte-identical to its active definition")
            if not state.split("=", 1)[1]:
                faults.append(f"{rid}: the re-anchor names no origin")
    return faults


def _definition(row):
    """The parts of a row a re-anchor can move, as one comparable value."""
    return (
        row["file"],
        [tuple(edit) for edit in row["edits"]],
        list(row["command"]),
        row["filter"],
        row["needle"],
    )


def main(argv):
    if argv[1:2] != ["verify"]:
        print(f"usage: {argv[0]} verify", file=sys.stderr)
        return 2
    for relative, digest in SOURCES:
        print(f"source {digest}  {relative}")
    faults = verify()
    if faults:
        print("MANIFEST VERIFICATION FAILED:")
        print("\n".join(f"  {fault}" for fault in faults))
        return 1
    print(
        f"OK: {len(INHERITED)} inherited + {len(M4SA_OWNED)} M4-SA + {len(M4SB_OWNED)} M4-SBR "
        f"= {len(rows())} rows verified"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
