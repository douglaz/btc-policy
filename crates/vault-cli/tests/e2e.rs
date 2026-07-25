//! The demo IS the e2e test. Every test here needs bitcoind on PATH, which a plain
//! `cargo test --workspace` does not provide, so all of them are `#[ignore]`d and
//! opted into together — this one command IS the launch gate, and it runs
//! [`attack_harness_exits_zero`] along with the two demos:
//!
//!   nix develop -c cargo test -p vault-cli -- --ignored --test-threads=1

#[test]
#[ignore = "spawns bitcoind and 5 vault-node processes; run with --ignored"]
fn demo_first_light_exits_zero() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_btc-vault"))
        .args(["demo", "first-light"])
        .status()
        .expect("run btc-vault demo first-light");
    assert!(status.success(), "demo exited {status}");
}

/// The NAMED v0 acceptance artifact (DESIGN.md, "The demo"): act one is the
/// structured `DEST_NOT_ALLOWED` refusal of a sweep to an unknown address by every
/// node, act two is the attacker's ALLOWLISTED spend caught mid-Hold as a pending
/// spend the user never authorized and clawed back by an instant escape sweep. The
/// exit code IS the scorecard, so a plain `success()` assertion is the whole gate.
///
/// Slower than first light: act two waits out a real (regtest-compressed) Hold and
/// the combine window that follows before it may call the attacker's spend absent.
#[test]
#[ignore = "spawns bitcoind and 5 vault-node processes; run with --ignored"]
fn demo_theft_refused_exits_zero() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_btc-vault"))
        .args(["demo", "theft-refused"])
        .status()
        .expect("run btc-vault demo theft-refused");
    assert!(status.success(), "theft-refused demo exited {status}");
}

/// The V0-10 recovery exit end-to-end: the two-branch vault is funded, a recovery
/// spend before the relative timelock matures is consensus-rejected, 1-of-3 cannot
/// finalize, and after advancing median-time-past the 2-of-3 recovery spend
/// confirms and the watchtower classifies it as a RECOVERY_PATH_SPEND.
#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn demo_recovery_drill_exits_zero() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_btc-vault"))
        .args(["demo", "recovery-drill"])
        .status()
        .expect("run btc-vault demo recovery-drill");
    assert!(status.success(), "recovery drill exited {status}");
}

/// The adversarial harness (ADR-0012 / ADR-0014): sixteen scenarios (the reorg trio
/// added in bead 9y5.3) against live `n = 2t−1` federations with `t−1` compromised node
/// identities, asserting the
/// signer/partial coupling and release-gate rather than a receipt count, the Hot
/// budget bound on the censorship residual, silence before `T`, ADR-0012's V0-4
/// implementation-semantics checklist (the Armed overlay racing a Hold expiry,
/// fail-closed lockout, idempotency ordering), reboot-death on both sides of the
/// threshold, and the recovery exit. Exits 0 only when every safety assertion holds.
///
/// Slower than the demos — it stands up a fresh federation per scenario and waits
/// out real Holds and hostage windows.
#[test]
#[ignore = "spawns bitcoind and a vault-node federation per scenario; run with --ignored"]
fn attack_harness_exits_zero() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_btc-vault"))
        .args(["attack", "all"])
        .status()
        .expect("run btc-vault attack all");
    assert!(status.success(), "adversarial harness exited {status}");
}
