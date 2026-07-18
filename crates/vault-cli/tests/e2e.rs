//! The demo IS the e2e test. Opt in (needs bitcoind on PATH, e.g. the flake
//! dev shell) with:
//!
//!   nix develop -c cargo test -p vault-cli -- --ignored

#[test]
#[ignore = "spawns bitcoind and 5 vault-node processes; run with --ignored"]
fn demo_first_light_exits_zero() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_btc-vault"))
        .args(["demo", "first-light"])
        .status()
        .expect("run btc-vault demo first-light");
    assert!(status.success(), "demo exited {status}");
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
