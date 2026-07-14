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
