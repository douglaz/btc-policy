//! btc-vault coordinator CLI. See docs/DESIGN.md and docs/adr/.

mod bitcoind;
mod demo;
mod http;
mod recovery;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["demo", "first-light"] => match demo::run_first_light() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("first light FAILED: {e}");
                ExitCode::FAILURE
            }
        },
        ["demo", "recovery-drill"] => match recovery::run_recovery_drill() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("recovery drill FAILED: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: btc-vault demo <first-light|recovery-drill>");
            ExitCode::from(2)
        }
    }
}
