//! btc-vault coordinator CLI. See docs/DESIGN.md and docs/adr/.

mod bitcoind;
mod demo;
mod http;

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
        _ => {
            eprintln!("usage: btc-vault demo first-light");
            ExitCode::from(2)
        }
    }
}
