//! btc-vault coordinator CLI. See docs/DESIGN.md and docs/adr/.

mod adversary;
mod attack;
mod bitcoind;
mod demo;
mod fed;
mod http;
mod recovery;
mod setup;

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
        // The named v0 acceptance artifact (DESIGN.md, "The demo"). It reports its
        // own per-act scorecard, so it owns its exit code rather than being mapped
        // from a Result here.
        ["demo", "theft-refused"] => demo::run_theft_refused(),
        ["demo", "recovery-drill"] => match recovery::run_recovery_drill() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("recovery drill FAILED: {e}");
                ExitCode::FAILURE
            }
        },
        // The adversarial harness. `attack all` is the launch gate; a single
        // scenario name runs just that one, for iterating on a failure.
        ["attack"] | ["attack", "all"] => attack::run(None),
        ["attack", scenario] => attack::run(Some(scenario)),
        // The production setup ceremony (ADR-0013 §4). Distinct from the demo
        // federation's bring-up in WHO RUNS WHAT, not in what it computes: the
        // demos drive these same functions, with the node-side steps in their own
        // processes, so what the acceptance runs is the real provisioning path.
        ["setup", rest @ ..] => setup::run(rest),
        _ => {
            eprintln!(
                "usage: btc-vault demo <first-light|theft-refused|recovery-drill>\n\
                        btc-vault attack [all|{}]\n\
                        btc-vault setup <step>   (see `btc-vault setup` for the ceremony)",
                attack::SCENARIO_NAMES.join("|")
            );
            ExitCode::from(2)
        }
    }
}
