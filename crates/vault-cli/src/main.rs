//! btc-vault coordinator CLI. See docs/DESIGN.md and docs/adr/.

mod adversary;
mod attack;
mod bitcoind;
mod demo;
mod fed;
mod http;
// The M2 operator substrate: the sealed-artifact trust boundary and the stage-1 ingress
// client. M4/M5 add the commands that call them, so a binary build has no caller yet.
#[cfg_attr(not(test), allow(dead_code))]
mod ingress;
mod recovery;
#[cfg_attr(not(test), allow(dead_code))]
mod sealed;
mod setup;
// The frozen user-signing seam over that boundary. M4/M5 add the commands that call
// it, so a binary build has no caller yet.
#[cfg_attr(not(test), allow(dead_code))]
mod signer;
mod signet;

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
        // The adversarial harness. `attack all` is the LARGEST PART of the launch gate,
        // not the whole of it: the gate is `attack all` plus all three demos
        // (first-light, theft-refused, recovery-drill), each a step of the `launch-gate`
        // job in .github/workflows/ci.yml. `attack recovery` only OVERLAPS the
        // recovery-drill demo, which is why that demo is gated in its own right
        // (bead btc-policy-9yf). A single scenario name runs just that one, for
        // iterating on a failure.
        ["attack"] | ["attack", "all"] => attack::run(None),
        ["attack", scenario] => attack::run(Some(scenario)),
        // The production setup ceremony (ADR-0013 §4). Distinct from the demo
        // federation's bring-up in WHO RUNS WHAT, not in what it computes: the
        // demos drive these same functions, with the node-side steps in their own
        // processes, so what the acceptance runs is the real provisioning path.
        ["setup", rest @ ..] => setup::run(rest),
        // Real-signet spend driver (bead btc-policy-9y5.8 deliverable 1): the same
        // federation as the demos, but against a live external signet node with a
        // real Hold and real block timing. Funds out of band from a signet faucet.
        ["signet", "spend"] => match signet::run_signet_spend() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("signet spend FAILED: {e}");
                ExitCode::FAILURE
            }
        },
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
