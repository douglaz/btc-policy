//! vault-node daemon entry point. See docs/DESIGN.md and docs/adr/.

use std::process::ExitCode;
use std::sync::Arc;

use vault_node::{server, spawn_drivers, Node};

/// Floor on Tokio worker threads. The Lockdown-deadline and fire-driver prologues
/// both touch the synchronous channel store; if that lock is wedged, each can pin one
/// worker, so a third is what keeps the lock-free `/healthz` operations surface
/// schedulable on a one- or two-vCPU sealed host. A FLOOR and not a cap: a larger
/// sealed host keeps its `available_parallelism()` workers, which is the count Tokio
/// itself defaults to and what the daemon ran on before this floor existed.
///
/// Setting the count explicitly does mean `TOKIO_WORKER_THREADS` no longer applies,
/// and that is the intended reading: this floor exists precisely so the number cannot
/// drop below what keeps `/healthz` answerable on a wedged store, and nothing in a
/// sealed v0 deployment asks for a different one.
const MIN_WORKER_THREADS: usize = 3;

fn main() -> ExitCode {
    let workers = std::thread::available_parallelism().map_or(MIN_WORKER_THREADS, |cpus| {
        cpus.get().max(MIN_WORKER_THREADS)
    });
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("vault-node: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vault-node: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

async fn run() -> Result<(), vault_node::Error> {
    let args: Vec<String> = std::env::args().collect();
    let config_path = match args.as_slice() {
        [_, flag, path] if flag == "--config" => path,
        _ => return Err("usage: vault-node --config <policy-config.toml>".into()),
    };
    let node = Arc::new(Node::load(config_path)?);
    // Escape-class union coverage needs reliable confirmed-transaction lookup.
    // Check the production backend before binding or consuming this tmpfs key's
    // one allowed process generation.
    node.validate_chain_backend()?;
    // v0 nodes bind loopback only (DESIGN.md, node API access control). All
    // surfaces share the one port on tokio; each connection is its own task, so
    // a stalled client no longer wedges signing.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", node.listen_port))
        .await
        .map_err(|e| format!("cannot bind 127.0.0.1:{}: {e}", node.listen_port))?;
    // With a chain backend configured, start the two background drivers: the
    // watchtower (ADR-0001, V0-6b) scanning this node's own chain view, and the
    // fire driver (V0-8b) that releases partials at each candidate's authorized
    // fire event and then combines + broadcasts. The public serving boundary
    // claims the one-shot process generation before accepting this already-bound
    // listener, so no request can reach these fresh tasks before reboot-death is
    // enforced. We are inside the runtime here, so the tasks spawn cleanly.
    spawn_drivers(&node);
    println!("vault-node listening on 127.0.0.1:{}", node.listen_port);
    server::serve(listener, Arc::clone(&node))
        .await
        .map_err(|e| format!("serve error: {e}"))?;
    Ok(())
}
