//! vault-node daemon entry point. See docs/DESIGN.md and docs/adr/.

use std::process::ExitCode;
use std::sync::Arc;

use vault_node::{server, spawn_drivers, Node};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault-node: {e}");
            ExitCode::FAILURE
        }
    }
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
