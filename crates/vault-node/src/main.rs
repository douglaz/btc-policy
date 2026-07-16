//! vault-node daemon entry point. See docs/DESIGN.md and docs/adr/.

use std::process::ExitCode;
use std::sync::Arc;

use vault_node::{server, Node};

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
    // v0 nodes bind loopback only (DESIGN.md, node API access control). All
    // surfaces share the one port on tokio; each connection is its own task, so
    // a stalled client no longer wedges signing.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", node.listen_port))
        .await
        .map_err(|e| format!("cannot bind 127.0.0.1:{}: {e}", node.listen_port))?;
    // If a chain backend is configured, drive the watchtower (ADR-0001, V0-6b):
    // one background tokio task scanning this node's own chain view on an
    // interval, queueing alerts that surface through GET /events. We are inside
    // the runtime here, so the task spawns cleanly.
    node.spawn_watchtower();
    println!("vault-node listening on 127.0.0.1:{}", node.listen_port);
    server::serve(listener, Arc::clone(&node))
        .await
        .map_err(|e| format!("serve error: {e}"))?;
    Ok(())
}
