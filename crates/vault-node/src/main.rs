//! vault-node daemon entry point. See docs/DESIGN.md and docs/adr/.

use std::net::TcpListener;
use std::process::ExitCode;

use vault_node::{http, Node};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault-node: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), vault_node::Error> {
    let args: Vec<String> = std::env::args().collect();
    let config_path = match args.as_slice() {
        [_, flag, path] if flag == "--config" => path,
        _ => return Err("usage: vault-node --config <policy-config.toml>".into()),
    };
    let node = Node::load(config_path)?;
    // v0 nodes bind loopback only (DESIGN.md, node API access control).
    let listener = TcpListener::bind(("127.0.0.1", node.listen_port))
        .map_err(|e| format!("cannot bind 127.0.0.1:{}: {e}", node.listen_port))?;
    println!("vault-node listening on 127.0.0.1:{}", node.listen_port);
    http::serve(listener, &node);
    Ok(())
}
