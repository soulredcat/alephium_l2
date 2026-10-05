use alephium_l2_node::{
    config::{self, Config},
    development,
    protocol::CHAIN_ID,
    rpc, service,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--make-genesis") {
        let chain_id = match args.len() {
            3 => CHAIN_ID,
            5 if args[3] == "--chain-id" => config::parse_chain_id(&args[4])?,
            _ => return Err("Usage: --make-genesis <new-file> [--chain-id <id>]".into()),
        };
        let genesis = development::genesis_for_chain(chain_id)?;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[2])?;
        file.write_all(&serde_json::to_vec_pretty(&genesis)?)?;
        file.sync_all()?;
        println!("Created development-only genesis for chain {chain_id}");
        return Ok(());
    }
    let config = Config::parse()?;
    // Reserve the port first; do not spawn an unowned worker on bind failure.
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let (node, worker) = service::start(&config)?;
    println!(
        "Development-only EVM node on {}; chain {}; settlement unimplemented",
        config.listen, config.genesis.chain_id
    );
    let stop = node.clone();
    let result = axum::serve(listener, rpc::router(node))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    stop.stop().await;
    let _ = tokio::task::spawn_blocking(move || worker.join()).await;
    result?;
    Ok(())
}
