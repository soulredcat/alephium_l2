use alephium_l2_node::{
    config::{self, Config},
    rpc, service,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workers = std::thread::available_parallelism()
        .map(|available| available.get())
        .unwrap_or(1)
        .saturating_sub(1)
        .max(1);
    // Async workers park while idle. Execution and durable commits retain the
    // separate ordered core; this networking budget leaves one logical CPU.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--make-genesis") {
        let (path, genesis) = config::genesis_command(&args)?;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&serde_json::to_vec_pretty(&genesis)?)?;
        file.sync_all()?;
        println!(
            "Created development-only genesis for chain {} with capacity {:?}",
            genesis.chain_id, genesis.capacity
        );
        return Ok(());
    }
    let config = Config::parse()?;
    // Reserve the port first; do not spawn an unowned worker on bind failure.
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let (node, worker) = service::start(&config)?;
    // Owned-process clients consume this one-line acknowledgement and close
    // the startup pipe. CPU diagnostics stay available through /health.
    println!(
        "Development-only EVM node on {}; chain {}; settlement unimplemented",
        config.listen, config.genesis.chain_id
    );
    let stop = node.clone();
    let router = match rpc::router_with_limits(node, config.rpc) {
        Ok(router) => router,
        Err(error) => {
            stop.stop().await;
            let _ = tokio::task::spawn_blocking(move || worker.join()).await;
            return Err(error.into());
        }
    };
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    stop.stop().await;
    let _ = tokio::task::spawn_blocking(move || worker.join()).await;
    result?;
    Ok(())
}
