use alephium_l2_sdk::{Client, ExpectedNetwork};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("Usage: inspect <loopback-url> <chain-id> <expected-genesis-id>".into());
    }
    let expected = ExpectedNetwork {
        chain_id: args[1].parse().map_err(|_| "Invalid chain ID")?,
        genesis_id: args[2].parse().map_err(|_| "Invalid genesis ID")?,
        rpc_profile: "development/c5-v1".into(),
    };
    let client = Client::connect(&args[0], expected)?;
    println!("{}", serde_json::to_string_pretty(client.node_info())?);
    Ok(())
}
