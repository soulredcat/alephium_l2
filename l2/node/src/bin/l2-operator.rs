use alephium_l2_node::{config, operator, protocol::CHAIN_ID};
use alloy_primitives::B256;
use std::{collections::BTreeMap, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .ok_or("Use backup, replay, transition, transition-batch or transition-checkpoint with explicit paths")?;
    let expected: &[&str] = match command.as_str() {
        "backup" => &["--source", "--destination", "--genesis"],
        "replay" | "transition" => &["--backup", "--work-dir", "--genesis"],
        "transition-batch" | "transition-checkpoint" => &[
            "--backup",
            "--work-dir",
            "--genesis",
            "--batch-start",
            "--l1-network",
            "--l1-genesis",
            "--settlement-contract",
        ],
        _ => return Err("Supported commands: backup, replay, transition, transition-batch, transition-checkpoint".into()),
    };
    let mut options = BTreeMap::new();
    let mut chain_id = CHAIN_ID;
    let mut chain_option_seen = false;
    while let Some(flag) = args.next() {
        if flag == "--chain-id" {
            if chain_option_seen {
                return Err("Duplicate chain identity argument".into());
            }
            chain_id = config::parse_chain_id(&args.next().ok_or("Missing chain identity")?)?;
            chain_option_seen = true;
            continue;
        }
        if !expected.contains(&flag.as_str()) || options.contains_key(&flag) {
            return Err("Unknown or duplicate argument".into());
        }
        let value = args.next().ok_or("Missing argument value")?;
        if value.is_empty() {
            return Err("Empty argument is invalid".into());
        }
        options.insert(flag, value);
    }
    if options.len() != expected.len() {
        return Err("Missing required command arguments".into());
    }
    let path = |key: &str| Path::new(options[key].as_str());
    let genesis = config::load_genesis(path("--genesis"), chain_id)?;
    let report = match command.as_str() {
        "backup" => serde_json::to_value(operator::backup(
            path("--source"),
            path("--destination"),
            &genesis,
        )?)?,
        "replay" => serde_json::to_value(operator::verify_replay(
            path("--backup"),
            &genesis,
            path("--work-dir"),
        )?)?,
        "transition" => serde_json::to_value(operator::prepare_transition(
            path("--backup"),
            &genesis,
            path("--work-dir"),
        )?)?,
        "transition-batch" | "transition-checkpoint" => {
            let batch_start = options["--batch-start"]
                .parse::<u64>()
                .map_err(|_| "Invalid batch start")?;
            let domain = operator::SettlementDomain {
                l1_network: options["--l1-network"]
                    .parse::<u8>()
                    .map_err(|_| "Invalid Alephium network ID")?,
                l1_genesis_id: parse_hash(&options["--l1-genesis"])?,
                settlement_contract_id: parse_hash(&options["--settlement-contract"])?,
            };
            if command == "transition-batch" {
                serde_json::to_value(operator::prepare_transition_batch(
                    path("--backup"),
                    &genesis,
                    path("--work-dir"),
                    batch_start,
                    domain,
                )?)?
            } else {
                serde_json::to_value(operator::prepare_transition_checkpoint(
                    path("--backup"),
                    &genesis,
                    path("--work-dir"),
                    batch_start,
                    domain,
                )?)?
            }
        }
        _ => unreachable!(),
    };
    let mut console = report;
    if let Some(object) = console.as_object_mut() {
        let count = object
            .get("transaction_hashes")
            .and_then(|value| value.as_array())
            .map(Vec::len);
        if let Some(count) = count.filter(|count| *count > 256) {
            // Full identities stay in the private export report. Large batches
            // must not turn safe CLI metadata into megabytes of console output.
            object.remove("transaction_hashes");
            object.insert("transaction_hash_count".into(), count.into());
        }
    }
    println!("{}", serde_json::to_string_pretty(&console)?);
    Ok(())
}

fn parse_hash(value: &str) -> Result<B256, &'static str> {
    if value.len() != 66 || !value.starts_with("0x") {
        return Err("Identity must be a 0x-prefixed 32-byte hash");
    }
    value.parse().map_err(|_| "Invalid 32-byte identity")
}
