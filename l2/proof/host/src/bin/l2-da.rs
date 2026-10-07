//! Local native DA export/reconstruction. No signer, RPC, node or prover.
use alephium_l2_transition_core::protocol::Capacity;
use alephium_l2_transition_prover::da;
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("DA tool stopped; private payload suppressed.")
    }));
    match run() {
        Ok(report) => {
            match serde_json::to_string_pretty(&report) {
                Ok(text) => println!("{text}"),
                Err(_) => return ExitCode::FAILURE,
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<da::DaPackageReport, &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments
        .next()
        .ok_or("Expected export or reconstruct command.")?;
    let allowed: &[&str] = match command.to_str() {
        Some("export") => &["--input", "--output"],
        Some("reconstruct") => &[
            "--package",
            "--expected",
            "--expected-sha256",
            "--block-gas",
            "--block-bytes",
            "--max-pending",
            "--output",
        ],
        _ => return Err("Only local DA export/reconstruct commands are supported."),
    };
    let mut options = BTreeMap::<String, OsString>::new();
    while let Some(key) = arguments.next() {
        let key = key.to_str().ok_or("Invalid DA option.")?;
        if !allowed.contains(&key) || options.contains_key(key) {
            return Err("Unknown or repeated DA option.");
        }
        let value = arguments.next().ok_or("DA option requires a value.")?;
        options.insert(key.into(), value);
    }
    if options.len() != allowed.len() {
        return Err("Every declared DA option is required.");
    }
    let path = |key: &str| PathBuf::from(&options[key]);
    if command == "export" {
        return da::export_package(&path("--input"), &path("--output"));
    }
    let number = |key: &str| {
        options[key]
            .to_str()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or("DA capacity must use bounded decimal integers.")
    };
    let capacity = Capacity {
        block_gas: number("--block-gas")?,
        block_bytes: usize::try_from(number("--block-bytes")?)
            .map_err(|_| "DA byte limit exceeds host range.")?,
        max_pending: usize::try_from(number("--max-pending")?)
            .map_err(|_| "DA count exceeds host range.")?,
    };
    let expected = da::read_candidate(
        &path("--expected"),
        options["--expected-sha256"]
            .to_str()
            .ok_or("Expected SHA-256 must be text.")?,
    )?;
    da::reconstruct_package(&path("--package"), &expected, capacity, &path("--output"))
}
