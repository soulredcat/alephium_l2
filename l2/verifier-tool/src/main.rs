//! Bounded verifier compilation and synthetic VM qualification; no live transactions.
#![forbid(unsafe_code)]
mod actual_factory_service;
mod actual_receipt;
mod cases;
mod compiler;
mod compiler_schema;
mod curve_cases;
mod diagnostic_cases;
mod factory_service;
mod factory_state;
mod fixed_pair;
mod folded_msm;
mod input;
mod miller_cases;
mod ordinary_miller;
mod pairing_cases;
mod receipt_cases;
mod receipt_fixture;
mod receipt_sources;
mod residue_cases;
mod residue_witness;
mod service;
mod session_binding;
mod settlement;
mod settlement_schema;
mod settlement_sources;
mod source_inventory;
mod staged_canonical;
mod staged_cases;
mod staged_service;
mod staged_sources;
mod staged_state;
mod testnet_plan;
mod testnet_plan_cli;
mod tower_cases;
mod transport;
mod verification_key;

use input::Suite;
use serde_json::{Value, json};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

const HARNESS_DEADLINE: Duration = Duration::from_secs(120);

fn run() -> Result<(), String> {
    let mut args: Vec<_> = env::args_os().skip(1).collect();
    let no_run_time_limit = args
        .first()
        .is_some_and(|flag| flag == "--no-run-time-limit");
    if no_run_time_limit {
        args.remove(0);
    }
    if args.iter().any(|flag| flag == "--no-run-time-limit") {
        return Err("--no-run-time-limit must occur once as the first option".into());
    }
    if let [mode, jar, evidence, public_key, genesis, policy] = args.as_slice()
        && mode == "--testnet-plan-draft"
    {
        if !no_run_time_limit {
            return Err("Offline draft requires explicit --no-run-time-limit".into());
        }
        let public_key = public_key
            .to_str()
            .ok_or("Offline public key must be UTF-8")?;
        let genesis = genesis
            .to_str()
            .ok_or("Offline genesis pin must be UTF-8")?;
        let report = testnet_plan_cli::run(
            Path::new(jar),
            Path::new(evidence),
            public_key,
            genesis,
            Path::new(policy),
        )?;
        println!("{report}");
        return Ok(());
    }
    let mut actual = None;
    let mut settlement_data = None;
    let (suite, jar, evidence) = match args.as_slice() {
        [flag, mode, jar, evidence, receipt, image, journal, data, checkpoint]
            if flag == "--mainnet-readonly" && mode == "--settlement-actual" => {
                actual = Some(actual_receipt::Input::new(receipt, image, journal)?);
                let checkpoint = checkpoint.to_str().ok_or("Checkpoint pin must be UTF-8 hex")?;
                if checkpoint.len() != 64 || !checkpoint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err("Checkpoint pin must have exact 32-byte hex width".into());
                }
                settlement_data = Some((PathBuf::from(data), checkpoint.to_owned()));
                (Suite::SettlementFactoryFlow, PathBuf::from(jar), PathBuf::from(evidence))
            },
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--settlement-compile" =>
            (Suite::SettlementFactoryCompile, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence, receipt, image, journal]
            if flag == "--mainnet-readonly" && mode == "--staged-actual" => {
                actual = Some(actual_receipt::Input::new(receipt, image, journal)?);
                (Suite::StagedFactoryFlow, PathBuf::from(jar), PathBuf::from(evidence))
            },
        [flag, jar, evidence] if flag == "--mainnet-readonly" =>
            (Suite::Base, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--tower" =>
            (Suite::Tower, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--pairing-arithmetic" =>
            (Suite::PairingArithmetic, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--curves" =>
            (Suite::Curves, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--miller" =>
            (Suite::Miller, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--receipt" =>
            (Suite::Receipt, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--receipt-residue" =>
            (Suite::ResidueReceipt, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--residue-diagnostics" =>
            (Suite::ResidueDiagnostic, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--staged-receipt" =>
            (Suite::StagedReceipt, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--staged-factory-compile" =>
            (Suite::StagedFactory, PathBuf::from(jar), PathBuf::from(evidence)),
        [flag, mode, jar, evidence] if flag == "--mainnet-readonly" && mode == "--staged-factory" =>
            (Suite::StagedFactoryFlow, PathBuf::from(jar), PathBuf::from(evidence)),
        _ => return Err("Usage: alephium-l2-verifier-tool [--no-run-time-limit] --mainnet-readonly [--tower|--pairing-arithmetic|--curves|--miller|--receipt|--receipt-residue|--residue-diagnostics|--staged-receipt|--staged-factory-compile|--staged-factory] <pinned-ralphc.jar> <NEW-evidence-directory>; or [--no-run-time-limit] --mainnet-readonly --staged-actual <pinned-ralphc.jar> <NEW-evidence-directory> <private-receipt-directory> <expected-image-id-hex> <expected-journal-sha256-hex>".into()),
    };
    fs::create_dir(&evidence)
        .map_err(|_| "Evidence directory must be new and its parent writable")?;
    let evidence = evidence
        .canonicalize()
        .map_err(|_| "Cannot resolve fresh evidence directory")?;
    let started = Instant::now();
    // Absence is an explicit policy, not an arbitrarily large synthetic timeout.
    let deadline = (!no_run_time_limit).then(|| started + HARNESS_DEADLINE);
    let deadline_seconds = (!no_run_time_limit).then_some(HARNESS_DEADLINE.as_secs());
    let mut report = json!({
        "schema": 1, "scope": suite.scope(),
        "endpoint": transport::ENDPOINT, "selectedNetworkId": 0,
        "mainnetReadOnlyExplicitlySelected": true,
        "operation": "offline compilation and synthetic contracts/test-contract simulation",
        "sourcesUploadedToPublicEndpoints": false,
        "limits": {"caseCount": suite.case_count(), "deadlineSeconds": deadline_seconds,
            "runTimeLimitApplied": !no_run_time_limit,
            "parameterBindingRequests": 1, "maxVmRequests": suite.case_count() + 1,
            "requestTimeoutSeconds": 10, "maxResponseBytes": 1_048_576,
            "maxExecutableBytes": 32_768, "maxVmGasPerCase": 5_000_000,
            "maxIdentityReads": 3, "retries": 0},
        "expectationOracle": {"library": "ark-bn254", "version": "0.6.0",
            "field": suite.oracle_fields(), "fp2Order": "real,imaginary", "independentFromRalph": true},
        "syntheticInitialAttoAlph": "100000000000000000",
        "passed": false, "results": [], "signing": false, "deployment": false,
        "realAssetTransfer": false, "publicTestnetAcceptance": false,
        "fullTransactionGasMeasured": false, "completeBn254VerifierAccepted": false,
        "stackPeaksMeasured": false, "gate0Complete": false,
        "alephiumSettlementAccepted": false
    });
    if actual.is_some() {
        report["scope"] = json!("pinned-actual-receipt-canonical-synthetic-acceptance");
        report["limits"]["caseCount"] = json!(actual_receipt::MAX_REQUESTS);
        report["limits"]["parameterBindingRequests"] = json!(0);
        report["limits"]["maxVmRequests"] = json!(actual_receipt::MAX_REQUESTS);
    }
    if matches!(suite, Suite::SettlementFactoryFlow) {
        report["scope"] = json!(suite.scope());
        report["limits"]["caseCount"] = json!(settlement::MAX_REQUESTS);
        report["limits"]["maxVmRequests"] = json!(settlement::MAX_REQUESTS);
    }
    let outcome = service::execute(
        &jar,
        &evidence,
        deadline,
        suite,
        &mut report,
        actual.as_ref(),
        settlement_data
            .as_ref()
            .map(|(path, pin)| (path.as_path(), pin.as_str())),
    );
    report["elapsedMilliseconds"] = json!(started.elapsed().as_millis());
    if let Err(error) = &outcome {
        report["failure"] = json!(error);
    }
    write_report(&evidence.join("report.json"), &report)?;
    outcome?;
    println!(
        "Verifier bundle passed: {} aggregate checks; safe report.json saved. Gate 0 remains open.",
        report["executedCases"].as_u64().unwrap_or(0)
    );
    Ok(())
}

fn write_report(path: &Path, report: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(report).map_err(|_| "Cannot encode safe field report")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "Cannot create new safe field report")?;
    file.write_all(&bytes)
        .map_err(|_| "Cannot write safe field report")?;
    file.sync_all()
        .map_err(|_| "Cannot synchronize safe field report".to_owned())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Field slice failed: {error}");
            ExitCode::FAILURE
        }
    }
}
