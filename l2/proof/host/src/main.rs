//! Local Groth16 proof host for the pinned transition guest.
//! Receipt generation does not approve a guest or establish Alephium settlement.

mod artifacts;
mod cli;
mod inputs;
mod prover;

use alephium_l2_transition_core::{decode_input, prove_input};
use sha2::{Digest, Sha256};
use std::process::ExitCode;

type HostResult<T> = Result<T, &'static str>;

fn main() -> ExitCode {
    // A dependency panic must not dump its private arguments or proof values.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("Proof host stopped after an internal error; payload suppressed.");
    }));
    match run() {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> HostResult<String> {
    let config = cli::Config::parse()?;
    let local_prover = cli::LocalProver::validate(config.prover_sha256, config.output.is_some())?;
    let input = inputs::read_bounded(&config.input, inputs::MAX_INPUT_BYTES)?;
    let program = inputs::read_bounded(&config.guest, inputs::MAX_PROGRAM_BYTES)?;
    let bundle =
        decode_input(&input).map_err(|_| "Invalid private transition JSON; payload suppressed.")?;
    let expected = prove_input(&bundle)
        .map_err(|_| "Independent core transition replay failed; payload suppressed.")?;
    let expected_journal = expected
        .encode()
        .map_err(|_| "Cannot encode independently derived transition journal.")?;

    let Some(output) = &config.output else {
        let preflight = prover::preflight(
            &local_prover,
            &input,
            &program,
            &expected_journal,
            config.expected_image_id,
        )?;
        // Cycle counts and the public journal digest only; never inputs.
        return Ok(format!(
            "Execution-only preflight passed: Halted(0), {} user cycles in {} segments \
             (ceiling {}), journal sha256 {}",
            preflight.user_cycles,
            preflight.segments,
            prover::SESSION_LIMIT_CYCLES,
            hex::encode(Sha256::digest(&expected_journal))
        ));
    };
    // Reserve a new directory before expensive work. Partial output is never
    // resumed or overwritten, and report.json is written only after validation.
    let output = artifacts::ArtifactDirectory::create(output)?;
    let proof = prover::generate(
        &local_prover,
        &input,
        &program,
        &expected_journal,
        config.expected_image_id,
    )?;
    let report = output.persist(&input, &program, &expected, &proof)?;
    Ok(format!(
        "Transition proof generated and verified: {}",
        report.display()
    ))
}
