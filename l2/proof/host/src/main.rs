//! Local Groth16 proof host for the pinned transition guest.
//! Receipt generation does not approve a guest or establish Alephium settlement.

mod artifacts;
mod cli;
mod inputs;
mod prover;

use alephium_l2_transition_core::{decode_input, prove_input};
use std::{path::PathBuf, process::ExitCode};

type HostResult<T> = Result<T, &'static str>;

fn main() -> ExitCode {
    // A dependency panic must not dump its private arguments or proof values.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("Proof host stopped after an internal error; payload suppressed.");
    }));
    match run() {
        Ok(report_path) => {
            println!(
                "Transition proof generated and verified: {}",
                report_path.display()
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> HostResult<PathBuf> {
    let config = cli::Config::parse()?;
    let local_prover = cli::LocalProver::validate(config.prover_sha256)?;
    let input = inputs::read_bounded(&config.input, inputs::MAX_INPUT_BYTES)?;
    let program = inputs::read_bounded(&config.guest, inputs::MAX_PROGRAM_BYTES)?;
    let bundle =
        decode_input(&input).map_err(|_| "Invalid private transition JSON; payload suppressed.")?;
    let expected = prove_input(&bundle)
        .map_err(|_| "Independent core transition replay failed; payload suppressed.")?;
    let expected_journal = expected
        .encode()
        .map_err(|_| "Cannot encode independently derived transition journal.")?;

    // Reserve a new directory before expensive work. Partial output is never
    // resumed or overwritten, and report.json is written only after validation.
    let output = artifacts::ArtifactDirectory::create(&config.output)?;
    let proof = prover::generate(
        &local_prover,
        &input,
        &program,
        &expected_journal,
        config.expected_image_id,
    )?;
    output.persist(&input, &program, &expected, &proof)
}
