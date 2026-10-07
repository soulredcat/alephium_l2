//! Local Groth16 proof host for the pinned transition guest.
//! Receipt generation does not approve a guest or establish Alephium settlement.

mod artifacts;
mod backend;
mod cli;
mod diagnostics;
mod input_stream;
mod inputs;
mod prover;
mod resources;
mod transition_input;

use alephium_l2_transition_core::prove_input;
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
    let resources = resources::ResourcePolicy::select(config.workers, config.max_cycles)?;
    // SAFETY: plain CLI startup is still single-threaded; no SDK or native
    // execution has run, and no concurrently running environment reader exists.
    unsafe { resources.apply_at_startup() };
    let local_prover = cli::LocalProver::validate(&config)?;
    let worker = resources::WorkerGuard::acquire(&local_prover.server_path)?;
    let mut input = transition_input::TransitionInput::open(&config.input)?;
    let program = inputs::read_bounded(&config.guest, inputs::MAX_PROGRAM_BYTES)?;
    let bundle = input.replay_input()?;
    let expected = prove_input(&bundle)
        .map_err(|_| "Independent core transition replay failed; payload suppressed.")?;
    drop(bundle);
    let expected_journal = expected
        .encode()
        .map_err(|_| "Cannot encode independently derived transition journal.")?;

    let Some(output) = &config.output else {
        let preflight = prover::preflight(
            &local_prover,
            &mut input,
            &program,
            &expected_journal,
            config.expected_image_id,
            resources.max_cycles,
        )?;
        // Cycle counts and the public journal digest only; never inputs.
        return Ok(format!(
            "Execution-only preflight passed: Halted(0), {} user cycles in {} segments \
             (ceiling {}, segment limit 2^{}, Rayon workers {}/{}, available logical CPUs {}, one owned job), \
             worker lock [{}], backend {} ({}; CUDA runtime qualification {}), \
             input schema {} / {} bytes (limit {}), journal sha256 {}",
            preflight.user_cycles,
            preflight.segments,
            preflight.max_cycles,
            prover::SEGMENT_LIMIT_PO2,
            resources.workers,
            resources.worker_ceiling,
            resources.available_logical_cpus,
            worker.access_policy,
            local_prover.backend.requested_backend,
            local_prover.backend.provenance_status,
            local_prover.backend.runtime_cuda_qualification,
            input.schema,
            input.length,
            input.byte_limit,
            hex::encode(Sha256::digest(&expected_journal))
        ));
    };
    // Reserve a new directory before expensive work. Partial output is never
    // resumed or overwritten, and report.json is written only after validation.
    let output = artifacts::ArtifactDirectory::create(output)?;
    let proof = prover::generate(
        &local_prover,
        &mut input,
        &program,
        &expected_journal,
        config.expected_image_id,
        resources.max_cycles,
    )?;
    let report = output.persist(&input, &program, &expected, &proof, &resources, &worker)?;
    Ok(format!(
        "Transition proof generated and verified: {}",
        report.display()
    ))
}
