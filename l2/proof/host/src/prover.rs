//! Execute the selected guest once and validate its actual Groth16 receipt,
//! or execute it without proving as a bounded preflight.

use crate::{
    HostResult, backend::BackendEvidence, cli::LocalProver, diagnostics::ExecutionProgress,
    resources, transition_input::TransitionInput,
};
use risc0_zkvm::{
    ApiClient, Asset, AssetRequest, Digest, ExecutorEnv, ExitCode, ExternalProver, InnerReceipt,
    Prover, ProverOpts, Receipt, SessionStats, compute_image_id,
};

/// Lower segment memory than the pinned SDK default (20), with more segments.
/// This is a prover working-set choice, not an overall RSS or security limit.
pub const SEGMENT_LIMIT_PO2: u32 = 19;
pub const VERIFIER_PARAMETERS: &str =
    "73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc";
pub const SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];
const PROOF_BYTES: usize = 256;

pub struct VerifiedProof {
    pub receipt: Receipt,
    pub image_id: Digest,
    pub seal: Vec<u8>,
    pub stats: SessionStats,
    pub prover_sha256: [u8; 32],
    pub backend: BackendEvidence,
    pub max_cycles: u64,
}

/// Non-sensitive outcome of an execution-only run of the pinned guest.
pub struct Preflight {
    pub user_cycles: u64,
    pub segments: usize,
    pub max_cycles: u64,
}

fn checked_image(program: &[u8], expected_image_id: [u8; 32]) -> HostResult<Digest> {
    let image_id = compute_image_id(program)
        .map_err(|_| "Cannot derive the guest image ID; a packaged ProgramBinary is required.")?;
    if image_id.as_bytes() != expected_image_id {
        return Err("Selected guest ProgramBinary differs from the expected image ID pin.");
    }
    Ok(image_id)
}

/// Proving and preflight share this exact framing and cycle ceiling.
fn bounded_env(
    reader: impl std::io::Read + 'static,
    max_cycles: u64,
) -> HostResult<ExecutorEnv<'static>> {
    resources::validate_max_cycles(max_cycles)?;
    // The checked reader supplies the little-endian length and exact file bytes.
    // stdin avoids the SDK's full Vec copy in write_slice/build for large input.
    ExecutorEnv::builder()
        .session_limit(Some(max_cycles))
        .segment_limit_po2(SEGMENT_LIMIT_PO2)
        .stdin(reader)
        .stdout(std::io::sink())
        .stderr(std::io::sink())
        .build()
        .map_err(|_| "Cannot construct bounded private guest environment.")
}

/// Execute without proving through the same pinned local r0vm. Only a
/// Halted(0) session whose journal equals the independently derived canonical
/// journal passes. This checks resources before an expensive proof attempt.
pub fn preflight(
    local: &LocalProver,
    input: &mut TransitionInput,
    program: &[u8],
    expected_journal: &[u8],
    expected_image_id: [u8; 32],
    max_cycles: u64,
) -> HostResult<Preflight> {
    checked_image(program, expected_image_id)?;
    let feed = input.guest_input()?;
    let env = bounded_env(feed.reader, max_cycles)?;
    let mut progress = ExecutionProgress::default();
    // This is the same pinned public SDK path as ExternalProver::execute, with
    // a counter-only callback. Private assets are dropped on each callback.
    let executed = ApiClient::new_sub_process(&local.server_path).and_then(|client| {
        client.execute(
            &env,
            Asset::Inline(program.to_vec().into()),
            AssetRequest::Inline,
            |info, asset| {
                drop(asset);
                progress.include(info.po2, info.cycles)?;
                Ok(())
            },
        )
    });
    let session = match executed {
        Ok(session) => session,
        Err(error) => {
            // Inspect the cause locally for one reviewed category; never emit
            // the SDK error chain, segment assets, PC, trace or private bytes.
            let cause = format!("{error:#}");
            progress.emit_failure(
                preflight_executor_category(&cause),
                max_cycles,
                feed.completion.bytes_fed(),
                input.length,
            );
            return Err(preflight_executor_error(&cause));
        }
    };
    let user_cycles = session.cycles();
    let validated = feed
        .completion
        .finish(Some(feed.expected_digest))
        .and_then(|_| input.check_unchanged())
        .and_then(|_| {
            check_session(
                session.exit_code,
                &session.journal.bytes,
                user_cycles,
                expected_journal,
                max_cycles,
            )
        });
    if let Err(message) = validated {
        progress.emit_failure(
            "result-validation",
            max_cycles,
            feed.completion.bytes_fed(),
            input.length,
        );
        return Err(message);
    }
    Ok(Preflight {
        user_cycles,
        segments: session.segments.len(),
        max_cycles,
    })
}

/// Match the pinned SDK's executor failure category without exposing its cause.
/// Alternate Display includes any IPC context chain; none of it is logged.
fn preflight_executor_error(cause: &str) -> &'static str {
    if cause.contains("Session limit exceeded") {
        "Execution-only preflight exceeded the selected finite session cycle budget; payload suppressed."
    } else {
        "Execution-only preflight failed in the pinned executor; payload suppressed."
    }
}

fn preflight_executor_category(cause: &str) -> &'static str {
    if cause.contains("Session limit exceeded") {
        "session-limit"
    } else {
        "executor"
    }
}

fn check_session(
    exit_code: ExitCode,
    journal: &[u8],
    user_cycles: u64,
    expected_journal: &[u8],
    max_cycles: u64,
) -> HostResult<()> {
    resources::validate_max_cycles(max_cycles)?;
    if exit_code != ExitCode::Halted(0) {
        return Err("Guest execution did not halt with exit code zero.");
    }
    if user_cycles > max_cycles {
        return Err("Guest execution exceeded the selected finite session cycle budget.");
    }
    if journal != expected_journal {
        return Err(
            "Executed guest journal differs from the independently derived canonical journal.",
        );
    }
    Ok(())
}

pub fn generate(
    local: &LocalProver,
    input: &mut TransitionInput,
    program: &[u8],
    expected_journal: &[u8],
    expected_image_id: [u8; 32],
    max_cycles: u64,
) -> HostResult<VerifiedProof> {
    let image_id = checked_image(program, expected_image_id)?;
    let feed = input.guest_input()?;
    let env = bounded_env(feed.reader, max_cycles)?;
    let opts = ProverOpts::groth16().with_dev_mode(false);
    // Construct the prover with the validated path instead of SDK fallback
    // discovery. No remote service, network prover or development receipt is used.
    let result = ExternalProver::new("ipc", &local.server_path)
        .prove_with_opts(env, program, &opts)
        .map_err(|error| {
            let category = crate::diagnostics::proof_error_category(
                &format!("{error:#}"),
                local.backend.requested_backend == "cuda",
            );
            crate::diagnostics::emit_proof_failure(category);
            "Real local Groth16 proof generation failed; payload suppressed."
        })?;
    feed.completion.finish(Some(feed.expected_digest))?;
    input.check_unchanged()?;
    if result.stats.user_cycles > max_cycles {
        return Err("Proof execution exceeded the selected finite session cycle budget.");
    }
    let receipt = result.receipt;
    let inner = match &receipt.inner {
        InnerReceipt::Groth16(inner) => inner,
        _ => {
            return Err(
                "Proof host requires an actual Groth16 receipt; fake or other kinds refused.",
            );
        }
    };
    if hex::encode(inner.verifier_parameters.as_bytes()) != VERIFIER_PARAMETERS {
        return Err(
            "Groth16 verifier parameter digest differs from the canonical staged verifier.",
        );
    }
    if inner.seal.len() != PROOF_BYTES {
        return Err("Groth16 receipt does not contain exactly 256 proof bytes.");
    }
    if receipt.journal.bytes != expected_journal {
        return Err(
            "Guest journal differs from independently executed canonical transition bytes.",
        );
    }
    receipt
        .verify(image_id)
        .map_err(|_| "Generated receipt failed successful-image and journal verification.")?;
    let mut seal = Vec::with_capacity(SELECTOR.len() + PROOF_BYTES);
    seal.extend_from_slice(&SELECTOR);
    seal.extend_from_slice(&inner.seal);
    Ok(VerifiedProof {
        receipt,
        image_id,
        seal,
        stats: result.stats,
        prover_sha256: local.server_sha256,
        backend: local.backend.clone(),
        max_cycles,
    })
}

#[cfg(test)]
mod tests {
    use super::{SEGMENT_LIMIT_PO2, bounded_env, check_session, preflight_executor_error};
    use crate::resources::DEFAULT_MAX_CYCLES;
    use risc0_zkvm::ExitCode;

    #[test]
    fn resource_environment_keeps_the_pinned_sdk_range_and_session_ceiling() {
        // Reviewed SDK 3.0.3 supports segment exponents 13 through 24.
        assert!((13..=24).contains(&SEGMENT_LIMIT_PO2));
        assert_eq!(DEFAULT_MAX_CYCLES, 268_435_456);
        assert!(
            bounded_env(
                std::io::Cursor::new(b"bounded framing check"),
                DEFAULT_MAX_CYCLES
            )
            .is_ok()
        );
        assert!(bounded_env(std::io::Cursor::new(b"bounded framing check"), 536_870_912).is_ok());
        assert!(bounded_env(std::io::Cursor::new(b"bounded framing check"), u64::MAX).is_ok());
        assert!(bounded_env(std::io::Cursor::new(b"bounded framing check"), 0).is_err());
    }

    #[test]
    fn preflight_accepts_only_a_successful_matching_bounded_session() {
        let journal = b"canonical journal";
        assert!(
            check_session(ExitCode::Halted(0), journal, 1, journal, DEFAULT_MAX_CYCLES).is_ok()
        );
        assert!(
            check_session(
                ExitCode::Halted(0),
                journal,
                DEFAULT_MAX_CYCLES,
                journal,
                DEFAULT_MAX_CYCLES
            )
            .is_ok()
        );
        for exit_code in [
            ExitCode::Halted(1),
            ExitCode::Paused(0),
            ExitCode::SystemSplit,
            ExitCode::SessionLimit,
        ] {
            assert!(check_session(exit_code, journal, 1, journal, DEFAULT_MAX_CYCLES).is_err());
        }
        assert!(
            check_session(
                ExitCode::Halted(0),
                journal,
                DEFAULT_MAX_CYCLES + 1,
                journal,
                DEFAULT_MAX_CYCLES
            )
            .is_err()
        );
        assert!(
            check_session(
                ExitCode::Halted(0),
                b"other journal",
                1,
                journal,
                DEFAULT_MAX_CYCLES
            )
            .is_err()
        );
        assert!(check_session(ExitCode::Halted(0), b"", 1, journal, DEFAULT_MAX_CYCLES).is_err());
        assert!(
            check_session(
                ExitCode::Halted(0),
                journal,
                536_870_912,
                journal,
                536_870_912
            )
            .is_ok()
        );
        assert!(
            check_session(
                ExitCode::Halted(0),
                journal,
                536_870_913,
                journal,
                536_870_912
            )
            .is_err()
        );
        assert!(check_session(ExitCode::Halted(0), journal, 1, journal, 0).is_err());
    }

    #[test]
    fn preflight_executor_category_suppresses_context_and_payload() {
        assert_eq!(
            preflight_executor_error("IPC context: Session limit exceeded; private-input-marker"),
            "Execution-only preflight exceeded the selected finite session cycle budget; payload suppressed."
        );
        assert_eq!(
            preflight_executor_error("IPC context: another failure; private-input-marker"),
            "Execution-only preflight failed in the pinned executor; payload suppressed."
        );
    }
}
