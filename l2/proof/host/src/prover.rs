//! Execute the selected guest once and validate its actual Groth16 receipt.

use crate::{HostResult, cli::LocalProver};
use risc0_zkvm::{
    Digest, ExecutorEnv, ExternalProver, InnerReceipt, Prover, ProverOpts, Receipt, SessionStats,
    compute_image_id,
};

pub const SESSION_LIMIT_CYCLES: u64 = 256 * 1024 * 1024;
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
}

pub fn generate(
    local: &LocalProver,
    input: &[u8],
    program: &[u8],
    expected_journal: &[u8],
    expected_image_id: [u8; 32],
) -> HostResult<VerifiedProof> {
    let image_id = compute_image_id(program)
        .map_err(|_| "Cannot derive the guest image ID; a packaged ProgramBinary is required.")?;
    if image_id.as_bytes() != expected_image_id {
        return Err("Selected guest ProgramBinary differs from the expected image ID pin.");
    }
    let input_length = u32::try_from(input.len())
        .map_err(|_| "Private transition exceeds the framed input length limit.")?;
    // The guest bounds this little-endian length before allocating its buffer.
    // These are exact bytes, without the SDK Vec serializer's length encoding.
    let env = ExecutorEnv::builder()
        .session_limit(Some(SESSION_LIMIT_CYCLES))
        .write_slice(&input_length.to_le_bytes())
        .write_slice(input)
        .stdout(std::io::sink())
        .stderr(std::io::sink())
        .build()
        .map_err(|_| "Cannot construct bounded private guest environment.")?;
    let opts = ProverOpts::groth16().with_dev_mode(false);
    // Construct the prover with the validated path instead of SDK fallback
    // discovery. No remote service, network prover or development receipt is used.
    let result = ExternalProver::new("ipc", &local.server_path)
        .prove_with_opts(env, program, &opts)
        .map_err(|_| "Real local Groth16 proof generation failed; payload suppressed.")?;
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
    })
}
