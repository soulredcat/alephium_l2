//! Create-only proof artifacts, observed access metadata and a safe report.

use crate::{
    HostResult, cli,
    prover::{SESSION_LIMIT_CYCLES, VERIFIER_PARAMETERS, VerifiedProof},
};
use alephium_l2_transition_core::ProvenTransition;
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::File;
use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub struct ArtifactDirectory {
    path: PathBuf,
}

impl ArtifactDirectory {
    pub fn create(path: &Path) -> HostResult<Self> {
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = DirBuilder::new();
        builder
            .create(path)
            .map_err(|_| "Output must be a new directory under an existing writable parent.")?;
        let path = path
            .canonicalize()
            .map_err(|_| "Cannot resolve the new output directory.")?;
        if path.to_string_lossy().chars().any(char::is_control) {
            return Err("Resolved output directory contains a control character.");
        }
        Ok(Self { path })
    }

    pub fn persist(
        &self,
        input: &[u8],
        program: &[u8],
        journal: &ProvenTransition,
        proof: &VerifiedProof,
    ) -> HostResult<PathBuf> {
        let receipt_json = serde_json::to_vec(&proof.receipt)
            .map_err(|_| "Cannot serialize the actual verified receipt privately.")?;
        let statement_json = serde_json::to_vec_pretty(journal)
            .map_err(|_| "Cannot serialize the derived transition statement.")?;
        // Receipt and journal validation has already completed. Retain the
        // private continuation witness separately from the public statement.
        let checkpoint = journal
            .checkpoint()
            .map(|value| value.encode())
            .transpose()
            .map_err(|_| "Cannot encode the derived private execution checkpoint.")?;
        let journal_bytes = &proof.receipt.journal.bytes;
        let journal_digest = Sha256::digest(journal_bytes);
        self.write_new("receipt.json", &receipt_json)?;
        self.write_new("seal.bin", &proof.seal)?;
        self.write_new("imageid.bin", proof.image_id.as_bytes())?;
        self.write_new("journal.bin", journal_bytes)?;
        self.write_new("journal_digest.bin", &journal_digest)?;
        self.write_new("guest.bin", program)?;
        self.write_new("statement.json", &statement_json)?;
        if let Some(bytes) = &checkpoint {
            self.write_new("checkpoint.bin", bytes)?;
        }
        self.sync_directory()?;
        let (scope, blocks, transactions, before_accounts, after_accounts) = match journal {
            ProvenTransition::Native(journal) => (
                journal.proof_scope.as_str(),
                1,
                1,
                journal.before_account_count,
                journal.after_account_count,
            ),
            ProvenTransition::Batch(journal) => (
                journal.proof_scope.as_str(),
                journal.blocks,
                journal.executed_transactions,
                journal.before_account_count,
                journal.after_account_count,
            ),
            ProvenTransition::Checkpoint(output) => (
                output.journal.proof_scope.as_str(),
                output.journal.blocks,
                output.journal.executed_transactions,
                output.journal.before_account_count,
                output.journal.after_account_count,
            ),
        };
        let report = ProofReport {
            schema: 1,
            proof_scope: scope,
            sdk_version: cli::SDK_VERSION,
            sdk_revision: cli::SDK_REVISION,
            prover: "explicit-local-ipc",
            prover_sha256: hex::encode(proof.prover_sha256),
            receipt_kind: "groth16",
            dev_mode: false,
            proof_generated: true,
            receipt_verified: true,
            independent_journal_match: true,
            approved_guest: false,
            settlement_verified: false,
            general_evm_transition_claim: false,
            canonical_factory_acceptance_claim: false,
            input_bytes: input.len(),
            input_sha256: sha(input),
            guest_format: "risc0-ProgramBinary-v1",
            program_bytes: program.len(),
            program_sha256: sha(program),
            image_id: hex::encode(proof.image_id.as_bytes()),
            verifier_parameters: VERIFIER_PARAMETERS,
            journal_bytes: journal_bytes.len(),
            journal_sha256: hex::encode(journal_digest),
            receipt_bytes: receipt_json.len(),
            receipt_sha256: sha(&receipt_json),
            raw_proof_bytes: proof.seal.len() - 4,
            seal_bytes: proof.seal.len(),
            seal_sha256: sha(&proof.seal),
            blocks,
            executed_transactions: transactions,
            before_account_count: before_accounts,
            after_account_count: after_accounts,
            segments: proof.stats.segments,
            total_cycles: proof.stats.total_cycles,
            user_cycles: proof.stats.user_cycles,
            session_limit_cycles: SESSION_LIMIT_CYCLES,
            checkpoint_transport: checkpoint.as_ref().map(|bytes| CheckpointTransportReport {
                format: "alephium-l2/execution-checkpoint/v1",
                bytes: bytes.len(),
                sha256: sha(bytes),
                hash_purpose: "transport-integrity-only; not-a-state-root",
                authentication: "journal-new-state-root; requires-accepted-parent-chain",
            }),
            artifact_access_policy: self.access_policy(checkpoint.is_some())?,
        };
        let report_json = serde_json::to_vec_pretty(&report)
            .map_err(|_| "Cannot serialize the safe proof report.")?;
        // A complete report is the final marker; no proof bytes reach stdout.
        self.write_new("report.json", &report_json)?;
        self.sync_directory()?;
        Ok(self.path.join("report.json"))
    }

    fn write_new(&self, name: &str, bytes: &[u8]) -> HostResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(self.path.join(name)).map_err(
            |_| "Cannot create a private proof artifact; existing files are never replaced.",
        )?;
        file.write_all(bytes)
            .map_err(|_| "Cannot write a private proof artifact.")?;
        file.sync_all()
            .map_err(|_| "Cannot synchronize a private proof artifact.")
    }

    fn sync_directory(&self) -> HostResult<()> {
        #[cfg(unix)]
        File::open(&self.path)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Cannot synchronize the proof artifact directory.")?;
        // Windows inherits the parent's ACL. std does not establish equivalent
        // directory fsync or enforce a private DACL, so the report says so.
        #[cfg(not(unix))]
        std::fs::metadata(&self.path)
            .map_err(|_| "Cannot inspect the proof artifact directory.")?;
        Ok(())
    }

    fn access_policy(&self, checkpoint_present: bool) -> HostResult<String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let directory_mode = std::fs::metadata(&self.path)
                .map_err(|_| "Cannot inspect artifact directory permissions.")?
                .permissions()
                .mode()
                & 0o7777;
            let mut file_modes = Vec::new();
            let payloads = [
                "receipt.json",
                "seal.bin",
                "imageid.bin",
                "journal.bin",
                "journal_digest.bin",
                "guest.bin",
                "statement.json",
            ];
            for name in payloads
                .into_iter()
                .chain(checkpoint_present.then_some("checkpoint.bin"))
            {
                let mode = std::fs::metadata(self.path.join(name))
                    .map_err(|_| "Cannot inspect proof artifact permissions.")?
                    .permissions()
                    .mode()
                    & 0o7777;
                file_modes.push(mode);
            }
            let restrictive =
                directory_mode == 0o700 && file_modes.iter().all(|mode| *mode == 0o600);
            file_modes.sort_unstable();
            file_modes.dedup();
            let modes = file_modes
                .iter()
                .map(|mode| format!("{mode:04o}"))
                .collect::<Vec<_>>()
                .join(",");
            let policy = if restrictive {
                "requested-Unix-modes-observed; effective-ACL-access-unqualified"
            } else {
                "requested-Unix-modes-not-enforced; inherited-ACL/filesystem-access-unqualified; Windows-mounts-depend-on-Windows-ACLs"
            };
            Ok(format!(
                "observed-directory={directory_mode:04o}/payload-file-modes={modes}; {policy}; release-privacy-unqualified"
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = checkpoint_present;
            Ok("inherited-Windows-parent-ACL-not-inspected; release-privacy-unqualified".into())
        }
    }
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Serialize)]
struct ProofReport<'a> {
    schema: u32,
    proof_scope: &'a str,
    sdk_version: &'static str,
    sdk_revision: &'static str,
    prover: &'static str,
    prover_sha256: String,
    receipt_kind: &'static str,
    dev_mode: bool,
    proof_generated: bool,
    receipt_verified: bool,
    independent_journal_match: bool,
    approved_guest: bool,
    settlement_verified: bool,
    general_evm_transition_claim: bool,
    canonical_factory_acceptance_claim: bool,
    input_bytes: usize,
    input_sha256: String,
    guest_format: &'static str,
    program_bytes: usize,
    program_sha256: String,
    image_id: String,
    verifier_parameters: &'static str,
    journal_bytes: usize,
    journal_sha256: String,
    receipt_bytes: usize,
    receipt_sha256: String,
    raw_proof_bytes: usize,
    seal_bytes: usize,
    seal_sha256: String,
    blocks: u64,
    executed_transactions: u64,
    before_account_count: u32,
    after_account_count: u32,
    segments: usize,
    total_cycles: u64,
    user_cycles: u64,
    session_limit_cycles: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_transport: Option<CheckpointTransportReport>,
    artifact_access_policy: String,
}

#[derive(Serialize)]
struct CheckpointTransportReport {
    format: &'static str,
    bytes: usize,
    sha256: String,
    hash_purpose: &'static str,
    authentication: &'static str,
}
