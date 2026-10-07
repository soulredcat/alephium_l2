//! Exact DA export/reconstruction from a separately pinned local candidate.
use super::{repository::PackageRepository, types::*};
use crate::{HostResult, inputs::CheckedFile};
use alephium_l2_transition_core::{
    BatchTransitionJournal, ProofInput, ProvenTransition,
    da::{ExpectedDa, read_checkpoint_da, reconstruct_checkpoint_da, write_checkpoint_da},
    decode_input_reader,
    protocol::{Capacity, proof_transport::ProofLimits},
    prove_input,
};
use std::{
    io::{BufReader, Write},
    path::Path,
};

/// A caller-selected JSON pin is an integrity boundary, not an accepted proof.
pub fn read_candidate(
    path: &Path,
    expected_json_sha256: &str,
) -> HostResult<BatchTransitionJournal> {
    let pin =
        hex::decode(expected_json_sha256).map_err(|_| "Candidate SHA-256 must be 32 bytes.")?;
    if pin.len() != 32 {
        return Err("Candidate SHA-256 must be 32 bytes.");
    }
    let bytes = crate::inputs::read_bounded(path, MANIFEST_LIMIT)?;
    if sha(&bytes) != hex::encode(pin) {
        return Err("Candidate JSON differs from the independent pin.");
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid bounded DA candidate journal.")
}

/// Local native derivation only. No guest, signer, RPC, node or prover is started.
pub fn export_package(input: &Path, output: &Path) -> HostResult<DaPackageReport> {
    let mut source = CheckedFile::open(input)?;
    let length =
        usize::try_from(source.length).map_err(|_| "DA source size exceeds host range.")?;
    let bundle = decode_input_reader(&mut BufReader::new(&mut source.file), length)
        .map_err(|_| "Invalid DA source transition; payload suppressed.")?;
    source.check_unchanged()?;
    let ProofInput::Checkpoint(ref checkpoint) = bundle else {
        return Err("DA export requires the current schema-four checkpoint transition.");
    };
    if checkpoint.schema != 4 {
        return Err("DA export does not change legacy reconstruction encodings.");
    }
    let capacity = checkpoint.checkpoint.capacity;
    let ProvenTransition::Checkpoint(native) =
        prove_input(&bundle).map_err(|_| "Native DA source replay failed; payload suppressed.")?
    else {
        return Err("DA source must produce a checkpoint journal.");
    };
    let repository = PackageRepository::create(output)?;
    let mut data = repository.create_file("data.bin")?;
    let encoded = write_checkpoint_da(checkpoint, &mut |bytes| {
        data.write_all(bytes)
            .map_err(|_| "Cannot write private canonical DA bytes.".into())
    })
    .map_err(|_| "Canonical DA encoding failed; payload suppressed.")?;
    data.sync_all()
        .map_err(|_| "Cannot synchronize canonical DA bytes.")?;
    drop(data);
    repository.sync_directory()?;
    if encoded.commitment != native.journal.da_commitment {
        return Err("DA writer differs from the unchanged native journal commitment.");
    }
    let expected = ExpectedDa {
        journal: &native.journal,
        capacity,
    };
    let reconstructed = reconstruct_data(&repository, encoded.bytes, &expected)?;
    if reconstructed
        .checkpoint
        .encode()
        .map_err(|_| "Cannot encode reconstructed checkpoint.")?
        != native
            .checkpoint
            .encode()
            .map_err(|_| "Cannot encode native checkpoint.")?
    {
        return Err("Clean DA reconstruction differs from the native checkpoint.");
    }
    source.check_unchanged()?;
    let manifest = PackageManifest {
        schema: 1,
        encoding: "alephium-l2/reconstruction/checkpoint-suffix/v4".into(),
        data_file: "data.bin".into(),
        data_bytes: encoded.bytes,
        da_commitment: native.journal.da_commitment.to_string(),
        candidate_journal_sha256: journal_sha(&native.journal)?,
        capacity,
    };
    repository.write_new("candidate-journal.json", &json(&native.journal)?)?;
    repository.write_new(
        "retention.json",
        &json(&RetentionRecord::expected(&manifest))?,
    )?;
    let report = report(&manifest, &reconstructed)?;
    repository.write_new("report.json", &json(&report)?)?;
    // Completeness marker last: earlier partial files never authorize reuse.
    repository.write_new("manifest.json", &json(&manifest)?)?;
    Ok(report)
}

/// Caller supplies a separately pinned candidate, never authority from manifest.
pub fn reconstruct_package(
    package: &Path,
    journal: &BatchTransitionJournal,
    capacity: Capacity,
    output: &Path,
) -> HostResult<DaPackageReport> {
    let repository = PackageRepository::open(package)?;
    let manifest: PackageManifest =
        serde_json::from_slice(&repository.read("manifest.json", MANIFEST_LIMIT)?)
            .map_err(|_| "Invalid or incomplete DA package manifest.")?;
    let limits =
        ProofLimits::for_capacity(capacity).map_err(|_| "Unsupported DA candidate capacity.")?;
    if manifest.schema != 1
        || manifest.data_file != "data.bin"
        || manifest.encoding != "alephium-l2/reconstruction/checkpoint-suffix/v4"
        || manifest.data_bytes == 0
        || manifest.data_bytes > limits.input_bytes
        || manifest.capacity != capacity
        || manifest.da_commitment != journal.da_commitment.to_string()
        || manifest.candidate_journal_sha256 != journal_sha(journal)?
    {
        return Err("DA manifest differs from the independently pinned candidate.");
    }
    let retention: RetentionRecord =
        serde_json::from_slice(&repository.read("retention.json", MANIFEST_LIMIT)?)
            .map_err(|_| "Missing or invalid DA retention record; retain and refuse reuse.")?;
    if retention != RetentionRecord::expected(&manifest) {
        return Err("DA retention record conflicts with the candidate; retain and refuse reuse.");
    }
    let expected = ExpectedDa { journal, capacity };
    let reconstructed = reconstruct_data(&repository, manifest.data_bytes, &expected)?;
    let target = PackageRepository::create(output)?;
    let report = report(&manifest, &reconstructed)?;
    target.write_new(
        "checkpoint.bin",
        &reconstructed
            .checkpoint
            .encode()
            .map_err(|_| "Cannot encode reconstructed checkpoint.")?,
    )?;
    target.write_new(
        "journal.bin",
        &reconstructed
            .journal
            .encode()
            .map_err(|_| "Cannot encode reconstructed native journal.")?,
    )?;
    target.write_new("report.json", &json(&report)?)?;
    Ok(report)
}

fn reconstruct_data(
    repository: &PackageRepository,
    length: usize,
    expected: &ExpectedDa<'_>,
) -> HostResult<alephium_l2_transition_core::CheckpointTransitionOutput> {
    let mut source = repository.checked_data()?;
    if source.length != length as u64 {
        return Err("DA package data length differs from its complete marker.");
    }
    let decoded = read_checkpoint_da(&mut BufReader::new(&mut source.file), length, expected)
        .map_err(|_| "Invalid canonical DA data; payload suppressed.")?;
    source.check_unchanged()?;
    reconstruct_checkpoint_da(decoded, expected)
        .map_err(|_| "DA candidate reconstruction mismatch; payload suppressed.")
}

fn report(
    manifest: &PackageManifest,
    output: &alephium_l2_transition_core::CheckpointTransitionOutput,
) -> HostResult<DaPackageReport> {
    let bytes = output
        .checkpoint
        .encode()
        .map_err(|_| "Cannot encode DA checkpoint.")?;
    Ok(DaPackageReport {
        schema: 1,
        scope: "local-native-candidate-reconstruction-only".into(),
        data_bytes: manifest.data_bytes,
        da_commitment: manifest.da_commitment.clone(),
        candidate_journal_sha256: manifest.candidate_journal_sha256.clone(),
        blocks: output.journal.blocks,
        executed_transactions: output.journal.executed_transactions,
        checkpoint_bytes: bytes.len(),
        checkpoint_sha256: sha(&bytes),
        native_reconstruction_verified: true,
        proof_accepted: false,
        settlement_eligible: false,
        public_data_available: false,
        retention_policy: RETENTION_POLICY.into(),
    })
}

fn json(value: &impl serde::Serialize) -> HostResult<Vec<u8>> {
    serde_json::to_vec_pretty(value).map_err(|_| "Cannot encode safe DA metadata.")
}
