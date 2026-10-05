//! Reuse an immutable runtime fixture; never sign or submit new transactions.
#[allow(dead_code)]
#[path = "support/recovery_fixture.rs"]
mod fixture;

use alephium_l2_node::{
    config, development,
    operator::{self, BackupManifest, SettlementDomain},
    protocol::CHAIN_ID,
};
use alloy_primitives::{B256, keccak256};
use fixture::{file_hashes, io_error};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "Requires L2_CHECKPOINT_FIXTURE pointing to the retained four-block transition fixture"]
fn export_retained_checkpoint_as_canonical_binary() -> Result<(), String> {
    let fixture = PathBuf::from(
        std::env::var_os("L2_CHECKPOINT_FIXTURE")
            .ok_or("Set L2_CHECKPOINT_FIXTURE to the existing immutable four-block fixture")?,
    );
    let genesis = config::load_genesis(&fixture.join("genesis.json"), CHAIN_ID)?;
    let backup = fixture.join("backup");
    let inventory = file_hashes(&backup)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&fs::read(backup.join("manifest.json")).map_err(io_error)?)
            .map_err(|_| "Invalid retained fixture manifest")?;
    if manifest.head.height != 4 || manifest.pending_count != 0 {
        return Err("Checkpoint test requires the retained four-block completed fixture".into());
    }
    let temporary = tempfile::Builder::new()
        .prefix("l2-p4-checkpoint-")
        .tempdir()
        .map_err(io_error)?;
    let output = if let Some(path) = std::env::var_os("L2_CHECKPOINT_OUTPUT") {
        let output = PathBuf::from(path);
        fs::create_dir(&output).map_err(io_error)?;
        output
    } else {
        temporary.path().to_path_buf()
    };
    let domain = SettlementDomain {
        l1_network: 1,
        l1_genesis_id: B256::from([0x11; 32]),
        settlement_contract_id: B256::from([0x22; 32]),
    };
    let genesis_report = operator::prepare_transition_checkpoint(
        &backup, &genesis, &output.join("genesis-export"), 1, domain.clone(),
    )?;
    let genesis_bytes = fs::read(&genesis_report.bundle_path).map_err(io_error)?;
    let genesis_bundle = operator::decode_checkpoint_transition(&genesis_bytes)?;
    assert_eq!(genesis_bundle.checkpoint.head.height, 0);
    assert_eq!(genesis_bundle.blocks.len(), 4);
    assert!(genesis_bundle.checkpoint.codes.is_empty());
    assert!(genesis_bundle.checkpoint.accounts.iter().all(|account| account.nonce == 0 && account.slots.is_empty()));
    let report = operator::prepare_transition_checkpoint(
        &backup,
        &genesis,
        &output.join("export"),
        3,
        domain.clone(),
    )?;
    assert_eq!(report.schema, 3);
    assert_eq!(report.parent.height, 2);
    assert_eq!(report.head, manifest.head);
    assert_eq!(report.expected_state_digest, manifest.state_digest);
    assert_eq!(report.blocks, 2);
    assert_eq!(report.executed_transactions, 2);
    assert_eq!(report.replayed_blocks, 4);
    assert!(report.semantic_replay_verified);
    assert!(!report.guest_proof_generated && !report.settlement_verified);
    assert_eq!(
        report
            .bundle_path
            .file_name()
            .and_then(|name| name.to_str()),
        Some("transition.bin")
    );
    assert!(!output.join("export/transition.json").exists());
    let bytes = fs::read(&report.bundle_path).map_err(io_error)?;
    assert_eq!(bytes.len(), report.bundle_bytes);
    assert_eq!(
        B256::from_slice(&Sha256::digest(&bytes)),
        report.bundle_sha256
    );
    assert!(operator::is_checkpoint_wire(&bytes));
    let bundle = operator::decode_checkpoint_transition(&bytes)?;
    assert_eq!(bundle.domain, domain);
    assert_eq!(bundle.checkpoint.head, report.parent);
    assert_eq!(bundle.checkpoint.block_hashes.len(), 3);
    assert_eq!(bundle.blocks.len(), 2);
    assert_eq!(bundle.blocks[0].context.number, 3);
    assert_eq!(bundle.blocks[1].context.number, 4);
    assert_eq!(bundle.blocks[0].parent, bundle.checkpoint.head);
    assert_eq!(bundle.blocks[1].parent, bundle.blocks[0].head);
    assert!(bundle.blocks[0].transactions[0].expected_receipt.success);
    assert!(!bundle.blocks[1].transactions[0].expected_receipt.success);
    let sender = bundle
        .checkpoint
        .accounts
        .iter()
        .find(|account| account.address == development::address())
        .ok_or("Missing sender in retained checkpoint")?;
    assert_eq!(sender.nonce, 2);
    let contract = bundle
        .checkpoint
        .accounts
        .iter()
        .find(|account| {
            !account.deleted
                && account.code_hash != B256::ZERO
                && account.code_hash != keccak256([])
        })
        .ok_or("Missing deployed contract in retained checkpoint")?;
    assert!(
        contract.slots.is_empty(),
        "Height-two checkpoint must precede contract writes"
    );
    assert_eq!(bundle.checkpoint.codes.len(), 1);
    assert_eq!(
        bundle.checkpoint.codes[0].bytes,
        development::contract_runtime()
    );
    assert_eq!(
        B256::from_slice(&Sha256::digest(bundle.checkpoint.encode()?)),
        report.checkpoint_sha256
    );
    // Bool assertions deliberately avoid dumping private binary signed input.
    assert!(
        operator::encode_checkpoint_transition(&bundle)? == bytes,
        "Binary roundtrip differs"
    );
    assert!(operator::decode_checkpoint_transition(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(operator::decode_checkpoint_transition(&trailing).is_err());
    let mut oversized_checkpoint = operator::encode_checkpoint_transition(&bundle)?;
    let checkpoint_length_offset = b"ALEPHIUM-L2/TRANSITION/WIRE/V3\0".len() + 4
        + 4 + bundle.rpc_profile.len() + 4 + bundle.execution_engine.len() + 65;
    oversized_checkpoint[checkpoint_length_offset..checkpoint_length_offset + 4]
        .copy_from_slice(&(8 * 1024 * 1024 + 1_u32).to_be_bytes());
    assert!(operator::decode_checkpoint_transition(&oversized_checkpoint).is_err());
    assert_eq!(file_hashes(&backup)?, inventory);
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report).map_err(|_| "Cannot encode safe checkpoint report")?,
    )
    .map_err(io_error)?;
    fs::write(output.join("genesis-report.json"), serde_json::to_vec_pretty(&genesis_report)
        .map_err(|_| "Cannot encode safe genesis checkpoint report")?).map_err(io_error)?;
    Ok(())
}
