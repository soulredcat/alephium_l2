//! A changed execution rule requires a fresh identity and rejects old storage.
#[allow(dead_code)]
#[path = "support/recovery_fixture.rs"]
mod fixture;

use alephium_l2_node::{
    development,
    operator::{self, SettlementDomain},
    protocol::{BLOCK_BYTES, BLOCK_GAS, BLOCK_INTERVAL_MS, Genesis, SCHEMA},
    storage::Store,
};
use alloy_primitives::{Address, B256, U256};
use fixture::{admit, commit, file_hashes, io_error};
use sha2::{Digest, Sha256};
use std::fs;

const MARKER: &str = ".alephium-l2-development";
const LEGACY_MARKER: &[u8] = b"alephium-l2-development-schema-1\n";

/// Independent schema-1 genesis encoding, retained only to check fork separation.
fn legacy_genesis_id(genesis: &Genesis) -> B256 {
    let domain = b"alephium-l2-development/genesis";
    let mut bytes = (domain.len() as u32).to_be_bytes().to_vec();
    bytes.extend(domain);
    bytes.extend(1_u32.to_be_bytes());
    bytes.extend(genesis.chain_id.to_be_bytes());
    bytes.extend(6_u32.to_be_bytes());
    bytes.extend(b"Cancun");
    bytes.extend(BLOCK_GAS.to_be_bytes());
    bytes.extend((BLOCK_BYTES as u64).to_be_bytes());
    bytes.extend(BLOCK_INTERVAL_MS.to_be_bytes());
    let mut accounts = genesis.accounts.clone();
    accounts.sort_by_key(|account| account.address);
    bytes.extend((accounts.len() as u32).to_be_bytes());
    for account in accounts {
        bytes.extend_from_slice(account.address.as_slice());
        bytes.extend(account.balance.to_be_bytes::<32>());
    }
    B256::from_slice(&Sha256::digest(bytes))
}

#[test]
fn profile_forks_identity_replays_fresh_state_and_refuses_legacy_before_writes()
-> Result<(), String> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let source = root.path().join("source");
    let backup = root.path().join("backup");
    let genesis = development::genesis();
    let mut store = Store::open(&source, &genesis)?;
    let genesis_id = store.view()?.head.genesis_id;
    assert_ne!(genesis_id, legacy_genesis_id(&genesis));
    assert_eq!(
        fs::read(source.join(MARKER)).map_err(io_error)?,
        format!("alephium-l2-development-schema-{SCHEMA}\n").as_bytes()
    );
    let fresh = Address::repeat_byte(0x51);
    let transfer = development::sign(0, Some(fresh), U256::ZERO, vec![], 21_000)?;
    admit(&mut store, &transfer, 1)?;
    commit(&mut store, &[transfer], 1)?;
    let head = store.view()?.head;
    assert!(
        store
            .view()?
            .execution_checkpoint()?
            .accounts
            .iter()
            .all(|account| account.address != fresh)
    );
    drop(store);
    let reopened = Store::open_existing(&source, &genesis)?;
    assert_eq!(reopened.view()?.head, head);
    drop(reopened);
    operator::backup(&source, &backup, &genesis)?;
    let domain = SettlementDomain {
        l1_network: 1,
        l1_genesis_id: B256::repeat_byte(0x11),
        settlement_contract_id: B256::repeat_byte(0x22),
    };
    let report = operator::prepare_transition_batch(
        &backup,
        &genesis,
        &root.path().join("export"),
        1,
        domain.clone(),
    )?;
    assert_eq!(report.head, head);
    assert!(report.semantic_replay_verified);

    // Simulate the schema-1 ownership boundary. Rejection must happen before
    // reading/recovering database records, so no old engine is needed here.
    fs::write(source.join(MARKER), LEGACY_MARKER).map_err(io_error)?;
    fs::write(backup.join("data").join(MARKER), LEGACY_MARKER).map_err(io_error)?;
    let before = file_hashes(root.path())?;
    assert!(Store::open(&source, &genesis).is_err());
    assert!(Store::open_existing(&source, &genesis).is_err());
    let output = root.path().join("must-not-exist");
    assert!(operator::backup(&source, &output, &genesis).is_err());
    assert!(!output.exists());
    let error = operator::verify_replay(&backup, &genesis, &output).unwrap_err();
    assert!(error.contains("Incompatible development storage profile"));
    assert!(!output.exists());
    assert!(operator::prepare_transition(&backup, &genesis, &output).is_err());
    assert!(!output.exists());
    assert!(
        operator::prepare_transition_batch(&backup, &genesis, &output, 1, domain.clone()).is_err()
    );
    assert!(!output.exists());
    assert!(
        operator::prepare_transition_checkpoint(&backup, &genesis, &output, 1, domain).is_err()
    );
    assert!(!output.exists());
    assert_eq!(file_hashes(root.path())?, before);
    Ok(())
}
