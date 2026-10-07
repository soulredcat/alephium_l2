//! Format-boundary coverage, without an execution/load or proving experiment.
use super::{block, encoding::MAX_RECORD, records};
use crate::{development, protocol::*};
use alloy_primitives::{Address, B256, U256, keccak256};

#[test]
fn expanded_records_and_checkpoints_roundtrip_above_legacy_bound() {
    let mut genesis = development::genesis();
    genesis.capacity = Capacity {
        block_gas: 3_000_000_000,
        block_bytes: 32 * 1024 * 1024,
        max_pending: 100_000,
    };
    let parent = records::genesis_head(&records::genesis_bytes(&genesis).unwrap());
    let mut stored = Vec::new();
    for index in 0..700u64 {
        // Each code is within Cancun's unchanged 24,576-byte limit. Distinct
        // code references exercise a >16 MiB record without a large TX run.
        let mut code = vec![0; 24_576];
        code[..8].copy_from_slice(&index.to_be_bytes());
        stored.push(block::StoredChange {
            change: AccountChange {
                address: Address::from_word(B256::from(U256::from(index + 100_000))),
                code_hash: keccak256(&code),
                code: Some(code),
                nonce: 1,
                ..Default::default()
            },
            epoch: 0,
        });
    }
    let hash = B256::repeat_byte(0x61);
    let receipt = Receipt {
        hash,
        from: development::address(),
        to: Some(Address::repeat_byte(0x62)),
        contract: None,
        success: true,
        gas_used: 21_000,
        gas_price: 1,
        logs: vec![],
        block_height: 1,
        block_hash: B256::ZERO,
        transaction_index: 0,
        cumulative_gas: 21_000,
        first_log_index: 0,
    };
    let commit = BlockCommit {
        parent: parent.clone(),
        context: BlockContext {
            number: 1,
            timestamp: 0,
            gas_limit: genesis.capacity.block_gas,
        },
        transactions: vec![hash],
        changes: stored.iter().map(|item| item.change.clone()).collect(),
        receipts: vec![receipt],
        rejected: vec![],
    };
    let (head, record) = block::encode_with_capacity(&commit, &stored, genesis.capacity).unwrap();
    drop(commit);
    assert!(record.len() > MAX_RECORD);
    assert!(record.len() < genesis.capacity.runtime_record_bytes().unwrap());
    assert!(block::decode(&record).is_err());
    let decoded = block::decode_with_capacity(&record, genesis.capacity).unwrap();
    assert_eq!(decoded.head, head);
    assert_eq!(decoded.changes.len(), stored.len());
    assert_eq!(decoded.receipts.len(), 1);
    assert!(block::decode_with_capacity(&record[..record.len() - 1], genesis.capacity).is_err());
    drop(decoded);
    drop(record);

    let mut accounts = Vec::new();
    let mut codes = Vec::new();
    for item in stored {
        accounts.push(checkpoint::CheckpointAccount {
            address: item.change.address,
            balance: item.change.balance,
            nonce: item.change.nonce,
            code_hash: item.change.code_hash,
            storage_epoch: item.epoch,
            deleted: false,
            slots: vec![],
        });
        codes.push(checkpoint::CheckpointCode {
            hash: item.change.code_hash,
            bytes: item.change.code.unwrap(),
        });
    }
    codes.sort_by_key(|code| code.hash);
    let checkpoint = checkpoint::ExecutionCheckpoint {
        schema: 3,
        chain_id: genesis.chain_id,
        capacity: genesis.capacity,
        genesis_id: head.genesis_id,
        head: head.clone(),
        accounts,
        codes,
        block_hashes: vec![
            checkpoint::CheckpointBlockHash {
                height: 0,
                hash: parent.commit_id,
            },
            checkpoint::CheckpointBlockHash {
                height: 1,
                hash: head.commit_id,
            },
        ],
    };
    let encoded = checkpoint.encode().unwrap();
    assert!(encoded.len() > MAX_RECORD);
    assert!(encoded.len() < genesis.capacity.runtime_checkpoint_bytes().unwrap());
    let recovered = checkpoint::ExecutionCheckpoint::decode(&encoded).unwrap();
    assert!(
        recovered == checkpoint,
        "expanded checkpoint changed during decoding"
    );
    assert!(checkpoint::ExecutionCheckpoint::decode(&encoded[..encoded.len() - 1]).is_err());
    assert!(
        checkpoint
            .root(
                B256::repeat_byte(1),
                1,
                B256::repeat_byte(2),
                B256::repeat_byte(3)
            )
            .is_err()
    );
    let bundle = crate::operator::CheckpointTransitionBundle {
        schema: 3,
        rpc_profile: "dev".into(),
        execution_engine: "revm".into(),
        domain: crate::operator::SettlementDomain {
            l1_network: 1,
            l1_genesis_id: B256::repeat_byte(2),
            settlement_contract_id: B256::repeat_byte(3),
        },
        checkpoint,
        blocks: vec![],
        head,
        expected_state_digest: B256::ZERO,
    };
    let error = crate::operator::encode_checkpoint_transition(&bundle).unwrap_err();
    assert!(error.contains("fixed proof transport"), "{error}");
}
