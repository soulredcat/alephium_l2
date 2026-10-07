use super::*;
use crate::protocol::{AccountChange, Head, checkpoint::*};
use alloy_primitives::{Address, U256};

fn profile() -> Capacity {
    // Retained chain identity, not a transaction workload or capacity claim.
    Capacity {
        block_gas: 3_000_000_000,
        block_bytes: 32 * 1024 * 1024,
        max_pending: 100_000,
    }
}

fn head(height: u64, genesis_id: B256) -> Head {
    Head {
        height,
        timestamp: height,
        commit_id: if height == 0 {
            genesis_commit(genesis_id)
        } else {
            B256::from(U256::from(height).to_be_bytes::<32>())
        },
        genesis_id,
    }
}

fn checkpoint(capacity: Capacity, height: u64) -> ExecutionCheckpoint {
    let genesis_id = B256::repeat_byte(0x31);
    let code = vec![0x60, 0x00];
    let code_hash = keccak256(&code);
    ExecutionCheckpoint {
        schema: capacity.checkpoint_schema(),
        chain_id: 424246,
        capacity,
        genesis_id,
        head: head(height, genesis_id),
        accounts: vec![
            CheckpointAccount {
                address: Address::repeat_byte(1),
                balance: U256::from(7),
                nonce: 1,
                code_hash,
                storage_epoch: 0,
                deleted: false,
                slots: vec![CheckpointSlot {
                    key: U256::from(1),
                    value: U256::from(9),
                }],
            },
            CheckpointAccount {
                address: Address::repeat_byte(2),
                balance: U256::ZERO,
                nonce: 1,
                code_hash,
                storage_epoch: 0,
                deleted: false,
                slots: vec![],
            },
            CheckpointAccount {
                address: Address::repeat_byte(3),
                balance: U256::ZERO,
                nonce: 0,
                code_hash: B256::ZERO,
                storage_epoch: 1,
                deleted: true,
                slots: vec![],
            },
        ],
        codes: vec![CheckpointCode {
            hash: code_hash,
            bytes: code,
        }],
        block_hashes: (height.saturating_sub(255)..=height)
            .map(|height| CheckpointBlockHash {
                height,
                hash: head(height, genesis_id).commit_id,
            })
            .collect(),
    }
}

#[test]
fn meter_matches_canonical_encoding_with_shared_code_and_tombstones() {
    for capacity in [
        Capacity::default(),
        Capacity {
            block_gas: 31_000_000,
            ..Capacity::default()
        },
        profile(),
    ] {
        for height in [0, 254, 255, 256] {
            let checkpoint = checkpoint(capacity, height);
            let mut state = FullState::from_checkpoint(&checkpoint).unwrap();
            // Old unreferenced code is retained in FullState but not encoded.
            let orphan = vec![0x00];
            state.codes.insert(keccak256(&orphan), orphan);
            let metered = state.checkpoint_encoded_bytes(capacity).unwrap();
            assert_eq!(metered, checkpoint.encode().unwrap().len());
            let rebuilt = state
                .checkpoint(
                    checkpoint.chain_id,
                    checkpoint.genesis_id,
                    &checkpoint.head,
                    capacity,
                )
                .unwrap();
            assert_eq!(metered, rebuilt.encode().unwrap().len());
            state.enforce_checkpoint_capacity(capacity).unwrap();
        }
    }
}

#[test]
fn producer_upper_guard_accepts_exact_reserved_size_and_rejects_one_byte_over() {
    for capacity in [Capacity::default(), profile()] {
        let limit = capacity.producer_checkpoint_bytes().unwrap();
        for height in [0, 254, 255, 256, u64::MAX] {
            let reserve = BLOCK_HASH_WINDOW.saturating_sub(height) as usize * BLOCK_HASH_BYTES;
            ensure_checkpoint_bytes(limit - reserve, height, capacity).unwrap();
            assert!(ensure_checkpoint_bytes(limit - reserve + 1, height, capacity).is_err());
        }
    }
    assert!(ensure_checkpoint_bytes(usize::MAX, 254, profile()).is_err());
    assert!(
        ensure_checkpoint_bytes(
            0,
            0,
            Capacity {
                max_pending: 0,
                ..profile()
            },
        )
        .is_err()
    );
    let mut bytes = 1;
    assert!(add_records(&mut bytes, usize::MAX, 2).is_err());
    assert_eq!(bytes, 1);
    assert!(add_records(&mut bytes, usize::MAX, 1).is_err());
    assert_eq!(bytes, 1);
}

#[test]
fn an_oversized_intermediate_block_is_not_excused_by_later_storage_shrink() {
    let checkpoint = checkpoint(profile(), 254);
    let mut state = FullState::from_checkpoint(&checkpoint).unwrap();
    let original_bytes = state.checkpoint_encoded_bytes(profile()).unwrap();
    // Small test-only budget exercises the production guard predicate without
    // allocating a large fixture or changing any declared chain capacity.
    let limit = original_bytes + BLOCK_HASH_BYTES;
    ensure_limit(original_bytes, 254, limit).unwrap();
    let account = &checkpoint.accounts[0];
    let mut change = AccountChange {
        address: account.address,
        balance: account.balance,
        nonce: account.nonce,
        code_hash: account.code_hash,
        slots: vec![
            (U256::from(2), U256::from(1)),
            (U256::from(3), U256::from(1)),
        ],
        ..Default::default()
    };
    state.apply(&[change.clone()]).unwrap();
    state
        .commit_head(&head(255, checkpoint.genesis_id))
        .unwrap();
    let oversized = state.checkpoint_encoded_bytes(profile()).unwrap();
    assert_eq!(
        oversized,
        original_bytes + BLOCK_HASH_BYTES + 2 * SLOT_BYTES
    );
    assert!(ensure_limit(oversized, 255, limit).is_err());
    // Continue only to demonstrate why checking the final state alone is wrong.
    for (_, value) in &mut change.slots {
        *value = U256::ZERO;
    }
    state.apply(&[change]).unwrap();
    state
        .commit_head(&head(256, checkpoint.genesis_id))
        .unwrap();
    let final_bytes = state.checkpoint_encoded_bytes(profile()).unwrap();
    assert_eq!(final_bytes, limit);
    ensure_limit(final_bytes, 256, limit).unwrap();
}

#[test]
fn meter_rejects_missing_executed_head_or_referenced_code() {
    let checkpoint = checkpoint(profile(), 0);
    let mut state = FullState::from_checkpoint(&checkpoint).unwrap();
    state.head = None;
    assert!(state.enforce_checkpoint_capacity(profile()).is_err());
    state.head = Some(checkpoint.head);
    state.codes.clear();
    assert!(state.enforce_checkpoint_capacity(profile()).is_err());
}
