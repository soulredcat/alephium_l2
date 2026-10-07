//! Synthetic codec/framing checks only; no database, signing or EVM acceptance.
use alephium_l2_node::{
    operator::*,
    protocol::{
        Capacity, Head, Receipt, checkpoint::*, proof_transport::V4_CHECKPOINT_FRAME_BYTES,
    },
};
use alloy_primitives::{Address, B256, U256, keccak256};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

fn expanded() -> Capacity {
    Capacity {
        block_gas: 3_000_000_000,
        block_bytes: 32 * 1024 * 1024,
        max_pending: 100_000,
    }
}

fn prefix_len(capacity: Capacity) -> usize {
    35 + 4 + 8 + if capacity.is_default() { 0 } else { 24 }
}

fn checkpoint(capacity: Capacity, slots: usize) -> ExecutionCheckpoint {
    let genesis_id = B256::repeat_byte(1);
    let mut digest = Sha256::new();
    digest.update(b"alephium-l2-development/genesis-commit/v1");
    digest.update(genesis_id);
    let commit_id = B256::from_slice(&digest.finalize());
    let code = vec![0x60; 256];
    let code_hash = keccak256(&code);
    ExecutionCheckpoint {
        schema: capacity.checkpoint_schema(),
        chain_id: 424_249,
        capacity,
        genesis_id,
        head: Head {
            height: 0,
            timestamp: 0,
            commit_id,
            genesis_id,
        },
        accounts: vec![
            CheckpointAccount {
                address: Address::repeat_byte(1),
                balance: U256::from(9),
                nonce: 2,
                code_hash,
                storage_epoch: 1,
                deleted: false,
                slots: (0..slots)
                    .map(|index| CheckpointSlot {
                        key: U256::from(index + 1),
                        value: U256::from(index + 2),
                    })
                    .collect(),
            },
            CheckpointAccount {
                address: Address::repeat_byte(2),
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
        block_hashes: vec![CheckpointBlockHash {
            height: 0,
            hash: commit_id,
        }],
    }
}

fn streamed(bytes: &[u8], expected: Capacity) -> Result<ExecutionCheckpoint, String> {
    let mut source = Cursor::new(bytes);
    ExecutionCheckpoint::read_encoded_for_capacity(
        &mut |output| {
            source
                .read_exact(output)
                .map_err(|_| "truncated test source".into())
        },
        bytes.len(),
        expected,
    )
}

#[test]
fn slice_and_stream_preserve_canonical_schemas_and_validation() -> Result<(), String> {
    for capacity in [
        Capacity::default(),
        Capacity {
            block_gas: 300_000_000,
            ..Capacity::default()
        },
        expanded(),
    ] {
        let fixture = checkpoint(capacity, 2);
        let bytes = fixture.encode()?;
        assert!(ExecutionCheckpoint::decode(&bytes)? == fixture);
        assert!(streamed(&bytes, capacity)? == fixture);
        assert!(streamed(&bytes, capacity)?.encode()? == bytes);
        let accounts_count = prefix_len(capacity) + 112;
        let account = accounts_count + 4;
        let slots_count = account + 101;
        let slots = slots_count + 4;
        let codes_count = account + 105 * 2 + 64 * 2;
        let code_len = codes_count + 4 + 32;
        let blocks_count = code_len + 4 + 256;
        let mut mutations = Vec::new();
        for offset in [
            accounts_count,
            slots_count,
            codes_count,
            code_len,
            blocks_count,
        ] {
            let mut changed = bytes.clone();
            changed[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            mutations.push(changed);
        }
        for flag in [1, 2] {
            let mut changed = bytes.clone();
            changed[account + 20] = flag; // Invalid lifecycle or noncanonical boolean.
            mutations.push(changed);
        }
        let mut changed = bytes.clone();
        changed[slots + 64..slots + 96].copy_from_slice(&bytes[slots..slots + 32]);
        mutations.push(changed); // Duplicate slot key.
        let mut changed = bytes.clone();
        changed[slots + 32..slots + 64].fill(0);
        mutations.push(changed); // Noncanonical zero slot.
        let mut changed = bytes.clone();
        changed[code_len + 4] ^= 1;
        mutations.push(changed); // Wrong code hash.
        let mut changed = bytes.clone();
        changed.push(0);
        mutations.push(changed);
        for changed in mutations {
            assert!(ExecutionCheckpoint::decode(&changed).is_err());
            assert!(streamed(&changed, capacity).is_err());
        }
        for end in [
            0,
            34,
            prefix_len(capacity) - 1,
            account + 100,
            bytes.len() - 1,
        ] {
            assert!(ExecutionCheckpoint::decode(&bytes[..end]).is_err());
            assert!(streamed(&bytes[..end], capacity).is_err());
        }
    }
    Ok(())
}

#[test]
fn capacity_and_declared_length_fail_before_reading_checkpoint_body() -> Result<(), String> {
    let capacity = expanded();
    let bytes = checkpoint(capacity, 0).encode()?;
    let prefix = prefix_len(capacity);
    for (expected, declared) in [
        (Capacity::default(), bytes.len()),
        (capacity, capacity.runtime_checkpoint_bytes()? + 1),
    ] {
        let mut consumed = 0;
        let result = ExecutionCheckpoint::read_encoded_for_capacity(
            &mut |output| {
                let end = consumed + output.len();
                assert!(
                    end <= prefix,
                    "decoder read the body before rejecting its profile"
                );
                output.copy_from_slice(&bytes[consumed..end]);
                consumed = end;
                Ok(())
            },
            declared,
            expected,
        );
        assert!(result.is_err());
        assert_eq!(consumed, prefix);
    }
    // Extra bytes available from the source are outside this declared payload.
    // Its account count must fail before either allocating or reading records.
    let count_end = prefix + 112 + 4;
    let mut consumed = 0;
    let result = ExecutionCheckpoint::read_encoded_for_capacity(
        &mut |output| {
            let end = consumed + output.len();
            assert!(
                end <= count_end,
                "count used bytes outside its declared payload"
            );
            output.copy_from_slice(&bytes[consumed..end]);
            consumed = end;
            Ok(())
        },
        count_end,
        capacity,
    );
    assert!(result.is_err());
    assert_eq!(consumed, count_end);
    Ok(())
}

fn bundle(checkpoint: ExecutionCheckpoint) -> CheckpointTransitionBundle {
    let parent = checkpoint.head.clone();
    let head = Head {
        height: 1,
        timestamp: 1,
        commit_id: B256::repeat_byte(3),
        genesis_id: checkpoint.genesis_id,
    };
    let hash = B256::repeat_byte(4);
    CheckpointTransitionBundle {
        schema: 4,
        rpc_profile: "codec-fixture".into(),
        execution_engine: "codec-fixture".into(),
        domain: SettlementDomain {
            l1_network: 1,
            l1_genesis_id: B256::repeat_byte(5),
            settlement_contract_id: B256::repeat_byte(6),
        },
        blocks: vec![TransitionBlock {
            parent,
            head: head.clone(),
            context: TransitionContext {
                number: 1,
                timestamp: 1,
                gas_limit: checkpoint.capacity.block_gas,
            },
            transactions: vec![TransitionInput {
                transaction_hash: hash,
                // Deliberately not a signed execution fixture.
                raw_envelope_hex: alephium_l2_node::operator::RawEnvelope::from_bytes(vec![1])
                    .expect("bounded unsigned transport fixture"),
                expected_receipt: Receipt {
                    hash,
                    from: Address::repeat_byte(1),
                    to: None,
                    contract: None,
                    success: true,
                    gas_used: 21_000,
                    gas_price: 0,
                    logs: vec![],
                    block_height: 1,
                    block_hash: head.commit_id,
                    transaction_index: 0,
                    cumulative_gas: 21_000,
                    first_log_index: 0,
                },
            }],
        }],
        checkpoint,
        head,
        expected_state_digest: B256::repeat_byte(7),
    }
}

struct ShortReads<'a>(&'a [u8]);
impl Read for ShortReads<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let size = output.len().min(7);
        self.0.read(&mut output[..size])
    }
}

#[test]
fn framed_decode_tolerates_short_reads_and_consumes_only_its_declaration() -> Result<(), String> {
    let fixture = bundle(checkpoint(expanded(), 2));
    let bytes = encode_large_checkpoint_transition(&fixture)?;
    let decoded = decode_large_checkpoint_transition_reader(&mut ShortReads(&bytes), bytes.len())?;
    assert!(decoded.checkpoint == fixture.checkpoint);
    let mut extra = bytes.clone();
    extra.extend_from_slice(&[0xa1, 0xb2, 0xc3]);
    let mut source = Cursor::new(extra);
    let decoded = decode_large_checkpoint_transition_reader(&mut source, bytes.len())?;
    assert!(decoded.checkpoint == fixture.checkpoint);
    assert_eq!(source.position(), bytes.len() as u64);
    Ok(())
}

#[test]
fn multiple_frames_preserve_cross_boundary_reads_and_reject_bad_partitions() -> Result<(), String> {
    let frame_bytes = V4_CHECKPOINT_FRAME_BYTES;
    // First case crosses the frame boundary within a code byte vector; the
    // second crosses within a fixed-width storage scalar. These are pure
    // format boundary fixtures, independent of transaction load/capacity tests.
    let code_start_without_slots = prefix_len(expanded()) + 112 + 4 + 2 * 105 + 4 + 36;
    for slots in [
        (frame_bytes - code_start_without_slots) / 64,
        frame_bytes / 64,
    ] {
        let fixture = bundle(checkpoint(expanded(), slots));
        let total = fixture.checkpoint.encoded_len()?;
        assert!(total > frame_bytes && total < 2 * frame_bytes);
        let bytes = encode_large_checkpoint_transition(&fixture)?;
        let decoded = decode_large_checkpoint_transition(&bytes)?;
        assert!(decoded.checkpoint == fixture.checkpoint);
        let frame_start = LARGE_CHECKPOINT_HEADER_BYTES
            + 8
            + fixture.rpc_profile.len()
            + fixture.execution_engine.len()
            + 65;
        let second_frame = frame_start + 20 + frame_bytes;
        let checkpoint_end = second_frame + 8 + total - frame_bytes;
        for offset in [second_frame, second_frame + 4] {
            let mut changed = bytes.clone();
            changed[offset + 3] ^= 1;
            assert!(decode_large_checkpoint_transition(&changed).is_err());
        }
        for end in [
            second_frame + 3,
            second_frame + 6,
            second_frame + 25,
            checkpoint_end - 1,
        ] {
            assert!(
                decode_large_checkpoint_transition_reader(
                    &mut Cursor::new(&bytes[..end]),
                    bytes.len()
                )
                .is_err()
            );
        }
        let mut changed = bytes.clone();
        changed[frame_start..frame_start + 8].copy_from_slice(&((total + 1) as u64).to_be_bytes());
        changed[second_frame + 4..second_frame + 8]
            .copy_from_slice(&((total - frame_bytes + 1) as u32).to_be_bytes());
        changed.insert(checkpoint_end, 0);
        assert!(decode_large_checkpoint_transition(&changed).is_err());
    }
    Ok(())
}
