//! Native bounded transport correctness; no guest, proving or settlement claim.
use alephium_l2_node::{development, execution, operator::*, protocol::*, storage::Store};
use alloy_primitives::{Address, B256, U256};
use proof_transport::ProofLimits;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Cursor, Write},
};

fn native_bundle(capacity: Capacity) -> Result<CheckpointTransitionBundle, String> {
    let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let mut genesis = development::genesis();
    genesis.capacity = capacity;
    let mut store = Store::open(directory.path(), &genesis)?;
    let checkpoint = store.view()?.execution_checkpoint()?;
    let recipient = Address::repeat_byte(0x75);
    let mut intent = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.path().join("unsigned-intent.json"))
        .map_err(|error| error.to_string())?;
    let metadata = serde_json::json!({"chain_id":genesis.chain_id,"nonce":0,"to":recipient,"value":1,"gas":21000});
    intent
        .write_all(
            serde_json::to_string(&metadata)
                .map_err(|error| error.to_string())?
                .as_bytes(),
        )
        .map_err(|error| error.to_string())?;
    intent.sync_all().map_err(|error| error.to_string())?;
    let raw = development::sign(0, Some(recipient), U256::from(1), vec![], 21_000)?;
    let context = BlockContext {
        number: 1,
        timestamp: 1_800_000_001,
        gas_limit: capacity.block_gas,
    };
    let info = execution::validate(store.view()?, &raw, context)?;
    store.admit(Pending {
        hash: info.hash,
        sender: info.sender,
        raw: raw.clone(),
    })?;
    let view = store.view()?;
    let executed = execution::execute_block(view.clone(), std::slice::from_ref(&raw), context)?;
    if !executed.rejected.is_empty() || executed.receipts.len() != 1 {
        return Err("native fixture execution failed".into());
    }
    store.commit(BlockCommit {
        parent: view.head,
        context,
        transactions: vec![info.hash],
        changes: executed.changes,
        receipts: executed.receipts,
        rejected: vec![],
    })?;
    let view = store.view()?;
    let block = view
        .replay_block(1)?
        .ok_or("missing native fixture block")?;
    Ok(CheckpointTransitionBundle {
        schema: 4,
        rpc_profile: "development/c5-v1".into(),
        execution_engine: "REVM 43.0.3/Cancun (same library as producer)".into(),
        domain: SettlementDomain {
            l1_network: 1,
            l1_genesis_id: B256::repeat_byte(0x11),
            settlement_contract_id: B256::repeat_byte(0x22),
        },
        checkpoint,
        blocks: vec![TransitionBlock {
            parent: block.parent,
            head: block.head,
            context: block.context.into(),
            transactions: vec![TransitionInput {
                transaction_hash: info.hash,
                raw_envelope_hex: RawEnvelope::from_bytes(raw)?,
                expected_receipt: block.receipts[0].clone(),
            }],
        }],
        head: view.head.clone(),
        expected_state_digest: view.state_digest()?,
    })
}

fn expanded() -> Capacity {
    Capacity {
        block_gas: 3_000_000_000,
        block_bytes: 32 * 1024 * 1024,
        max_pending: 100_000,
    }
}

#[test]
fn native_schema_four_roundtrips_slice_reader_and_streamed_roots() -> Result<(), String> {
    let bundle = native_bundle(expanded())?;
    let encoded = encode_large_checkpoint_transition(&bundle)?;
    assert_eq!(encoded.len(), large_checkpoint_transition_bytes(&bundle)?);
    assert!(is_checkpoint_wire(&encoded) && is_large_checkpoint_wire(&encoded));
    let (capacity, limits) = large_checkpoint_transition_header(&encoded)?;
    assert_eq!(capacity, expanded());
    assert_eq!(limits, ProofLimits::for_capacity(expanded())?);
    for decoded in [
        decode_large_checkpoint_transition(&encoded)?,
        decode_large_checkpoint_transition_reader(&mut Cursor::new(&encoded), encoded.len())?,
        decode_checkpoint_transition(&encoded)?,
    ] {
        assert_eq!(decoded.schema, 4);
        assert_eq!(decoded.head, bundle.head);
        assert_eq!(decoded.expected_state_digest, bundle.expected_state_digest);
        assert!(decoded.checkpoint == bundle.checkpoint);
        assert!(
            decoded.blocks[0].transactions[0].raw_envelope_hex
                == bundle.blocks[0].transactions[0].raw_envelope_hex,
            "private envelope changed"
        );
        assert!(
            encode_large_checkpoint_transition(&decoded)? == encoded,
            "canonical private wire bytes changed"
        );
    }
    let json = serde_json::to_value(&bundle).map_err(|_| "private JSON encoding failed")?;
    assert!(json["blocks"][0]["transactions"][0]["raw_envelope_hex"].is_string());
    let from_json: CheckpointTransitionBundle =
        serde_json::from_value(json).map_err(|_| "private JSON decoding failed")?;
    assert!(
        encode_large_checkpoint_transition(&from_json)? == encoded,
        "JSON boundary changed canonical private wire bytes"
    );
    let checkpoint_bytes = bundle.checkpoint.encode()?;
    let mut streamed = Sha256::new();
    bundle.checkpoint.write_encoded(&mut |bytes| {
        streamed.update(bytes);
        Ok(())
    })?;
    assert_eq!(
        B256::from_slice(&streamed.finalize()),
        B256::from_slice(&Sha256::digest(checkpoint_bytes))
    );
    let profile = B256::repeat_byte(0x31);
    let root = bundle.checkpoint.root_for_transport(
        profile,
        1,
        bundle.domain.l1_genesis_id,
        bundle.domain.settlement_contract_id,
        limits,
    )?;
    assert!(
        bundle
            .checkpoint
            .root(
                profile,
                1,
                bundle.domain.l1_genesis_id,
                bundle.domain.settlement_contract_id
            )
            .is_err()
    );
    let mut changed = limits;
    changed.frame_bytes += 1;
    assert!(
        bundle
            .checkpoint
            .root_for_transport(
                profile,
                1,
                bundle.domain.l1_genesis_id,
                bundle.domain.settlement_contract_id,
                changed
            )
            .is_err()
    );
    assert_ne!(
        root,
        bundle.checkpoint.root_for_transport(
            B256::repeat_byte(0x32),
            1,
            bundle.domain.l1_genesis_id,
            bundle.domain.settlement_contract_id,
            limits
        )?
    );
    Ok(())
}

#[test]
fn legacy_schema_three_bytes_and_root_namespace_remain_separate() -> Result<(), String> {
    let mut bundle = native_bundle(Capacity::default())?;
    bundle.schema = 3;
    let legacy = encode_checkpoint_transition(&bundle)?;
    let decoded = decode_checkpoint_transition(&legacy)?;
    assert!(
        encode_checkpoint_transition(&decoded)? == legacy,
        "legacy bytes changed"
    );
    assert!(!is_large_checkpoint_wire(&legacy));
    let profile = B256::repeat_byte(0x31);
    let old = bundle.checkpoint.root(
        profile,
        1,
        bundle.domain.l1_genesis_id,
        bundle.domain.settlement_contract_id,
    )?;
    let new = bundle.checkpoint.root_for_transport(
        profile,
        1,
        bundle.domain.l1_genesis_id,
        bundle.domain.settlement_contract_id,
        ProofLimits::for_capacity(Capacity::default())?,
    )?;
    assert_ne!(old, new);
    Ok(())
}

#[test]
fn header_frames_counts_and_trailing_bytes_fail_closed() -> Result<(), String> {
    let bundle = native_bundle(expanded())?;
    let encoded = encode_large_checkpoint_transition(&bundle)?;
    let mut changed = encoded.clone();
    let limit = LARGE_CHECKPOINT_WIRE_MAGIC.len() + 4 + 24;
    changed[limit + 7] ^= 1;
    assert!(decode_large_checkpoint_transition(&changed).is_err());
    let frame_start = LARGE_CHECKPOINT_HEADER_BYTES
        + 8
        + bundle.rpc_profile.len()
        + bundle.execution_engine.len()
        + 65;
    // Metadata follows total:u64,count:u32,index:u32,length:u32.
    let mut changed = encoded.clone();
    changed[frame_start + 11] = 0;
    assert!(decode_large_checkpoint_transition(&changed).is_err());
    let mut changed = encoded.clone();
    changed[frame_start + 15] = 1;
    assert!(decode_large_checkpoint_transition(&changed).is_err());
    let mut changed = encoded.clone();
    changed[frame_start + 19] ^= 1;
    assert!(decode_large_checkpoint_transition(&changed).is_err());
    let mut changed = encoded.clone();
    changed[frame_start..frame_start + 8].fill(0xff);
    assert!(decode_large_checkpoint_transition(&changed).is_err());
    let checkpoint_start = frame_start + 20;
    let mut changed = encoded.clone();
    // Checkpoint schema-three capacity follows domain(35),schema(4),chain(8).
    changed[checkpoint_start + 35 + 4 + 8 + 7] ^= 1;
    assert!(decode_large_checkpoint_transition(&changed).is_err());
    let mut changed = encoded.clone();
    changed.push(0);
    assert!(decode_large_checkpoint_transition(&changed).is_err());
    assert!(decode_large_checkpoint_transition(&encoded[..encoded.len() - 1]).is_err());
    Ok(())
}

#[test]
fn unsupported_larger_transport_does_not_invalidate_runtime_capacity() {
    let capacity = Capacity {
        block_gas: 21_000_000_000,
        block_bytes: 128 * 1024 * 1024,
        max_pending: 1_000_000,
    };
    assert!(capacity.validate().is_ok());
    assert!(ProofLimits::for_capacity(capacity).is_err());
}
