//! Normative binary schema-three input. Never log encoded signed envelopes.
use super::transition_types::{
    CheckpointTransitionBundle, MAX_TRANSITION_BLOCKS, SettlementDomain, TransitionBlock,
    TransitionContext, TransitionInput,
};
use crate::protocol::{
    BLOCK_BYTES, MAX_PENDING, MAX_TRANSACTION_BYTES, Receipt,
    checkpoint::ExecutionCheckpoint,
    encoding::{Decoder, Encoder, MAX_RECORD},
    head_codec::{encode_head, read_head},
    receipt_codec::{decode_receipt, encode_receipt},
};

pub const CHECKPOINT_WIRE_MAGIC: &[u8] = b"ALEPHIUM-L2/TRANSITION/WIRE/V3\0";
pub const MAX_CHECKPOINT_WIRE_BYTES: usize = MAX_RECORD;
pub const MAX_CONTINUATION_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROFILE_BYTES: usize = 256;

pub fn is_checkpoint_wire(bytes: &[u8]) -> bool {
    bytes.starts_with(CHECKPOINT_WIRE_MAGIC)
}

/// Includes all fixed outer fields and the checkpoint frame, excluding blocks.
/// Exporters use this and the block meter before retaining further input data.
pub fn checkpoint_transition_base_bytes(
    rpc_profile: &str,
    execution_engine: &str,
    checkpoint_bytes: usize,
) -> Result<usize, String> {
    if checkpoint_bytes == 0 || checkpoint_bytes > MAX_CONTINUATION_CHECKPOINT_BYTES {
        return Err("continuation checkpoint exceeds the eight MiB transport profile".into());
    }
    for profile in [rpc_profile, execution_engine] {
        if profile.is_empty() || profile.len() > MAX_PROFILE_BYTES {
            return Err("transition profile string exceeds its bound".into());
        }
    }
    // Schema, two string frames, L1 domain, checkpoint frame, block count,
    // final head and final logical-state digest.
    let mut size = CHECKPOINT_WIRE_MAGIC.len() + 4 + 8 + 65 + 4 + 4 + 80 + 32;
    add(&mut size, rpc_profile.len())?;
    add(&mut size, execution_engine.len())?;
    add(&mut size, checkpoint_bytes)?;
    Ok(size)
}

pub fn checkpoint_transition_block_bytes(block: &TransitionBlock) -> Result<usize, String> {
    if block.transactions.is_empty() || block.transactions.len() > MAX_PENDING {
        return Err("transition block transaction count exceeds its bound".into());
    }
    let mut size = 80 + 80 + 24 + 4;
    let mut logical_bytes = 148usize;
    for transaction in &block.transactions {
        let raw = raw_length(&transaction.raw_envelope_hex)?;
        logical_bytes = logical_bytes
            .checked_add(4 + raw)
            .ok_or("block byte overflow")?;
        if logical_bytes > BLOCK_BYTES {
            return Err("transition block exceeds the runtime payload bound".into());
        }
        add(&mut size, 32 + 4 + raw + 4)?;
        add(&mut size, receipt_bytes(&transaction.expected_receipt)?)?;
    }
    Ok(size)
}

pub fn encode_checkpoint_transition(
    bundle: &CheckpointTransitionBundle,
) -> Result<Vec<u8>, String> {
    bundle.domain.validate()?;
    if bundle.schema != 3
        || bundle.blocks.is_empty()
        || bundle.blocks.len() as u64 > MAX_TRANSITION_BLOCKS
    {
        return Err("unsupported binary transition version or block count".into());
    }
    let checkpoint = bundle.checkpoint.encode()?;
    let mut size = checkpoint_transition_base_bytes(
        &bundle.rpc_profile,
        &bundle.execution_engine,
        checkpoint.len(),
    )?;
    for block in &bundle.blocks {
        add(&mut size, checkpoint_transition_block_bytes(block)?)?;
    }
    // The complete size is checked before allocating the transport buffer.
    let mut out = Encoder(Vec::with_capacity(size));
    out.0.extend_from_slice(CHECKPOINT_WIRE_MAGIC);
    out.u32(3);
    out.bytes(bundle.rpc_profile.as_bytes())?;
    out.bytes(bundle.execution_engine.as_bytes())?;
    out.byte(bundle.domain.l1_network);
    out.hash(bundle.domain.l1_genesis_id);
    out.hash(bundle.domain.settlement_contract_id);
    out.bytes(&checkpoint)?;
    out.u32(bundle.blocks.len() as u32);
    for block in &bundle.blocks {
        out.0.extend(encode_head(&block.parent));
        out.0.extend(encode_head(&block.head));
        out.u64(block.context.number);
        out.u64(block.context.timestamp);
        out.u64(block.context.gas_limit);
        out.u32(block.transactions.len() as u32);
        for transaction in &block.transactions {
            out.hash(transaction.transaction_hash);
            let raw = hex::decode(&transaction.raw_envelope_hex[2..])
                .map_err(|_| "invalid private envelope hex")?;
            out.bytes(&raw)?;
            out.bytes(&encode_receipt(&transaction.expected_receipt, true)?)?;
        }
    }
    out.0.extend(encode_head(&bundle.head));
    out.hash(bundle.expected_state_digest);
    if out.0.len() != size {
        return Err("binary transition size disagrees with its canonical meter".into());
    }
    out.finish()
}

pub fn decode_checkpoint_transition(bytes: &[u8]) -> Result<CheckpointTransitionBundle, String> {
    let mut input = Decoder::new(bytes)?;
    if input.take(CHECKPOINT_WIRE_MAGIC.len())? != CHECKPOINT_WIRE_MAGIC || input.u32()? != 3 {
        return Err("invalid binary checkpoint transition domain or version".into());
    }
    let rpc_profile = profile(&mut input)?;
    let execution_engine = profile(&mut input)?;
    let domain = SettlementDomain {
        l1_network: input.byte()?,
        l1_genesis_id: input.hash()?,
        settlement_contract_id: input.hash()?,
    };
    domain.validate()?;
    let checkpoint =
        ExecutionCheckpoint::decode(slice(&mut input, MAX_CONTINUATION_CHECKPOINT_BYTES)?)?;
    let count = input.count(376)?;
    if count == 0 || count as u64 > MAX_TRANSITION_BLOCKS {
        return Err("binary transition block count exceeds its bound".into());
    }
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let parent = read_head(&mut input)?;
        let head = read_head(&mut input)?;
        let context = TransitionContext {
            number: input.u64()?,
            timestamp: input.u64()?,
            gas_limit: input.u64()?,
        };
        let count = input.count(188)?;
        if count == 0 || count > MAX_PENDING {
            return Err("binary block transaction count exceeds its bound".into());
        }
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let transaction_hash = input.hash()?;
            let raw = slice(&mut input, MAX_TRANSACTION_BYTES)?;
            if raw.is_empty() {
                return Err("binary transition contains an empty envelope".into());
            }
            let expected_receipt = decode_receipt(slice(&mut input, MAX_RECORD)?, None)?;
            transactions.push(TransitionInput {
                transaction_hash,
                raw_envelope_hex: format!("0x{}", hex::encode(raw)),
                expected_receipt,
            });
        }
        let block = TransitionBlock {
            parent,
            head,
            context,
            transactions,
        };
        checkpoint_transition_block_bytes(&block)?;
        blocks.push(block);
    }
    let head = read_head(&mut input)?;
    let expected_state_digest = input.hash()?;
    input.finish()?;
    Ok(CheckpointTransitionBundle {
        schema: 3,
        rpc_profile,
        execution_engine,
        domain,
        checkpoint,
        blocks,
        head,
        expected_state_digest,
    })
}

fn profile(input: &mut Decoder<'_>) -> Result<String, String> {
    let bytes = slice(input, MAX_PROFILE_BYTES)?;
    if bytes.is_empty() {
        return Err("empty binary transition profile".into());
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| "invalid binary transition profile text".into())
}

fn slice<'a>(input: &mut Decoder<'a>, maximum: usize) -> Result<&'a [u8], String> {
    let length = input.u32()? as usize;
    if length > maximum {
        return Err("binary transition field exceeds its byte bound".into());
    }
    input.take(length)
}

fn raw_length(value: &str) -> Result<usize, String> {
    let raw = value
        .strip_prefix("0x")
        .ok_or("missing private envelope prefix")?;
    if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES * 2 || raw.len() % 2 != 0 {
        return Err("private envelope exceeds the supported byte bound".into());
    }
    Ok(raw.len() / 2)
}

fn receipt_bytes(receipt: &Receipt) -> Result<usize, String> {
    // Exact existing receipt encoding, including its block hash.
    let mut size =
        147 + usize::from(receipt.to.is_some()) * 20 + usize::from(receipt.contract.is_some()) * 20;
    for log in &receipt.logs {
        if log.topics.len() > 4 {
            return Err("EVM log topic count exceeds four".into());
        }
        add(&mut size, 28 + log.topics.len() * 32)?;
        add(&mut size, log.data.len())?;
    }
    Ok(size)
}

fn add(size: &mut usize, additional: usize) -> Result<(), String> {
    *size = size
        .checked_add(additional)
        .ok_or("binary transition byte overflow")?;
    if *size > MAX_CHECKPOINT_WIRE_BYTES {
        return Err("binary transition exceeds its complete byte bound".into());
    }
    Ok(())
}
