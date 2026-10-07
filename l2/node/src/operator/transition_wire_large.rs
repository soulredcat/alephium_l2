//! Schema-four full-state witness transport; native support is not proof acceptance.
use super::{transition_types::*, transition_wire::receipt_bytes};
use crate::protocol::{
    Capacity,
    encoding::{Decoder, Encoder},
    head_codec::encode_head,
    proof_transport::{ABSOLUTE_MAX_V4_INPUT, ProofLimits},
    receipt_codec::encode_receipt,
};

#[path = "transition_wire_large_decode.rs"]
mod decode;
#[path = "transition_wire_large_frames.rs"]
mod frames;
pub use decode::{decode_large_checkpoint_transition, decode_large_checkpoint_transition_reader};

pub const LARGE_CHECKPOINT_WIRE_MAGIC: &[u8] = b"ALEPHIUM-L2/TRANSITION/WIRE/V4\0";
pub const LARGE_CHECKPOINT_HEADER_BYTES: usize = LARGE_CHECKPOINT_WIRE_MAGIC.len() + 4 + 24 + 32;

pub fn is_large_checkpoint_wire(bytes: &[u8]) -> bool {
    bytes.starts_with(LARGE_CHECKPOINT_WIRE_MAGIC)
}

/// Bounded, allocation-free probe for host/guest input selection.
pub fn large_checkpoint_transition_header(bytes: &[u8]) -> Result<(Capacity, ProofLimits), String> {
    let prefix = bytes
        .get(..LARGE_CHECKPOINT_HEADER_BYTES)
        .ok_or("truncated schema-four transport header")?;
    let mut input = Decoder::new(prefix)?;
    if input.take(LARGE_CHECKPOINT_WIRE_MAGIC.len())? != LARGE_CHECKPOINT_WIRE_MAGIC
        || input.u32()? != 4
    {
        return Err("invalid schema-four transport domain or version".into());
    }
    let capacity = Capacity {
        block_gas: input.u64()?,
        block_bytes: usize::try_from(input.u64()?).map_err(|_| "capacity byte overflow")?,
        max_pending: usize::try_from(input.u64()?).map_err(|_| "capacity count overflow")?,
    };
    let limits = ProofLimits {
        checkpoint_bytes: usize::try_from(input.u64()?).map_err(|_| "checkpoint limit overflow")?,
        transcript_bytes: usize::try_from(input.u64()?).map_err(|_| "transcript limit overflow")?,
        input_bytes: usize::try_from(input.u64()?).map_err(|_| "input limit overflow")?,
        frame_bytes: usize::try_from(input.u64()?).map_err(|_| "frame limit overflow")?,
    };
    input.finish()?;
    limits.validate_for_capacity(capacity)?;
    Ok((capacity, limits))
}

pub fn large_checkpoint_transition_base_bytes(
    rpc: &str,
    engine: &str,
    checkpoint_len: usize,
    limits: ProofLimits,
) -> Result<usize, String> {
    limits.validate()?;
    if checkpoint_len == 0 || checkpoint_len > limits.checkpoint_bytes {
        return Err("checkpoint exceeds schema-four transport limit".into());
    }
    for field in [rpc, engine] {
        if field.is_empty() || field.len() > 256 {
            return Err("transition profile exceeds its field limit".into());
        }
    }
    let count = frames::frame_count(checkpoint_len, limits)?;
    // Fixed header, profile frames, domain, checkpoint total/count + frame
    // metadata, block count, final head and logical state digest.
    let mut size = LARGE_CHECKPOINT_HEADER_BYTES + 8 + 65 + 12 + 4 + 80 + 32;
    for bytes in [
        rpc.len(),
        engine.len(),
        checkpoint_len,
        count.checked_mul(8).ok_or("frame metadata overflow")?,
    ] {
        add(&mut size, bytes, limits.input_bytes)?;
    }
    Ok(size)
}

pub fn large_checkpoint_transition_block_bytes(
    block: &TransitionBlock,
    capacity: Capacity,
    limits: ProofLimits,
) -> Result<usize, String> {
    limits.validate_for_capacity(capacity)?;
    if block.context.gas_limit != capacity.block_gas
        || block.transactions.is_empty()
        || block.transactions.len() > capacity.max_pending
    {
        return Err("schema-four block context or transaction count exceeds profile".into());
    }
    let mut size = 188usize;
    let mut logical = 148usize;
    for transaction in &block.transactions {
        let raw = transaction.raw_envelope_hex.as_bytes().len();
        add(&mut logical, 4 + raw, capacity.block_bytes)?;
        add(&mut size, 32 + 4 + raw + 4, limits.transcript_bytes)?;
        add(
            &mut size,
            receipt_bytes(&transaction.expected_receipt)?,
            limits.transcript_bytes,
        )?;
    }
    Ok(size)
}

pub fn large_checkpoint_transition_bytes(
    bundle: &CheckpointTransitionBundle,
) -> Result<usize, String> {
    bundle.domain.validate()?;
    let capacity = bundle.checkpoint.capacity;
    let limits = ProofLimits::for_capacity(capacity)?;
    if bundle.schema != 4
        || bundle.blocks.is_empty()
        || bundle.blocks.len() as u64 > MAX_TRANSITION_BLOCKS
    {
        return Err("unsupported schema-four transition version or block count".into());
    }
    let mut size = large_checkpoint_transition_base_bytes(
        &bundle.rpc_profile,
        &bundle.execution_engine,
        bundle.checkpoint.encoded_len()?,
        limits,
    )?;
    let mut transcript = 0usize;
    for block in &bundle.blocks {
        let bytes = large_checkpoint_transition_block_bytes(block, capacity, limits)?;
        add(&mut transcript, bytes, limits.transcript_bytes)?;
        add(&mut size, bytes, limits.input_bytes)?;
    }
    Ok(size)
}

pub fn encode_large_checkpoint_transition(
    bundle: &CheckpointTransitionBundle,
) -> Result<Vec<u8>, String> {
    let size = large_checkpoint_transition_bytes(bundle)?;
    let capacity = bundle.checkpoint.capacity;
    let limits = ProofLimits::for_capacity(capacity)?;
    let checkpoint_len = bundle.checkpoint.encoded_len()?;
    let mut out = Encoder(Vec::with_capacity(size));
    out.0.extend_from_slice(LARGE_CHECKPOINT_WIRE_MAGIC);
    out.u32(4);
    out.u64(capacity.block_gas);
    out.u64(capacity.block_bytes as u64);
    out.u64(capacity.max_pending as u64);
    out.0.extend(limits.binding_bytes()?);
    out.bytes(bundle.rpc_profile.as_bytes())?;
    out.bytes(bundle.execution_engine.as_bytes())?;
    out.byte(bundle.domain.l1_network);
    out.hash(bundle.domain.l1_genesis_id);
    out.hash(bundle.domain.settlement_contract_id);
    frames::encode(&mut out, &bundle.checkpoint, checkpoint_len, limits)?;
    out.u32(u32::try_from(bundle.blocks.len()).map_err(|_| "block count overflow")?);
    for block in &bundle.blocks {
        out.0.extend(encode_head(&block.parent));
        out.0.extend(encode_head(&block.head));
        out.u64(block.context.number);
        out.u64(block.context.timestamp);
        out.u64(block.context.gas_limit);
        out.u32(u32::try_from(block.transactions.len()).map_err(|_| "transaction count overflow")?);
        for transaction in &block.transactions {
            out.hash(transaction.transaction_hash);
            out.bytes(transaction.raw_envelope_hex.as_bytes())?;
            out.bytes(&encode_receipt(&transaction.expected_receipt, true)?)?;
        }
    }
    out.0.extend(encode_head(&bundle.head));
    out.hash(bundle.expected_state_digest);
    if out.0.len() != size {
        return Err("schema-four encoding differs from exact meter".into());
    }
    out.finish_with_limit(limits.input_bytes)
}

fn add(size: &mut usize, bytes: usize, limit: usize) -> Result<(), String> {
    *size = size
        .checked_add(bytes)
        .ok_or("schema-four byte count overflow")?;
    if *size > limit {
        return Err("schema-four data exceeds its explicit transport bound".into());
    }
    Ok(())
}
