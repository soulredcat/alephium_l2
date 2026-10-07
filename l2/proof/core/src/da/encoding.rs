//! Canonical schema-four reconstruction bytes; excludes all producer output oracles.
use super::{DaEncodingEvidence, NAMESPACE};
use crate::{
    CheckpointTransitionBundle, EXECUTION_ENGINE, MAX_TRANSITION_BLOCKS, RPC_PROFILE,
    checkpoint_profile_v4_with_capacity,
    protocol::{
        Capacity, MAX_TRANSACTION_BYTES,
        hash::{Digest, Sha256},
        proof_transport::ProofLimits,
    },
};

const BLOCK_LOGICAL_PREFIX: usize = 148;

fn add(value: &mut usize, amount: usize, limit: usize) -> Result<(), String> {
    *value = value.checked_add(amount).ok_or("DA byte count overflow")?;
    if *value > limit {
        return Err("DA bytes exceed the selected profile bound".into());
    }
    Ok(())
}

pub(super) fn context_valid(
    number: u64,
    timestamp: u64,
    gas: u64,
    previous_number: u64,
    previous_timestamp: u64,
    capacity: Capacity,
) -> Result<(), String> {
    if number != previous_number.checked_add(1).ok_or("DA height overflow")?
        || timestamp < previous_timestamp
        || gas != capacity.block_gas
    {
        return Err("DA contexts are unordered or use another gas capacity".into());
    }
    Ok(())
}

pub(super) fn raw_length_valid(
    bytes: usize,
    logical: &mut usize,
    capacity: Capacity,
) -> Result<(), String> {
    if bytes == 0 || bytes > MAX_TRANSACTION_BYTES {
        return Err("DA envelope length exceeds the supported transaction bound".into());
    }
    add(logical, 4 + bytes, capacity.block_bytes)
}

pub(super) const fn logical_prefix() -> usize {
    BLOCK_LOGICAL_PREFIX
}

/// Validate serialized inputs only. Supplied heads, receipts, transaction-hash
/// oracles and final state-digest assertions are deliberately not DA inputs.
fn encoding_size(
    bundle: &CheckpointTransitionBundle,
    limits: ProofLimits,
    checkpoint_bytes: usize,
) -> Result<usize, String> {
    if bundle.schema != 4
        || bundle.rpc_profile != RPC_PROFILE
        || bundle.execution_engine != EXECUTION_ENGINE
        || bundle.blocks.is_empty()
        || bundle.blocks.len() as u64 > MAX_TRANSITION_BLOCKS
    {
        return Err("unsupported DA profile or block count".into());
    }
    bundle.domain.validate()?;
    limits.validate_for_capacity(bundle.checkpoint.capacity)?;
    if checkpoint_bytes == 0 || checkpoint_bytes > limits.checkpoint_bytes {
        return Err("DA checkpoint exceeds the selected profile bound".into());
    }
    let mut transcript_bytes = 0;
    let mut previous_number = bundle.checkpoint.head.height;
    let mut previous_timestamp = bundle.checkpoint.head.timestamp;
    for block in &bundle.blocks {
        context_valid(
            block.context.number,
            block.context.timestamp,
            block.context.gas_limit,
            previous_number,
            previous_timestamp,
            bundle.checkpoint.capacity,
        )?;
        if block.transactions.is_empty()
            || block.transactions.len() > bundle.checkpoint.capacity.max_pending
        {
            return Err("DA transaction count exceeds the selected block bound".into());
        }
        add(&mut transcript_bytes, 28, limits.transcript_bytes)?;
        let mut logical = BLOCK_LOGICAL_PREFIX;
        for input in &block.transactions {
            let length = input.raw_envelope_hex.as_bytes().len();
            raw_length_valid(length, &mut logical, bundle.checkpoint.capacity)?;
            add(&mut transcript_bytes, 4 + length, limits.transcript_bytes)?;
        }
        previous_number = block.context.number;
        previous_timestamp = block.context.timestamp;
    }
    let mut total = 4 + NAMESPACE.len() + 65 + 32 + 32 + 4 + 8;
    add(&mut total, checkpoint_bytes, limits.input_bytes)?;
    add(&mut total, transcript_bytes, limits.input_bytes)?;
    Ok(total)
}

struct Emitter<'a, F> {
    sink: &'a mut F,
    digest: Sha256,
    bytes: usize,
    limit: usize,
}

impl<F: FnMut(&[u8]) -> Result<(), String>> Emitter<'_, F> {
    fn raw(&mut self, value: &[u8]) -> Result<(), String> {
        let next = self
            .bytes
            .checked_add(value.len())
            .ok_or("DA byte count overflow")?;
        if next > self.limit {
            return Err("DA output exceeds the selected byte bound".into());
        }
        (self.sink)(value).map_err(|_| "DA output sink rejected the bounded bytes".to_owned())?;
        self.digest.update(value);
        self.bytes = next;
        Ok(())
    }

    fn field(&mut self, value: &[u8]) -> Result<(), String> {
        let length = u32::try_from(value.len()).map_err(|_| "DA field exceeds u32")?;
        if self
            .bytes
            .checked_add(4)
            .and_then(|n| n.checked_add(value.len()))
            .is_none_or(|next| next > self.limit)
        {
            return Err("DA field exceeds the selected byte bound".into());
        }
        self.raw(&length.to_be_bytes())?;
        self.raw(value)
    }
}

/// Stream the exact existing reconstruction_hash transcript. The checkpoint is
/// never copied into a second whole wire buffer, and envelopes remain private.
pub fn write_checkpoint_da(
    bundle: &CheckpointTransitionBundle,
    sink: &mut impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<DaEncodingEvidence, String> {
    let capacity = bundle.checkpoint.capacity;
    let limits = ProofLimits::for_capacity(capacity)?;
    let checkpoint_bytes = bundle.checkpoint.encoded_len()?;
    let expected_bytes = encoding_size(bundle, limits, checkpoint_bytes)?;
    let profile = checkpoint_profile_v4_with_capacity(capacity)?;
    let mut out = Emitter {
        sink,
        digest: Sha256::new(),
        bytes: 0,
        limit: limits.input_bytes,
    };
    out.field(NAMESPACE)?;
    out.raw(&[bundle.domain.l1_network])?;
    out.raw(bundle.domain.l1_genesis_id.as_slice())?;
    out.raw(bundle.domain.settlement_contract_id.as_slice())?;
    out.raw(profile.as_slice())?;
    out.raw(&limits.binding_bytes()?)?;
    out.raw(
        &u32::try_from(checkpoint_bytes)
            .map_err(|_| "DA checkpoint exceeds u32")?
            .to_be_bytes(),
    )?;
    bundle
        .checkpoint
        .write_encoded(&mut |bytes| out.raw(bytes))?;
    out.raw(&(bundle.blocks.len() as u64).to_be_bytes())?;
    for block in &bundle.blocks {
        out.raw(&block.context.number.to_be_bytes())?;
        out.raw(&block.context.timestamp.to_be_bytes())?;
        out.raw(&block.context.gas_limit.to_be_bytes())?;
        out.raw(
            &u32::try_from(block.transactions.len())
                .map_err(|_| "DA count exceeds u32")?
                .to_be_bytes(),
        )?;
        for input in &block.transactions {
            out.field(input.raw_envelope_hex.as_bytes())?;
        }
    }
    if out.bytes != expected_bytes {
        return Err("DA emitted bytes differ from the validated canonical size".into());
    }
    Ok(DaEncodingEvidence {
        bytes: out.bytes,
        commitment: alloy_primitives::B256::from_slice(&out.digest.finalize()),
    })
}
