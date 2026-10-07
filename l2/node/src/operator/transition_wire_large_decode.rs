use super::*;
use crate::protocol::{
    Head, MAX_TRANSACTION_BYTES, encoding::MAX_RECORD, receipt_codec::decode_receipt,
};
use alloy_primitives::B256;
use std::io::{Cursor, Read};

pub fn decode_large_checkpoint_transition(
    bytes: &[u8],
) -> Result<CheckpointTransitionBundle, String> {
    decode_large_checkpoint_transition_reader(&mut Cursor::new(bytes), bytes.len())
}

/// Reads a declared complete envelope without retaining a flat input copy.
/// File callers must pin and verify that declaration against their input file.
pub fn decode_large_checkpoint_transition_reader<R: Read>(
    source: &mut R,
    total_len: usize,
) -> Result<CheckpointTransitionBundle, String> {
    if !(LARGE_CHECKPOINT_HEADER_BYTES..=ABSOLUTE_MAX_V4_INPUT).contains(&total_len) {
        return Err("schema-four input length exceeds the absolute bound".into());
    }
    let mut input = Reader {
        source,
        remaining: total_len,
    };
    let header = input.fixed::<LARGE_CHECKPOINT_HEADER_BYTES>()?;
    let (capacity, limits) = large_checkpoint_transition_header(&header)?;
    if total_len > limits.input_bytes {
        return Err("schema-four input exceeds its exact selected limit".into());
    }
    let rpc_profile = input.profile()?;
    let execution_engine = input.profile()?;
    let domain = SettlementDomain {
        l1_network: input.fixed::<1>()?[0],
        l1_genesis_id: input.hash()?,
        settlement_contract_id: input.hash()?,
    };
    domain.validate()?;
    let checkpoint = frames::decode(&mut input, capacity, limits)?;
    let count = input.count(376, MAX_TRANSITION_BLOCKS as usize)?;
    if count == 0 {
        return Err("schema-four transition must contain blocks".into());
    }
    let transcript_start = input.remaining;
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let parent = input.head()?;
        let head = input.head()?;
        let context = TransitionContext {
            number: input.u64()?,
            timestamp: input.u64()?,
            gas_limit: input.u64()?,
        };
        let count = input.count(188, capacity.max_pending)?;
        if count == 0 {
            return Err("schema-four block must contain transactions".into());
        }
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let transaction_hash = input.hash()?;
            let raw = input.field(MAX_TRANSACTION_BYTES)?;
            if raw.is_empty() {
                return Err("schema-four transition contains an empty envelope".into());
            }
            let expected_receipt = decode_receipt(&input.field(MAX_RECORD)?, None)?;
            transactions.push(TransitionInput {
                transaction_hash,
                raw_envelope_hex: RawEnvelope::from_bytes(raw)?,
                expected_receipt,
            });
        }
        let block = TransitionBlock {
            parent,
            head,
            context,
            transactions,
        };
        large_checkpoint_transition_block_bytes(&block, capacity, limits)?;
        if transcript_start - input.remaining > limits.transcript_bytes {
            return Err("schema-four transcript exceeds its selected bound".into());
        }
        blocks.push(block);
    }
    let head = input.head()?;
    let expected_state_digest = input.hash()?;
    if input.remaining != 0 {
        return Err("schema-four transition contains trailing bytes".into());
    }
    let bundle = CheckpointTransitionBundle {
        schema: 4,
        rpc_profile,
        execution_engine,
        domain,
        checkpoint,
        blocks,
        head,
        expected_state_digest,
    };
    if large_checkpoint_transition_bytes(&bundle)? != total_len {
        return Err("schema-four input differs from canonical exact meter".into());
    }
    Ok(bundle)
}

pub(super) struct Reader<'a, R> {
    source: &'a mut R,
    pub(super) remaining: usize,
}

impl<R: Read> Reader<'_, R> {
    pub(super) fn read_into(&mut self, bytes: &mut [u8]) -> Result<(), String> {
        if bytes.len() > self.remaining {
            return Err("schema-four field exceeds remaining input".into());
        }
        self.source
            .read_exact(bytes)
            .map_err(|_| "truncated schema-four input")?;
        self.remaining -= bytes.len();
        Ok(())
    }
    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let mut bytes = [0; N];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }
    pub(super) fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn hash(&mut self) -> Result<B256, String> {
        Ok(B256::from(self.fixed::<32>()?))
    }
    fn head(&mut self) -> Result<Head, String> {
        Ok(Head {
            height: self.u64()?,
            timestamp: self.u64()?,
            commit_id: self.hash()?,
            genesis_id: self.hash()?,
        })
    }
    fn count(&mut self, minimum: usize, maximum: usize) -> Result<usize, String> {
        let count = self.u32()? as usize;
        if count > maximum || count > self.remaining / minimum {
            return Err("schema-four count exceeds remaining input or selected bound".into());
        }
        Ok(count)
    }
    fn field(&mut self, maximum: usize) -> Result<Vec<u8>, String> {
        let length = self.u32()? as usize;
        if length > maximum || length > self.remaining {
            return Err("schema-four ordinary field exceeds its bound".into());
        }
        let mut bytes = vec![0; length];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }
    fn profile(&mut self) -> Result<String, String> {
        let bytes = self.field(256)?;
        if bytes.is_empty() {
            return Err("empty schema-four transition profile".into());
        }
        String::from_utf8(bytes).map_err(|_| "invalid schema-four profile text".into())
    }
}
