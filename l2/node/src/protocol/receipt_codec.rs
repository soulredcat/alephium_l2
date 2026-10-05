//! Existing durable receipt bytes, shared unchanged by storage and proof transport.
use super::{
    EventLog, Receipt,
    encoding::{Decoder, Encoder},
};
use alloy_primitives::B256;

pub(crate) fn encode_receipt(
    receipt: &Receipt,
    include_block_hash: bool,
) -> Result<Vec<u8>, String> {
    let mut out = Encoder::default();
    out.hash(receipt.hash);
    out.address(receipt.from);
    out.optional_address(receipt.to);
    out.optional_address(receipt.contract);
    out.byte(u8::from(receipt.success));
    out.u64(receipt.gas_used);
    out.u128(receipt.gas_price);
    out.u32(u32::try_from(receipt.logs.len()).map_err(|_| "log count overflow")?);
    for log in &receipt.logs {
        if log.topics.len() > 4 {
            return Err("EVM log topic count exceeds four".into());
        }
        out.address(log.address);
        out.u32(log.topics.len() as u32);
        for topic in &log.topics {
            out.hash(*topic);
        }
        out.bytes(&log.data)?;
    }
    out.u64(receipt.block_height);
    if include_block_hash {
        out.hash(receipt.block_hash);
    }
    out.u64(receipt.transaction_index);
    out.u64(receipt.cumulative_gas);
    out.u64(receipt.first_log_index);
    out.finish()
}

pub(crate) fn decode_receipt(bytes: &[u8], block_hash: Option<B256>) -> Result<Receipt, String> {
    let mut input = Decoder::new(bytes)?;
    let hash = input.hash()?;
    let from = input.address()?;
    let to = input.optional_address()?;
    let contract = input.optional_address()?;
    let success = input.boolean()?;
    let gas_used = input.u64()?;
    let gas_price = input.u128()?;
    let count = input.count(28)?;
    let mut logs = Vec::with_capacity(count);
    for _ in 0..count {
        let address = input.address()?;
        let topic_count = input.count(32)?;
        if topic_count > 4 {
            return Err("invalid stored topic count".into());
        }
        let mut topics = Vec::with_capacity(topic_count);
        for _ in 0..topic_count {
            topics.push(input.hash()?);
        }
        logs.push(EventLog {
            address,
            topics,
            data: input.bytes()?,
        });
    }
    let block_height = input.u64()?;
    let block_hash = if let Some(hash) = block_hash {
        hash
    } else {
        input.hash()?
    };
    let transaction_index = input.u64()?;
    let cumulative_gas = input.u64()?;
    let first_log_index = input.u64()?;
    input.finish()?;
    Ok(Receipt {
        hash,
        from,
        to,
        contract,
        success,
        gas_used,
        gas_price,
        logs,
        block_height,
        block_hash,
        transaction_index,
        cumulative_gas,
        first_log_index,
    })
}
