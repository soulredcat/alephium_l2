use super::*;

pub(super) fn encode(checkpoint: &ExecutionCheckpoint, size: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(size);
    write(checkpoint, &mut |bytes| {
        out.extend_from_slice(bytes);
        Ok(())
    })?;
    if out.len() != size {
        return Err("checkpoint encoding differs from exact meter".into());
    }
    Ok(out)
}

pub(super) fn write(
    checkpoint: &ExecutionCheckpoint,
    sink: &mut impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), String> {
    sink(DOMAIN)?;
    sink(&checkpoint.schema.to_be_bytes())?;
    sink(&checkpoint.chain_id.to_be_bytes())?;
    if !checkpoint.capacity.is_default() {
        sink(&checkpoint.capacity.block_gas.to_be_bytes())?;
        sink(&(checkpoint.capacity.block_bytes as u64).to_be_bytes())?;
        sink(&(checkpoint.capacity.max_pending as u64).to_be_bytes())?;
    }
    sink(checkpoint.genesis_id.as_slice())?;
    sink(&checkpoint.head.height.to_be_bytes())?;
    sink(&checkpoint.head.timestamp.to_be_bytes())?;
    sink(checkpoint.head.commit_id.as_slice())?;
    sink(checkpoint.head.genesis_id.as_slice())?;
    sink(&(checkpoint.accounts.len() as u32).to_be_bytes())?;
    for account in &checkpoint.accounts {
        sink(account.address.as_slice())?;
        sink(&[u8::from(account.deleted)])?;
        sink(&account.balance.to_be_bytes::<32>())?;
        sink(&account.nonce.to_be_bytes())?;
        sink(account.code_hash.as_slice())?;
        sink(&account.storage_epoch.to_be_bytes())?;
        sink(&(account.slots.len() as u32).to_be_bytes())?;
        for slot in &account.slots {
            sink(&slot.key.to_be_bytes::<32>())?;
            sink(&slot.value.to_be_bytes::<32>())?;
        }
    }
    sink(&(checkpoint.codes.len() as u32).to_be_bytes())?;
    for code in &checkpoint.codes {
        sink(code.hash.as_slice())?;
        sink(&(code.bytes.len() as u32).to_be_bytes())?;
        sink(&code.bytes)?;
    }
    sink(&(checkpoint.block_hashes.len() as u32).to_be_bytes())?;
    for block in &checkpoint.block_hashes {
        sink(&block.height.to_be_bytes())?;
        sink(block.hash.as_slice())?;
    }
    Ok(())
}
