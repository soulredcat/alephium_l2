use super::encoding::{Decoder, Encoder, MAX_RECORD};
use super::records::{decode_receipt, encode_head, encode_receipt, read_head};
use crate::protocol::{AccountChange, BlockCommit, BlockContext, Capacity, Head, Receipt, SCHEMA};
use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) struct StoredChange {
    pub change: AccountChange,
    pub epoch: u64,
}

pub(super) struct StoredBlock {
    pub head: Head,
    pub parent: Head,
    pub context: BlockContext,
    pub transactions: Vec<B256>,
    pub changes: Vec<StoredChange>,
    pub receipts: Vec<Receipt>,
    pub rejected: Vec<(B256, String)>,
}

#[allow(dead_code)]
pub(super) fn validate(commit: &BlockCommit) -> Result<(), String> {
    validate_with_capacity(commit, Capacity::default())
}

pub(super) fn validate_with_capacity(
    commit: &BlockCommit,
    capacity: Capacity,
) -> Result<(), String> {
    capacity.validate()?;
    let resolved = commit
        .transactions
        .len()
        .checked_add(commit.rejected.len())
        .ok_or("resolved transaction count overflow")?;
    if commit.context.number
        != commit
            .parent
            .height
            .checked_add(1)
            .ok_or("height overflow")?
        || commit.context.timestamp < commit.parent.timestamp
        || commit.context.gas_limit != capacity.block_gas
        || commit.transactions.len() != commit.receipts.len()
        || resolved > capacity.max_pending
        || commit.transactions.is_empty() && commit.rejected.is_empty()
    {
        return Err("invalid block transition context".into());
    }
    let mut hashes = BTreeSet::new();
    let mut cumulative = 0u64;
    let mut log_index = 0u64;
    for (index, receipt) in commit.receipts.iter().enumerate() {
        cumulative = cumulative
            .checked_add(receipt.gas_used)
            .ok_or("gas overflow")?;
        if receipt.hash != commit.transactions[index]
            || receipt.block_height != commit.context.number
            || receipt.transaction_index != index as u64
            || receipt.cumulative_gas != cumulative
            || receipt.first_log_index != log_index
            || cumulative > capacity.block_gas
            || !hashes.insert(receipt.hash)
            || !receipt.success && !receipt.logs.is_empty()
        {
            return Err("inconsistent block receipt".into());
        }
        log_index = log_index
            .checked_add(receipt.logs.len() as u64)
            .ok_or("log index overflow")?;
    }
    for (hash, reason) in &commit.rejected {
        if !hashes.insert(*hash) || reason.len() > 4096 || reason.is_empty() {
            return Err("invalid rejected transaction record".into());
        }
    }
    let mut addresses = BTreeSet::new();
    for change in &commit.changes {
        if !addresses.insert(change.address)
            || change.deleted && (!change.slots.is_empty() || change.code.is_some())
        {
            return Err("invalid account changeset".into());
        }
        let mut slots = BTreeSet::new();
        if change.slots.iter().any(|(slot, _)| !slots.insert(*slot)) {
            return Err("duplicate changed slot".into());
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn logical_bytes<'a>(
    commit: &BlockCommit,
    raws: impl Iterator<Item = &'a [u8]>,
) -> Result<usize, String> {
    logical_bytes_with_capacity(commit, raws, Capacity::default())
}

pub(super) fn logical_bytes_with_capacity<'a>(
    commit: &BlockCommit,
    raws: impl Iterator<Item = &'a [u8]>,
    capacity: Capacity,
) -> Result<usize, String> {
    capacity.validate()?;
    // Complete logical block: version, parent/head/context, count and each length-prefixed envelope.
    // Receipts/state delta are separately persisted execution outputs, not ingress block payload.
    let mut length = 4usize + 80 + 32 + 24 + 4;
    let mut count = 0;
    for raw in raws {
        length = length
            .checked_add(4 + raw.len())
            .ok_or("block byte count overflow")?;
        count += 1;
    }
    if count != commit.transactions.len() || length > capacity.block_bytes {
        return Err("complete block payload exceeds limit".into());
    }
    Ok(length)
}

#[allow(dead_code)]
pub(super) fn encode(
    commit: &BlockCommit,
    changes: &[StoredChange],
) -> Result<(Head, Vec<u8>), String> {
    encode_with_capacity(commit, changes, Capacity::default())
}

pub(super) fn encode_with_capacity(
    commit: &BlockCommit,
    changes: &[StoredChange],
    capacity: Capacity,
) -> Result<(Head, Vec<u8>), String> {
    validate_with_capacity(commit, capacity)?;
    let mut body = Encoder::default();
    body.u32(SCHEMA);
    body.0.extend(encode_head(&commit.parent));
    body.u64(commit.context.number);
    body.u64(commit.context.timestamp);
    body.u64(commit.context.gas_limit);
    body.u32(u32::try_from(commit.transactions.len()).map_err(|_| "transaction count overflow")?);
    for hash in &commit.transactions {
        body.hash(*hash);
    }
    body.u32(u32::try_from(changes.len()).map_err(|_| "changes count overflow")?);
    for change in changes {
        write_change(&mut body, change)?;
    }
    body.u32(u32::try_from(commit.receipts.len()).map_err(|_| "receipt count overflow")?);
    for receipt in &commit.receipts {
        body.bytes(&encode_receipt(receipt, false)?)?;
    }
    body.u32(u32::try_from(commit.rejected.len()).map_err(|_| "rejected count overflow")?);
    for (hash, reason) in &commit.rejected {
        body.hash(*hash);
        body.bytes(reason.as_bytes())?;
    }
    let mut digest = Sha256::new();
    digest.update(b"alephium-l2-development/local-commit/v1");
    digest.update(&body.0);
    let head = Head {
        height: commit.context.number,
        timestamp: commit.context.timestamp,
        commit_id: B256::from_slice(&digest.finalize()),
        genesis_id: commit.parent.genesis_id,
    };
    let mut record = Encoder::default();
    record.hash(head.commit_id);
    record.0.extend(body.finish()?);
    Ok((head, record.finish()?))
}

#[allow(dead_code)]
pub(super) fn decode(bytes: &[u8]) -> Result<StoredBlock, String> {
    decode_with_capacity(bytes, Capacity::default())
}

pub(super) fn decode_with_capacity(
    bytes: &[u8],
    capacity: Capacity,
) -> Result<StoredBlock, String> {
    capacity.validate()?;
    if bytes.len() < 36 || bytes.len() > MAX_RECORD {
        return Err("invalid block record size".into());
    }
    let mut input = Decoder::new(bytes)?;
    let commit_id = input.hash()?;
    let mut digest = Sha256::new();
    digest.update(b"alephium-l2-development/local-commit/v1");
    digest.update(&bytes[32..]);
    if B256::from_slice(&digest.finalize()) != commit_id {
        return Err("block commitment mismatch".into());
    }
    if input.u32()? != SCHEMA {
        return Err("unsupported block record schema".into());
    }
    let parent = read_head(&mut input)?;
    let context = BlockContext {
        number: input.u64()?,
        timestamp: input.u64()?,
        gas_limit: input.u64()?,
    };
    let count = input.count(32)?;
    if count > capacity.max_pending {
        return Err("block transaction count exceeds profile capacity".into());
    }
    let mut transactions = Vec::with_capacity(count);
    for _ in 0..count {
        transactions.push(input.hash()?);
    }
    let count = input.count(107)?;
    let mut changes = Vec::with_capacity(count);
    for _ in 0..count {
        changes.push(read_change(&mut input)?);
    }
    if changes
        .windows(2)
        .any(|pair| pair[0].change.address >= pair[1].change.address)
    {
        return Err("noncanonical account changes".into());
    }
    let count = input.count(4)?;
    if count > capacity.max_pending {
        return Err("block receipt count exceeds profile capacity".into());
    }
    let mut receipts = Vec::with_capacity(count);
    for _ in 0..count {
        receipts.push(decode_receipt(&input.bytes()?, Some(commit_id))?);
    }
    let count = input.count(36)?;
    if count > capacity.max_pending {
        return Err("block rejection count exceeds profile capacity".into());
    }
    let mut rejected = Vec::with_capacity(count);
    for _ in 0..count {
        rejected.push((
            input.hash()?,
            String::from_utf8(input.bytes()?).map_err(|_| "invalid rejection text")?,
        ));
    }
    input.finish()?;
    let commit = BlockCommit {
        parent: parent.clone(),
        context,
        transactions: transactions.clone(),
        changes: changes.iter().map(|change| change.change.clone()).collect(),
        receipts: receipts.clone(),
        rejected: rejected.clone(),
    };
    validate_with_capacity(&commit, capacity)?;
    let head = Head {
        height: context.number,
        timestamp: context.timestamp,
        commit_id,
        genesis_id: parent.genesis_id,
    };
    Ok(StoredBlock {
        head,
        parent,
        context,
        transactions,
        changes,
        receipts,
        rejected,
    })
}

fn write_change(out: &mut Encoder, stored: &StoredChange) -> Result<(), String> {
    let change = &stored.change;
    out.address(change.address);
    out.byte(u8::from(change.deleted));
    out.byte(u8::from(change.storage_reset));
    out.u64(stored.epoch);
    out.amount(change.balance);
    out.u64(change.nonce);
    out.hash(change.code_hash);
    out.byte(u8::from(change.code.is_some()));
    if let Some(code) = &change.code {
        out.bytes(code)?;
    }
    out.u32(u32::try_from(change.slots.len()).map_err(|_| "slot count overflow")?);
    for (slot, value) in &change.slots {
        out.amount(*slot);
        out.amount(*value);
    }
    Ok(())
}

fn read_change(input: &mut Decoder<'_>) -> Result<StoredChange, String> {
    let address = input.address()?;
    let deleted = input.boolean()?;
    let storage_reset = input.boolean()?;
    let epoch = input.u64()?;
    let balance = input.amount()?;
    let nonce = input.u64()?;
    let code_hash = input.hash()?;
    let code = if input.boolean()? {
        Some(input.bytes()?)
    } else {
        None
    };
    let count = input.count(64)?;
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        slots.push((input.amount()?, input.amount()?));
    }
    if slots.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err("noncanonical storage delta".into());
    }
    Ok(StoredChange {
        change: AccountChange {
            address,
            deleted,
            storage_reset,
            balance,
            nonce,
            code_hash,
            code,
            slots,
        },
        epoch,
    })
}
