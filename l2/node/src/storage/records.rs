use super::encoding::{Decoder, Encoder};
use crate::protocol::{Account, EventLog, Genesis, Head, Receipt, TransactionStatus};
use alloy_primitives::{B256, keccak256};
use sha2::{Digest, Sha256};

pub(super) fn genesis_bytes(genesis: &Genesis) -> Result<Vec<u8>, String> {
    use crate::protocol::{BLOCK_BYTES, BLOCK_GAS, BLOCK_INTERVAL_MS, SCHEMA};
    genesis.validate()?;
    let mut accounts = genesis.accounts.clone();
    accounts.sort_by_key(|account| account.address);
    let mut out = Encoder::default();
    out.bytes(b"alephium-l2-development/genesis")?;
    out.u32(SCHEMA);
    out.u64(genesis.chain_id);
    out.bytes(b"Cancun")?;
    out.u64(BLOCK_GAS);
    out.u64(BLOCK_BYTES as u64);
    out.u64(BLOCK_INTERVAL_MS);
    out.u32(accounts.len() as u32);
    for account in accounts {
        out.address(account.address);
        out.amount(account.balance);
    }
    out.finish()
}

pub(super) fn identity(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}

pub(super) fn genesis_head(bytes: &[u8]) -> Head {
    let genesis_id = identity(bytes);
    let mut digest = Sha256::new();
    digest.update(b"alephium-l2-development/genesis-commit/v1");
    digest.update(genesis_id);
    Head {
        genesis_id,
        commit_id: B256::from_slice(&digest.finalize()),
        ..Head::default()
    }
}

pub(super) fn encode_head(head: &Head) -> Vec<u8> {
    let mut out = Encoder::default();
    out.u64(head.height);
    out.u64(head.timestamp);
    out.hash(head.commit_id);
    out.hash(head.genesis_id);
    out.0
}

pub(super) fn decode_head(bytes: &[u8]) -> Result<Head, String> {
    let mut input = Decoder::new(bytes)?;
    let head = read_head(&mut input)?;
    input.finish()?;
    Ok(head)
}

pub(super) fn read_head(input: &mut Decoder<'_>) -> Result<Head, String> {
    Ok(Head {
        height: input.u64()?,
        timestamp: input.u64()?,
        commit_id: input.hash()?,
        genesis_id: input.hash()?,
    })
}

pub(super) fn encode_account(account: &Account, deleted: bool) -> Vec<u8> {
    let mut out = Encoder::default();
    out.byte(u8::from(deleted));
    out.amount(account.balance);
    out.u64(account.nonce);
    out.hash(account.code_hash);
    out.u64(account.storage_epoch);
    out.0
}

pub(super) fn decode_account(bytes: &[u8]) -> Result<(Account, bool), String> {
    let mut input = Decoder::new(bytes)?;
    let deleted = input.boolean()?;
    let account = Account {
        balance: input.amount()?,
        nonce: input.u64()?,
        code_hash: input.hash()?,
        storage_epoch: input.u64()?,
    };
    input.finish()?;
    if deleted
        && (!account.balance.is_zero() || account.nonce != 0 || account.code_hash != B256::ZERO)
    {
        return Err("invalid deleted account record".into());
    }
    Ok((account, deleted))
}

pub(super) fn encode_receipt(
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

pub(super) fn decode_receipt(bytes: &[u8], block_hash: Option<B256>) -> Result<Receipt, String> {
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

pub(super) fn encode_status(status: &TransactionStatus) -> Result<Vec<u8>, String> {
    let mut out = Encoder::default();
    out.hash(status.hash);
    out.bytes(status.status.as_bytes())?;
    out.byte(u8::from(status.block_height.is_some()));
    if let Some(height) = status.block_height {
        out.u64(height);
    }
    out.byte(u8::from(status.error.is_some()));
    if let Some(error) = &status.error {
        out.bytes(error.as_bytes())?;
    }
    out.finish()
}

pub(super) fn decode_status(bytes: &[u8]) -> Result<TransactionStatus, String> {
    let mut input = Decoder::new(bytes)?;
    let hash = input.hash()?;
    let status = String::from_utf8(input.bytes()?).map_err(|_| "invalid status text")?;
    let block_height = if input.boolean()? {
        Some(input.u64()?)
    } else {
        None
    };
    let error = if input.boolean()? {
        Some(String::from_utf8(input.bytes()?).map_err(|_| "invalid error text")?)
    } else {
        None
    };
    input.finish()?;
    match status.as_str() {
        "durably_accepted" if block_height.is_none() && error.is_none() => {}
        "committed" | "reverted" if block_height.is_some() && error.is_none() => {}
        "rejected" if error.is_some() => {}
        _ => return Err("invalid transaction status lifecycle".into()),
    }
    Ok(TransactionStatus {
        hash,
        status,
        block_height,
        error,
    })
}

pub(super) fn verify_code(hash: B256, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 24_576 || keccak256(bytes) != hash {
        Err("stored code identity or fork size is invalid".into())
    } else {
        Ok(())
    }
}
