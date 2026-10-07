use super::encoding::{Decoder, Encoder};
use crate::protocol::hash::{Digest, Sha256};
pub(super) use crate::protocol::head_codec::{decode_head, encode_head, read_head};
pub(super) use crate::protocol::receipt_codec::{decode_receipt, encode_receipt};
use crate::protocol::{Account, Capacity, Genesis, Head, TransactionStatus};
use alloy_primitives::{B256, keccak256};

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
    // Keep the original default identity exact. An extended profile binds
    // every limit under an explicit domain/version after the legacy prefix.
    if genesis.capacity != Capacity::default() {
        out.bytes(b"alephium-l2-development/capacity/v1")?;
        out.u32(1);
        out.u64(genesis.capacity.block_gas);
        out.u64(u64::try_from(genesis.capacity.block_bytes).map_err(|_| "capacity byte overflow")?);
        out.u64(
            u64::try_from(genesis.capacity.max_pending).map_err(|_| "capacity count overflow")?,
        );
    }
    if genesis.capacity.uses_extended_runtime_codec() {
        out.bytes(b"alephium-l2-development/runtime-codec/v1")?;
        out.u32(1);
        out.u64(genesis.capacity.runtime_record_bytes()? as u64);
        out.u64(genesis.capacity.runtime_checkpoint_bytes()? as u64);
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
