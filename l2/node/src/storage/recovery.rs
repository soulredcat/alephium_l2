use super::{
    ReadView, block,
    encoding::{Decoder, key, slot_key},
    records,
};
use crate::protocol::{Account, BLOCK_BYTES, Genesis, TransactionStatus};
use alloy_primitives::{B256, keccak256};
use fjall::Readable;
use std::collections::{BTreeMap, BTreeSet};

/// Rebuild expected incremental records from retained, hash-checked local commits.
/// This is startup consistency verification, not proof of EVM/L1 validity.
pub(super) fn validate(view: &ReadView, genesis: &Genesis, identity: &[u8]) -> Result<(), String> {
    let mut expected = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for funded in &genesis.accounts {
        if funded.balance.is_zero() {
            continue;
        }
        let account = Account {
            balance: funded.balance,
            code_hash: keccak256([]),
            ..Account::default()
        };
        expected.insert(
            key(0x10, funded.address.as_slice()),
            records::encode_account(&account, false),
        );
    }
    let mut head = records::genesis_head(identity);
    let mut resolved = BTreeSet::new();
    let mut block_hashes = BTreeMap::new();
    for entry in view.snapshot.prefix(&view.items, [0x30]) {
        let (block_key, bytes) = entry.into_inner().map_err(super::engine_error)?;
        if block_key.len() != 9 {
            return Err("invalid retained block key".into());
        }
        let retained = block::decode(&bytes)?;
        if retained.parent != head
            || block_key[1..] != retained.head.height.to_be_bytes()
            || retained.context.number != retained.head.height
        {
            return Err("retained commit chain is inconsistent".into());
        }
        let mut logical_size = 4usize + 80 + 32 + 24 + 4;
        for hash in &retained.transactions {
            let raw = read_raw(view, *hash)?;
            logical_size = logical_size
                .checked_add(4 + raw.len())
                .ok_or("logical block size overflow")?;
            expected.insert(key(0x20, hash.as_slice()), raw);
        }
        if logical_size > BLOCK_BYTES {
            return Err("retained block exceeds complete payload limit".into());
        }
        // Insert code before account resolution: multiple accounts may share code
        // introduced in this same block without relying on change iteration order.
        for stored in &retained.changes {
            if let Some(code) = &stored.change.code {
                records::verify_code(stored.change.code_hash, code)?;
                if !code.is_empty() {
                    let code_key = key(0x12, stored.change.code_hash.as_slice());
                    if expected
                        .get(&code_key)
                        .is_some_and(|existing| existing != code)
                    {
                        return Err("retained code identity conflict".into());
                    }
                    expected.insert(code_key, code.clone());
                }
            }
        }
        for stored in &retained.changes {
            let change = &stored.change;
            let account_key = key(0x10, change.address.as_slice());
            let previous_epoch = expected
                .get(&account_key)
                .map(|bytes| {
                    records::decode_account(bytes).map(|(account, _)| account.storage_epoch)
                })
                .transpose()?
                .unwrap_or(0);
            let next_epoch = if change.storage_reset || change.deleted {
                previous_epoch
                    .checked_add(1)
                    .ok_or("retained epoch overflow")?
            } else {
                previous_epoch
            };
            if stored.epoch != next_epoch {
                return Err("retained storage epoch transition is inconsistent".into());
            }
            let account = Account {
                balance: change.balance,
                nonce: change.nonce,
                code_hash: change.code_hash,
                storage_epoch: next_epoch,
            };
            if !change.deleted
                && change.code_hash != B256::ZERO
                && change.code_hash != keccak256([])
                && !expected.contains_key(&key(0x12, change.code_hash.as_slice()))
            {
                return Err("retained account references absent code".into());
            }
            expected.insert(
                account_key,
                records::encode_account(&account, change.deleted),
            );
            for (slot, value) in &change.slots {
                let slot_key = slot_key(change.address, next_epoch, *slot);
                if value.is_zero() {
                    expected.remove(&slot_key);
                } else {
                    expected.insert(slot_key, value.to_be_bytes::<32>().to_vec());
                }
            }
        }
        for receipt in &retained.receipts {
            if !resolved.insert(receipt.hash) {
                return Err("transaction appears in multiple retained resolutions".into());
            }
            let raw = expected
                .get(&key(0x20, receipt.hash.as_slice()))
                .ok_or("missing receipt envelope")?;
            let info = crate::execution::inspect_for_chain(raw, view.chain_id())
                .map_err(|_| "invalid retained signed transaction")?;
            if info.hash != receipt.hash
                || info.sender != receipt.from
                || receipt.gas_used > info.gas_limit
            {
                return Err("retained receipt sender or gas differs from envelope".into());
            }
            let status = TransactionStatus {
                hash: receipt.hash,
                status: if receipt.success {
                    "committed"
                } else {
                    "reverted"
                }
                .into(),
                block_height: Some(retained.head.height),
                error: None,
            };
            expected.insert(
                key(0x21, receipt.hash.as_slice()),
                records::encode_status(&status)?,
            );
            expected.insert(
                key(0x22, receipt.hash.as_slice()),
                records::encode_receipt(receipt, true)?,
            );
        }
        for (hash, reason) in &retained.rejected {
            if !resolved.insert(*hash) {
                return Err("duplicate retained rejection".into());
            }
            let raw = read_raw(view, *hash)?;
            crate::execution::inspect_for_chain(&raw, view.chain_id())
                .map_err(|_| "invalid rejected signed transaction")?;
            expected.insert(key(0x20, hash.as_slice()), raw);
            let status = TransactionStatus {
                hash: *hash,
                status: "rejected".into(),
                block_height: Some(retained.head.height),
                error: Some(reason.clone()),
            };
            expected.insert(key(0x21, hash.as_slice()), records::encode_status(&status)?);
        }
        block_hashes.insert(retained.head.commit_id, retained.head.height);
        head = retained.head;
    }
    if head != view.head {
        return Err("committed head does not match retained chain".into());
    }
    validate_pending(view, &mut expected, &resolved)?;
    for prefix in [0x10u8, 0x11, 0x12, 0x20, 0x21, 0x22] {
        for entry in view.snapshot.prefix(&view.items, [prefix]) {
            let (key, bytes) = entry.into_inner().map_err(super::engine_error)?;
            let expected_bytes = expected
                .remove(key.as_ref())
                .ok_or("unexplained authoritative record")?;
            if expected_bytes != bytes.as_ref() {
                return Err("authoritative record differs from retained commits".into());
            }
        }
    }
    if !expected.is_empty() {
        return Err("authoritative record missing from recovered database".into());
    }
    // Derived C3 indexes are optional for older commits, but every present
    // index must identify a hash-checked member of the retained canonical chain.
    for entry in view.snapshot.prefix(&view.items, [0x31]) {
        let (key, value) = entry.into_inner().map_err(super::engine_error)?;
        if key.len() != 33 || value.len() != 8 {
            return Err("Invalid block hash index encoding".into());
        }
        let hash = B256::from_slice(&key[1..]);
        let height = u64::from_be_bytes(
            value
                .as_ref()
                .try_into()
                .map_err(|_| "Invalid indexed height")?,
        );
        if block_hashes.get(&hash) != Some(&height) {
            return Err("Block hash index differs from retained chain".into());
        }
    }
    for entry in view.snapshot.iter(&view.items) {
        let key = entry.key().map_err(super::engine_error)?;
        if !matches!(
            key.first(),
            Some(0x01 | 0x02 | 0x03 | 0x10 | 0x11 | 0x12 | 0x20 | 0x21 | 0x22 | 0x23 | 0x30 | 0x31)
        ) {
            return Err("unknown authoritative key namespace".into());
        }
    }
    Ok(())
}

fn read_raw(view: &ReadView, hash: B256) -> Result<Vec<u8>, String> {
    view.raw_transaction(hash)?
        .ok_or_else(|| "missing retained transaction envelope".into())
}

fn validate_pending(
    view: &ReadView,
    expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    resolved: &BTreeSet<B256>,
) -> Result<(), String> {
    let counter = view.get([0x03])?.ok_or("missing pending ordinal counter")?;
    if counter.len() != 8 {
        return Err("malformed pending ordinal counter".into());
    }
    let counter = u64::from_be_bytes(counter.try_into().unwrap());
    let mut senders = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for entry in view.snapshot.prefix(&view.items, [0x23]) {
        let (pending_key, bytes) = entry.into_inner().map_err(super::engine_error)?;
        if pending_key.len() != 9 || hashes.len() >= crate::protocol::MAX_PENDING {
            return Err("invalid pending recovery bound".into());
        }
        let ordinal = u64::from_be_bytes(pending_key[1..].try_into().unwrap());
        if ordinal == 0 || ordinal > counter {
            return Err("invalid recovered pending ordinal".into());
        }
        let mut input = Decoder::new(&bytes)?;
        let hash = input.hash()?;
        let sender = input.address()?;
        input.finish()?;
        if resolved.contains(&hash) || !hashes.insert(hash) || !senders.insert(sender) {
            return Err("duplicate recovered pending identity".into());
        }
        let raw = read_raw(view, hash)?;
        let info = crate::execution::inspect_for_chain(&raw, view.chain_id())
            .map_err(|_| "invalid pending signed envelope")?;
        if info.hash != hash || info.sender != sender {
            return Err("pending sender identity mismatch".into());
        }
        expected.insert(key(0x20, hash.as_slice()), raw);
        let status = TransactionStatus {
            hash,
            status: "durably_accepted".into(),
            block_height: None,
            error: None,
        };
        expected.insert(key(0x21, hash.as_slice()), records::encode_status(&status)?);
    }
    Ok(())
}
