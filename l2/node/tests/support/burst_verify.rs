//! All-offered durable receipts, exact accounting and actual chain membership.
use super::{
    Observed,
    fixture::{FUNDED_BALANCE, TRANSFER_GAS},
};
use alephium_l2_node::{development, protocol::Receipt, storage::ReadView};
use alloy_primitives::{Address, B256, U256, keccak256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn verify(
    view: &ReadView,
    observations: &[Observed],
    setup: &[Receipt],
    contract: Address,
) -> Result<Vec<Receipt>, String> {
    let accepted = observations.iter().filter(|item| item.durable_ack).count();
    assert_eq!(
        accepted,
        observations.len(),
        "Every offered request must receive a durable ACK"
    );
    assert!(
        observations
            .iter()
            .all(|o| o.rejection.is_none() && o.failure.is_none())
    );
    let mut expected_hashes: BTreeSet<_> = setup.iter().map(|r| r.hash).collect();
    expected_hashes.extend(observations.iter().map(|o| o.expected.hash));
    assert_eq!(expected_hashes.len(), setup.len() + accepted);
    let mut actual_hashes = BTreeSet::new();
    // This cache belongs to this immutable view and this verification call.
    // Reopened verification constructs it again; no prior-view data is reused.
    let mut blocks = BTreeMap::new();
    for height in 1..=view.head.height {
        let block = view.replay_block(height)?.ok_or("Missing burst block")?;
        assert!(block.rejected.is_empty());
        assert!(!block.transactions.is_empty());
        for hash in &block.transactions {
            assert!(actual_hashes.insert(*hash), "Duplicate block transaction");
        }
        blocks.insert(height, block);
    }
    let genesis_hash = view.block_hash(0)?;
    let block_hash = |height: u64| -> Result<B256, String> {
        if height == 0 {
            return Ok(genesis_hash);
        }
        Ok(blocks
            .get(&height)
            .ok_or("Missing cached ancestry block")?
            .head
            .commit_id)
    };
    assert_eq!(actual_hashes, expected_hashes);
    assert_eq!(view.pending_counter()?, expected_hashes.len() as u64);
    let setup_fees: U256 = setup
        .iter()
        .map(|r| U256::from(r.gas_used) * U256::from(r.gas_price))
        .sum();
    let mut total = U256::ZERO;
    let mut receipts = Vec::with_capacity(accepted);
    for observed in observations {
        let item = &observed.expected;
        let sender = view.account(item.sender)?.ok_or("Missing burst sender")?;
        let receipt = view.receipt(item.hash)?.ok_or("Missing accepted receipt")?;
        let block = blocks
            .get(&receipt.block_height)
            .ok_or("Missing receipt block")?;
        assert_eq!(receipt.hash, item.hash);
        assert_eq!(receipt.from, item.sender);
        assert_eq!(receipt.to, Some(item.recipient));
        assert_eq!(receipt.contract, None);
        assert!(receipt.success && receipt.logs.is_empty());
        assert_eq!(receipt.gas_used, TRANSFER_GAS);
        assert_eq!(receipt.gas_price, 1);
        let fee = U256::from(receipt.gas_used) * U256::from(receipt.gas_price);
        assert!(receipt.block_height > observed.parent.height);
        assert_eq!(observed.parent.genesis_id, view.head.genesis_id);
        assert_eq!(
            block_hash(observed.parent.height)?,
            observed.parent.commit_id
        );
        assert_eq!(block.parent.height, receipt.block_height - 1);
        assert_eq!(block_hash(block.parent.height)?, block.parent.commit_id);
        if receipt.block_height == observed.parent.height + 1 {
            assert_eq!(block.parent, observed.parent);
        }
        assert_eq!(receipt.block_hash, block.head.commit_id);
        assert_eq!(
            block.transactions.get(receipt.transaction_index as usize),
            Some(&item.hash)
        );
        assert_eq!(
            receipt.cumulative_gas,
            TRANSFER_GAS * (receipt.transaction_index + 1)
        );
        assert_eq!(receipt.first_log_index, 0);
        let raw = view
            .raw_transaction(item.hash)?
            .ok_or("Missing accepted envelope")?;
        assert_eq!(keccak256(raw), item.hash);
        let status = view.status(item.hash)?.ok_or("Missing accepted status")?;
        assert_eq!(status.status, "committed");
        assert_eq!(status.block_height, Some(receipt.block_height));
        assert!(status.error.is_none());
        assert_eq!(sender.nonce, 1);
        assert_eq!(
            sender.balance,
            U256::from(FUNDED_BALANCE) - item.value - fee
        );
        let recipient = view
            .account(item.recipient)?
            .ok_or("Missing transfer recipient")?;
        assert_eq!(recipient.balance, item.value);
        assert_eq!(recipient.nonce, 0);
        assert!(view.code(recipient.code_hash)?.is_empty());
        total += recipient.balance;
        receipts.push(receipt);
        assert!(view.code(sender.code_hash)?.is_empty());
        total += sender.balance;
    }
    for expected in setup {
        assert_eq!(view.receipt(expected.hash)?.as_ref(), Some(expected));
        assert!(expected.success && expected.logs.is_empty());
    }
    let root = view
        .account(development::address())?
        .ok_or("Missing funding root")?;
    assert_eq!(root.nonce, setup.len() as u64);
    assert_eq!(
        root.balance,
        U256::from(development::INITIAL_BALANCE)
            - U256::from(FUNDED_BALANCE) * U256::from(observations.len())
            - setup_fees
    );
    let fixture = view.account(contract)?.ok_or("Missing funding fixture")?;
    assert_eq!(fixture.balance, U256::ZERO);
    assert_eq!(fixture.nonce, 1);
    let beneficiary = view
        .account(Address::ZERO)?
        .ok_or("Missing fee beneficiary")?;
    let measured_fees: U256 = receipts
        .iter()
        .map(|r| U256::from(r.gas_used) * U256::from(r.gas_price))
        .sum();
    assert_eq!(beneficiary.balance, setup_fees + measured_fees);
    assert_eq!(beneficiary.nonce, 0);
    total += root.balance + fixture.balance + beneficiary.balance;
    assert_eq!(total, U256::from(development::INITIAL_BALANCE));
    receipts.sort_by_key(|r| r.hash);
    Ok(receipts)
}
