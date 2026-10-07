//! Exact receipts, ancestry, balances and private replay-derived witness checks.
use super::{
    flow::Observed,
    plan::{Plan, WALLET_BALANCE},
    storage_fixture,
};
use alephium_l2_node::{
    development,
    operator::{self, SettlementDomain},
    protocol::{Head, Receipt, checkpoint::ExecutionCheckpoint},
    storage::ReadView,
};
use alloy_primitives::{Address, B256, U256, keccak256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(PartialEq, Eq)]
pub(super) struct Snapshot {
    pub head: Head,
    pub state_digest: B256,
    pub receipts: Vec<Receipt>,
    pub checkpoint: ExecutionCheckpoint,
}

pub(super) fn verify(
    view: &ReadView,
    plan: &Plan,
    observations: &[Observed],
) -> Result<Snapshot, String> {
    if observations.len() != plan.total
        || view.capacity() != plan.genesis.capacity
        || view.chain_id() != plan.genesis.chain_id
        || view.pending_counter()? != plan.total as u64
        || view.head.height == 0
        || view.head.height > operator::MAX_TRANSITION_BLOCKS
    {
        return Err("Fixture profile, admission count or bounded history differs".into());
    }
    let expected: BTreeSet<_> = observations.iter().map(|o| o.expected.hash).collect();
    if expected.len() != plan.total {
        return Err("Fixture has duplicate transaction identities".into());
    }
    let mut actual = BTreeSet::new();
    let mut previous = view.block_hash(0)?;
    let mut blocks = BTreeMap::new();
    for height in 1..=view.head.height {
        let block = view
            .replay_block(height)?
            .ok_or("Missing fixture execution block")?;
        if block.parent.height != height - 1
            || block.parent.commit_id != previous
            || block.head.height != height
            || block.transactions.is_empty()
            || !block.rejected.is_empty()
            || block.context.gas_limit != plan.genesis.capacity.block_gas
        {
            return Err("Fixture ordered block ancestry or execution profile differs".into());
        }
        previous = block.head.commit_id;
        let mut cumulative = 0_u64;
        let mut log_index = 0_u64;
        for (index, hash) in block.transactions.iter().enumerate() {
            if !actual.insert(*hash) {
                return Err("Duplicate committed fixture transaction".into());
            }
            let receipt = view
                .receipt(*hash)?
                .ok_or("Ordered block receipt missing")?;
            cumulative = cumulative
                .checked_add(receipt.gas_used)
                .ok_or("Fixture cumulative gas overflow")?;
            if receipt.transaction_index != index as u64
                || receipt.cumulative_gas != cumulative
                || receipt.first_log_index != log_index
            {
                return Err("Mixed-operation cumulative gas or log indices differ".into());
            }
            log_index += receipt.logs.len() as u64;
        }
        blocks.insert(height, block);
    }
    if expected != actual || previous != view.head.commit_id {
        return Err("Committed fixture membership differs from the declared input count".into());
    }
    let mut receipts = Vec::with_capacity(plan.total);
    let mut total_fees = U256::ZERO;
    let mut root_fees = U256::ZERO;
    let mut root_value = U256::ZERO;
    for observation in observations {
        let item = &observation.expected;
        let receipt = view
            .receipt(item.hash)?
            .ok_or("Missing committed fixture receipt")?;
        let block = blocks
            .get(&receipt.block_height)
            .ok_or("Receipt block missing")?;
        let status = view.status(item.hash)?.ok_or("Receipt status missing")?;
        let expected_status = if receipt.success {
            "committed"
        } else {
            "reverted"
        };
        if observation.receipt.as_ref() != Some(&receipt)
            || receipt.from != item.sender
            || receipt.to != item.to
            || receipt.success != item.success
            || receipt.gas_price != item.gas_price
            || receipt.block_height <= observation.parent.height
            || observation.parent.genesis_id != view.head.genesis_id
            || view.block_hash(observation.parent.height)? != observation.parent.commit_id
            || receipt.block_hash != block.head.commit_id
            || block.transactions.get(receipt.transaction_index as usize) != Some(&item.hash)
            || status.status != expected_status
            || status.error.is_some()
            || status.block_height != Some(receipt.block_height)
            || keccak256(
                view.raw_transaction(item.hash)?
                    .ok_or("Committed envelope missing")?,
            ) != item.hash
        {
            return Err("Committed receipt, durable status or arrival ancestry differs".into());
        }
        let fee = U256::from(receipt.gas_used) * U256::from(receipt.gas_price);
        total_fees += fee;
        if item.sender == development::address() {
            root_fees += fee;
            if receipt.success {
                root_value += item.value;
            }
        } else if receipt.gas_used != 21_000
            || receipt.contract.is_some()
            || !receipt.logs.is_empty()
        {
            return Err("Wallet transfer receipt differs from exact native transfer".into());
        }
        receipts.push(receipt);
    }
    let mut total = U256::ZERO;
    for (signer, recipient, value) in &plan.wallets {
        let sender = view
            .account(signer.address())?
            .ok_or("Genesis-funded wallet missing")?;
        let receiver = view
            .account(*recipient)?
            .ok_or("Wallet transfer recipient missing")?;
        if sender.nonce != 1
            || sender.balance != U256::from(WALLET_BALANCE) - *value - U256::from(21_000)
            || receiver.balance != *value
            || receiver.nonce != 0
            || !view.code(sender.code_hash)?.is_empty()
            || !view.code(receiver.code_hash)?.is_empty()
        {
            return Err("Wallet transfer accounting or EOA state differs".into());
        }
        total += sender.balance + receiver.balance;
    }
    let root = view
        .account(development::address())?
        .ok_or("Development root missing")?;
    let recipient = view
        .account(plan.root_recipient)?
        .ok_or("Root transfer recipient missing")?;
    let contract = view
        .account(plan.contract)?
        .ok_or("Deployed fixture contract missing")?;
    let beneficiary = view
        .account(Address::ZERO)?
        .ok_or("Fee beneficiary missing")?;
    if root_value != U256::from(1_000)
        || root.nonce != 4
        || root.balance != U256::from(development::INITIAL_BALANCE) - root_value - root_fees
        || recipient.balance != U256::from(1_000)
        || recipient.nonce != 0
        || contract.balance != U256::ZERO
        || contract.nonce != 1
        || view.code(contract.code_hash)? != development::contract_runtime()
        || !view.code(root.code_hash)?.is_empty()
        || !view.code(recipient.code_hash)?.is_empty()
        || !view.code(beneficiary.code_hash)?.is_empty()
        || view.slot(plan.contract, U256::ZERO)? != U256::from(42)
        || beneficiary.balance != total_fees
        || beneficiary.nonce != 0
    {
        return Err("Root transfer/deploy/write/revert or exact fee accounting differs".into());
    }
    let root_receipts = &observations[plan.wallets.len()..];
    if root_receipts[1].receipt.as_ref().and_then(|r| r.contract) != Some(plan.contract)
        || root_receipts[2]
            .receipt
            .as_ref()
            .is_none_or(|r| r.logs.len() != 1)
        || root_receipts[3]
            .receipt
            .as_ref()
            .is_none_or(|r| r.success || !r.logs.is_empty())
    {
        return Err("Four-transaction contract lifecycle receipts differ".into());
    }
    total += root.balance + recipient.balance + contract.balance + beneficiary.balance;
    if total
        != U256::from(development::INITIAL_BALANCE)
            + U256::from(WALLET_BALANCE) * U256::from(plan.wallets.len())
    {
        return Err("Fixture global exact integer accounting differs".into());
    }
    receipts.sort_by_key(|receipt| receipt.hash);
    let checkpoint = view.execution_checkpoint()?;
    let full_balance: U256 = checkpoint
        .accounts
        .iter()
        .filter(|account| !account.deleted)
        .map(|account| account.balance)
        .sum();
    if full_balance != total
        || checkpoint.accounts.len() != plan.wallets.len() * 2 + 4
        || checkpoint.codes.len() != 1
        || checkpoint.accounts.iter().any(|account| {
            account.deleted
                || (account.address != plan.contract && !account.slots.is_empty())
                || (account.address == plan.contract && account.slots.len() != 1)
        })
    {
        return Err("Full committed checkpoint accounting or account membership differs".into());
    }
    Ok(Snapshot {
        head: view.head.clone(),
        state_digest: view.state_digest()?,
        receipts,
        checkpoint,
    })
}

pub(super) fn export(root: &Path, plan: &Plan, snapshot: &Snapshot) -> Result<(), String> {
    let backup = root.join("backup");
    operator::backup(&root.join("data"), &backup, &plan.genesis)?;
    let report = operator::prepare_transition_checkpoint(
        &backup,
        &plan.genesis,
        &root.join("export"),
        1,
        SettlementDomain {
            l1_network: 1,
            l1_genesis_id: B256::repeat_byte(0x11),
            settlement_contract_id: B256::repeat_byte(0x22),
        },
    )?;
    if report.schema != 4
        || report.parent.height != 0
        || report.head != snapshot.head
        || report.expected_state_digest != snapshot.state_digest
        || report.executed_transactions != plan.total as u64
        || !report.semantic_replay_verified
        || report.guest_proof_generated
        || report.settlement_verified
    {
        return Err("Actual schema-four checkpoint export metadata differs".into());
    }
    let bytes = std::fs::read(&report.bundle_path)
        .map_err(|_| "Cannot read private development checkpoint witness")?;
    let bundle = operator::decode_large_checkpoint_transition(&bytes)?;
    if bundle.checkpoint.head.height != 0
        || bundle.checkpoint.capacity != plan.genesis.capacity
        || !bundle.checkpoint.codes.is_empty()
        || bundle.checkpoint.accounts.len() != plan.genesis.accounts.len()
        || bundle
            .checkpoint
            .accounts
            .iter()
            .any(|a| a.nonce != 0 || !a.slots.is_empty())
        || bundle
            .blocks
            .iter()
            .map(|b| b.transactions.len())
            .sum::<usize>()
            != plan.total
    {
        return Err("Development witness does not start at actual funded genesis".into());
    }
    let allocations: BTreeMap<_, _> = plan
        .genesis
        .accounts
        .iter()
        .map(|account| (account.address, account.balance))
        .collect();
    if bundle.checkpoint.accounts.iter().any(|account| {
        account.deleted || allocations.get(&account.address) != Some(&account.balance)
    }) {
        return Err("Witness initial state differs from the declared funded genesis".into());
    }
    let expected: BTreeMap<_, _> = snapshot.receipts.iter().map(|r| (r.hash, r)).collect();
    let mut witnessed = BTreeSet::new();
    for input in bundle.blocks.iter().flat_map(|block| &block.transactions) {
        if !witnessed.insert(input.transaction_hash)
            || expected.get(&input.transaction_hash).copied() != Some(&input.expected_receipt)
        {
            return Err("Development witness receipt/membership differs".into());
        }
    }
    if witnessed.len() != plan.total {
        return Err("Development witness transaction count differs".into());
    }
    if operator::encode_large_checkpoint_transition(&bundle)? != bytes {
        return Err("Private schema-four witness canonical roundtrip differs".into());
    }
    storage_fixture::write_json(&root.join("final-checkpoint.json"), &snapshot.checkpoint)?;
    storage_fixture::write_json(&root.join("export-report.json"), &report)
}
