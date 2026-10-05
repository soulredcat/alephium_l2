//! Hand-authored lifecycle opcodes and two public development-only signing identities.
use alephium_l2_node::{
    execution,
    protocol::{BLOCK_GAS, BlockCommit, BlockContext, CHAIN_ID, Pending, Receipt},
    storage::Store,
};
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

fn second_signer() -> PrivateKeySigner {
    // Public scalar two, solely for this fresh development genesis; never log signing material.
    PrivateKeySigner::from_bytes(&B256::from(U256::from(2).to_be_bytes::<32>()))
        .expect("public fixture scalar is valid")
}

pub(super) fn second_address() -> Address {
    second_signer().address()
}

pub(super) fn sign_second(
    nonce: u64,
    to: Option<Address>,
    value: U256,
    input: Vec<u8>,
    gas_limit: u64,
) -> Result<Vec<u8>, String> {
    let transaction = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: 1,
        gas_limit,
        to: to.map_or(TxKind::Create, TxKind::Call),
        value,
        input: Bytes::from(input),
    };
    let signature = second_signer()
        .sign_hash_sync(&transaction.signature_hash())
        .map_err(|_| "fixture signing failed".to_owned())?;
    let envelope: TxEnvelope = transaction.into_signed(signature).into();
    Ok(envelope.encoded_2718())
}

pub(super) fn context(number: u64) -> BlockContext {
    BlockContext {
        number,
        timestamp: 1_800_000_000 + number * 2,
        gas_limit: BLOCK_GAS,
    }
}

/// Admit distinct senders against committed state, execute in order, then durably commit.
pub(super) fn commit(
    store: &mut Store,
    inputs: &[Vec<u8>],
    number: u64,
) -> Result<Vec<Receipt>, String> {
    let context = context(number);
    for raw in inputs {
        let info = execution::validate(store.view()?, raw, context)?;
        let status = store.admit(Pending {
            hash: info.hash,
            sender: info.sender,
            raw: raw.clone(),
        })?;
        assert_eq!(status.status, "durably_accepted");
    }
    let view = store.view()?;
    let parent = view.head.clone();
    let result = execution::execute_block(view, inputs, context)?;
    assert!(result.rejected.is_empty());
    assert_eq!(result.receipts.len(), inputs.len());
    assert!(result.receipts.iter().all(|receipt| receipt.success));
    let view = store.commit(BlockCommit {
        parent,
        context,
        transactions: result.receipts.iter().map(|receipt| receipt.hash).collect(),
        changes: result.changes,
        receipts: result.receipts,
        rejected: result.rejected,
    })?;
    assert!(store.pending()?.is_empty());
    inputs
        .iter()
        .map(|raw| {
            view.receipt(keccak256(raw))?
                .ok_or_else(|| "missing lifecycle receipt".into())
        })
        .collect()
}

/// Calldata word 0 selects 1/write word 1 to slot 0, 2/copy slot 0 to slot 1,
/// or 3/SELFDESTRUCT to word 1. Other commands revert. JUMPDESTs are 28, 37, 46.
pub(super) fn runtime() -> Vec<u8> {
    hex::decode(concat!(
        "60003580600114601c5780600214602557600314602e5760006000fd",
        "5b5060203560005500",
        "5b5060005460015500",
        "5b602035ff"
    ))
    .expect("reviewed lifecycle opcode fixture")
}

pub(super) fn init() -> Vec<u8> {
    // CODECOPY the 51-byte runtime from offset 12, then RETURN it.
    let mut init = hex::decode("6033600c60003960336000f3").expect("reviewed init fixture");
    init.extend(runtime());
    init
}

pub(super) fn input(command: u64, value: U256) -> Vec<u8> {
    let mut input = U256::from(command).to_be_bytes::<32>().to_vec();
    input.extend(value.to_be_bytes::<32>());
    input
}

/// Top-level initcode destroys the account within its creation transaction.
pub(super) fn destroy_init(beneficiary: Address) -> Vec<u8> {
    let mut init = vec![0x73]; // PUSH20 beneficiary; SELFDESTRUCT.
    init.extend(beneficiary.as_slice());
    init.push(0xff);
    init
}
