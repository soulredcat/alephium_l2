//! Publicly reproducible fixtures for isolated development chains. Never fund with real assets.
use crate::protocol::{CHAIN_ID, Genesis, GenesisAccount, validate_chain_id};
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

/// Initial development-only allocation, deliberately unrelated to legacy development state.
pub const INITIAL_BALANCE: u128 = 1_000_000_000_000_000_000_000_000;

fn signer() -> PrivateKeySigner {
    // Widely known scalar one. This is test material, not a secret or production authority.
    PrivateKeySigner::from_bytes(&B256::from(U256::from(1).to_be_bytes::<32>()))
        .expect("public development scalar is valid")
}

pub fn address() -> Address {
    signer().address()
}

pub fn genesis() -> Genesis {
    genesis_for_chain(CHAIN_ID).expect("default development identity is valid")
}

pub fn genesis_for_chain(chain_id: u64) -> Result<Genesis, String> {
    validate_chain_id(chain_id)?;
    Ok(Genesis {
        chain_id,
        capacity: Default::default(),
        accounts: vec![GenesisAccount {
            address: address(),
            balance: U256::from(INITIAL_BALANCE),
        }],
    })
}

/// Default-chain wrapper for the public development fixture.
pub fn sign(
    nonce: u64,
    to: Option<Address>,
    value: U256,
    data: Vec<u8>,
    gas: u64,
) -> Result<Vec<u8>, String> {
    sign_for_chain(CHAIN_ID, nonce, to, value, data, gas)
}

/// Public fixture only; callers must use isolated development assets and data.
pub fn sign_for_chain(
    chain_id: u64,
    nonce: u64,
    to: Option<Address>,
    value: U256,
    data: Vec<u8>,
    gas: u64,
) -> Result<Vec<u8>, String> {
    validate_chain_id(chain_id)?;
    let transaction = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 1,
        gas_limit: gas,
        to: to.map(TxKind::Call).unwrap_or(TxKind::Create),
        value,
        input: Bytes::from(data),
    };
    let signature = signer()
        .sign_hash_sync(&transaction.signature_hash())
        .map_err(|_| "development signature failed".to_owned())?;
    let envelope: TxEnvelope = transaction.into_signed(signature).into();
    Ok(envelope.encoded_2718())
}

/// Selected type-2 fixture, still confined to the public development identity.
#[allow(clippy::too_many_arguments)]
pub fn sign_type2(
    nonce: u64,
    to: Option<Address>,
    value: U256,
    data: Vec<u8>,
    gas: u64,
    max_fee: u128,
    priority: u128,
    access_list: AccessList,
) -> Result<Vec<u8>, String> {
    sign_type2_for_chain(
        CHAIN_ID,
        nonce,
        to,
        value,
        data,
        gas,
        max_fee,
        priority,
        access_list,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_type2_for_chain(
    chain_id: u64,
    nonce: u64,
    to: Option<Address>,
    value: U256,
    data: Vec<u8>,
    gas: u64,
    max_fee: u128,
    priority: u128,
    access_list: AccessList,
) -> Result<Vec<u8>, String> {
    validate_chain_id(chain_id)?;
    let transaction = TxEip1559 {
        chain_id,
        nonce,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: priority,
        gas_limit: gas,
        to: to.map_or(TxKind::Create, TxKind::Call),
        value,
        access_list,
        input: Bytes::from(data),
    };
    let signature = signer()
        .sign_hash_sync(&transaction.signature_hash())
        .map_err(|_| "development signature failed".to_owned())?;
    let envelope: TxEnvelope = transaction.into_signed(signature).into();
    Ok(envelope.encoded_2718())
}

/// Hand-authored EVM fixture, independent of any application or compiler installation.
/// Calldata word 0 selects: 0/read, 1/write 42 and LOG1, 2/write 99+LOG1 then REVERT,
/// 3/CALL the address in word 1 with empty calldata, log and return its 32-byte result.
/// Jump destinations are byte offsets 34, 58 and 82. Runtime is exactly 111 bytes.
pub fn contract_runtime() -> Vec<u8> {
    hex::decode(concat!(
        "6000358060011460225780600214603a57600314605257",
        "60005460005260206000f3",
        "5b50602a600055602a600052602a60206000a160006000f3",
        "5b5060636000556063600052606360206000a160006000fd",
        "5b602060006000600060006020355af150602a60206000a160206000f3"
    ))
    .expect("reviewed constant fixture hex")
}

pub fn contract_init() -> Vec<u8> {
    // CODECOPY 111 bytes from offset 12 into memory[0], then RETURN memory[0..111].
    let mut init = hex::decode("606f600c600039606f6000f3").expect("constant init hex");
    init.extend(contract_runtime());
    init
}

pub fn contract_input(command: u64, target: Option<Address>) -> Vec<u8> {
    let mut input = U256::from(command).to_be_bytes::<32>().to_vec();
    if let Some(target) = target {
        input.extend([0u8; 12]);
        input.extend(target.as_slice());
    }
    input
}
