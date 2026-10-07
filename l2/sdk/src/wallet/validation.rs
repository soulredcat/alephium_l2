//! Caller-selected intent binding and complete supported EVM transaction checks.
use super::types::*;
use crate::PreparedTransaction;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::{
    eip2718::Decodable2718,
    eip2930::{AccessList, AccessListItem},
};
use alloy_primitives::{B256, keccak256};

/// EVM payload digest is its ordinary unsigned signing hash; L1 payload digest
/// is Keccak of opaque bytes only, never proof of safe or authorized spending.
/// Intent Keccak hashes DOMAIN || version(u32 BE) || requestID32 || intentID32 ||
/// namespace/network/account || payloadDigest32. L1 context is 0 || network(u8)
/// || genesis32 || addressLength(u32 BE) || addressUTF8; EVM context is 1 ||
/// chain(u64 BE) || genesis32 || address20. The versioned DTO accepts no extras.
pub fn prepare_wallet_request(
    request_id: B256,
    intent_id: B256,
    network: WalletNetwork,
    from: WalletAccount,
    payload: WalletPayload,
) -> Result<WalletRequest, WalletAdapterError> {
    let mut request = WalletRequest {
        binding: WalletRequestBinding {
            protocol_version: WALLET_ADAPTER_VERSION,
            request_id,
            intent_id,
            network,
            from,
            payload_keccak256: B256::ZERO,
            intent_keccak256: B256::ZERO,
        },
        payload,
    };
    check_request_context(&request)?;
    request.binding.payload_keccak256 = payload_digest(&request.payload);
    request.binding.intent_keccak256 = intent_digest(&request.binding);
    validate_wallet_request(&request)?;
    Ok(request)
}

pub fn validate_wallet_request(request: &WalletRequest) -> Result<(), WalletAdapterError> {
    check_request_context(request)?;
    if payload_digest(&request.payload) != request.binding.payload_keccak256
        || intent_digest(&request.binding) != request.binding.intent_keccak256
    {
        return Err(WalletAdapterError::BindingMismatch);
    }
    Ok(())
}

/// `expected` comes from the caller's retained intent, never from wallet output.
/// Echoed genesis/request metadata is local context, not authenticated by the
/// EVM signature. Keep the SDK Client's independent ExpectedNetwork handshake.
pub fn validate_wallet_response(
    expected: &WalletRequest,
    response: &WalletResponse,
) -> Result<ValidatedWalletResponse, WalletAdapterError> {
    validate_wallet_request(expected)?;
    if response.binding != expected.binding {
        return Err(WalletAdapterError::BindingMismatch);
    }
    match &response.result {
        WalletResponseOutcome::Unsupported { capability } => {
            if *capability != request_capability(expected) {
                return Err(WalletAdapterError::BindingMismatch);
            }
            Ok(ValidatedWalletResponse::Unsupported(*capability))
        }
        WalletResponseOutcome::Rejected => Ok(ValidatedWalletResponse::Rejected),
        WalletResponseOutcome::SignedAlephium { .. } => {
            Err(WalletAdapterError::UnsupportedL1Validation)
        }
        WalletResponseOutcome::SignedEvm { signed_transaction } => {
            let (
                WalletNetwork::EvmL2 { chain_id, .. },
                WalletAccount::EvmL2 { address },
                WalletPayload::EvmL2 { transaction },
            ) = (
                &expected.binding.network,
                &expected.binding.from,
                &expected.payload,
            )
            else {
                return Err(WalletAdapterError::BindingMismatch);
            };
            if signed_transaction.is_empty() || signed_transaction.len() > MAX_WALLET_PAYLOAD_BYTES
            {
                return Err(WalletAdapterError::InvalidSignedTransaction);
            }
            let prepared = PreparedTransaction::new(signed_transaction.to_vec(), *chain_id)
                .map_err(|_| WalletAdapterError::InvalidSignedTransaction)?;
            if prepared.sender() != *address {
                return Err(WalletAdapterError::InvalidSignedTransaction);
            }
            let mut raw = prepared.as_bytes();
            let envelope = TxEnvelope::decode_2718(&mut raw)
                .map_err(|_| WalletAdapterError::InvalidSignedTransaction)?;
            let exact = match (&envelope, &transaction.fees) {
                (TxEnvelope::Legacy(signed), EvmFees::Legacy { .. }) => {
                    signed.tx() == &legacy(transaction)
                }
                (TxEnvelope::Eip1559(signed), EvmFees::Eip1559 { .. }) => {
                    signed.tx() == &eip1559(transaction)
                }
                _ => false,
            };
            if !raw.is_empty() || !exact {
                return Err(WalletAdapterError::InvalidSignedTransaction);
            }
            Ok(ValidatedWalletResponse::Evm(prepared))
        }
    }
}

pub fn request_capability(request: &WalletRequest) -> WalletCapability {
    match request.payload {
        WalletPayload::AlephiumL1 { .. } => WalletCapability::AlephiumL1Transaction,
        WalletPayload::EvmL2 { .. } => WalletCapability::EvmL2Transaction,
    }
}

fn check_request_context(request: &WalletRequest) -> Result<(), WalletAdapterError> {
    let binding = &request.binding;
    if binding.protocol_version != WALLET_ADAPTER_VERSION {
        return Err(WalletAdapterError::UnsupportedVersion);
    }
    if binding.request_id == B256::ZERO || binding.intent_id == B256::ZERO {
        return Err(WalletAdapterError::InvalidRequest);
    }
    match (&binding.network, &binding.from, &request.payload) {
        (
            WalletNetwork::AlephiumL1 {
                network_id,
                genesis_id,
            },
            WalletAccount::AlephiumL1 { address },
            WalletPayload::AlephiumL1 {
                unsigned_encoded_tx,
            },
        ) => {
            if *network_id > 2
                || *genesis_id == B256::ZERO
                || address.is_empty()
                || address.len() > 256
                || unsigned_encoded_tx.is_empty()
                || unsigned_encoded_tx.len() > MAX_WALLET_PAYLOAD_BYTES
            {
                return Err(WalletAdapterError::InvalidRequest);
            }
        }
        (
            WalletNetwork::EvmL2 {
                chain_id,
                genesis_id,
            },
            WalletAccount::EvmL2 { address },
            WalletPayload::EvmL2 { transaction },
        ) => {
            if *chain_id == 0
                || *genesis_id == B256::ZERO
                || address.is_zero()
                || transaction.chain_id != *chain_id
                || transaction.gas_limit == 0
            {
                return Err(WalletAdapterError::InvalidRequest);
            }
            check_evm_size(transaction)?;
            match transaction.fees {
                EvmFees::Legacy { .. } if !transaction.access_list.is_empty() => {
                    return Err(WalletAdapterError::InvalidRequest);
                }
                EvmFees::Eip1559 {
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                } if max_priority_fee_per_gas > max_fee_per_gas => {
                    return Err(WalletAdapterError::InvalidRequest);
                }
                _ => (),
            }
        }
        _ => return Err(WalletAdapterError::InvalidRequest),
    }
    Ok(())
}

fn check_evm_size(transaction: &EvmTransactionIntent) -> Result<(), WalletAdapterError> {
    let mut size = transaction.input.len();
    for item in &transaction.access_list {
        size = item
            .storage_keys
            .len()
            .checked_mul(32)
            .and_then(|keys| keys.checked_add(20))
            .and_then(|bytes| size.checked_add(bytes))
            .ok_or(WalletAdapterError::InvalidRequest)?;
        if size > MAX_WALLET_PAYLOAD_BYTES {
            return Err(WalletAdapterError::InvalidRequest);
        }
    }
    if size > MAX_WALLET_PAYLOAD_BYTES {
        return Err(WalletAdapterError::InvalidRequest);
    }
    Ok(())
}

fn payload_digest(payload: &WalletPayload) -> B256 {
    match payload {
        WalletPayload::AlephiumL1 {
            unsigned_encoded_tx,
        } => keccak256(unsigned_encoded_tx),
        WalletPayload::EvmL2 { transaction } => match transaction.fees {
            EvmFees::Legacy { .. } => legacy(transaction).signature_hash(),
            EvmFees::Eip1559 { .. } => eip1559(transaction).signature_hash(),
        },
    }
}

/// Fixed-width BE integers; L1 address is UTF-8 prefixed by its u32 BE length.
/// Namespace byte is 0 for Alephium L1 or 1 for EVM L2. No JSON hashing.
fn intent_digest(binding: &WalletRequestBinding) -> B256 {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(WALLET_INTENT_KECCAK256_DOMAIN);
    bytes.extend_from_slice(&binding.protocol_version.to_be_bytes());
    bytes.extend_from_slice(binding.request_id.as_slice());
    bytes.extend_from_slice(binding.intent_id.as_slice());
    match (&binding.network, &binding.from) {
        (
            WalletNetwork::AlephiumL1 {
                network_id,
                genesis_id,
            },
            WalletAccount::AlephiumL1 { address },
        ) => {
            bytes.extend_from_slice(&[0, *network_id]);
            bytes.extend_from_slice(genesis_id.as_slice());
            bytes.extend_from_slice(&(address.len() as u32).to_be_bytes());
            bytes.extend_from_slice(address.as_bytes());
        }
        (
            WalletNetwork::EvmL2 {
                chain_id,
                genesis_id,
            },
            WalletAccount::EvmL2 { address },
        ) => {
            bytes.push(1);
            bytes.extend_from_slice(&chain_id.to_be_bytes());
            bytes.extend_from_slice(genesis_id.as_slice());
            bytes.extend_from_slice(address.as_slice());
        }
        _ => (), // Invalid namespace combinations were rejected before hashing.
    }
    bytes.extend_from_slice(binding.payload_keccak256.as_slice());
    keccak256(bytes)
}

fn legacy(intent: &EvmTransactionIntent) -> TxLegacy {
    let gas_price = match intent.fees {
        EvmFees::Legacy { gas_price } => gas_price,
        _ => 0,
    };
    TxLegacy {
        chain_id: Some(intent.chain_id),
        nonce: intent.nonce,
        gas_price,
        gas_limit: intent.gas_limit,
        to: intent.to.into(),
        value: intent.value,
        input: intent.input.clone(),
    }
}

fn eip1559(intent: &EvmTransactionIntent) -> TxEip1559 {
    let (max_fee_per_gas, max_priority_fee_per_gas) = match intent.fees {
        EvmFees::Eip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => (max_fee_per_gas, max_priority_fee_per_gas),
        _ => (0, 0),
    };
    TxEip1559 {
        chain_id: intent.chain_id,
        nonce: intent.nonce,
        gas_limit: intent.gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: intent.to.into(),
        value: intent.value,
        input: intent.input.clone(),
        access_list: AccessList(
            intent
                .access_list
                .iter()
                .map(|item| AccessListItem {
                    address: item.address,
                    storage_keys: item.storage_keys.clone(),
                })
                .collect(),
        ),
    }
}
