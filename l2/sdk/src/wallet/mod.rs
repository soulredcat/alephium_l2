//! External wallet adapter scaffold for distinct Alephium L1 and EVM L2 domains.
//! Standard legacy/EIP-1559 signing is preserved; no wallet backend or keys live
//! here. Ethereum signatures bind chain and transaction, not a genesis hash.
mod types;
mod validation;

pub use types::*;
pub use validation::{
    prepare_wallet_request, request_capability, validate_wallet_request, validate_wallet_response,
};

/// Starting point for a future Alephium wallet supporting EVM accounts too.
/// Replace this ONLY in the external wallet implementation after implementing
/// user authorization, key custody, exact request binding and canonical signing.
/// Merely changing capabilities does not implement signing or install a wallet.
pub struct ExternalWalletAdapterTemplate;

impl WalletAdapter for ExternalWalletAdapterTemplate {
    fn capabilities(&self) -> WalletCapabilities {
        WalletCapabilities {
            protocol_version: WALLET_ADAPTER_VERSION,
            alephium_l1: CapabilitySupport::Unsupported,
            evm_l2: CapabilitySupport::Unsupported,
        }
    }

    fn request_signature(
        &mut self,
        request: &WalletRequest,
    ) -> Result<WalletResponse, WalletAdapterError> {
        validate_wallet_request(request)?;
        Ok(WalletResponse {
            binding: request.binding.clone(),
            result: WalletResponseOutcome::Unsupported {
                capability: request_capability(request),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
    use alloy_eips::{
        eip2718::Encodable2718,
        eip2930::{AccessList, AccessListItem},
    };
    use alloy_primitives::{Address, B256, Bytes, Signature, U256};

    #[test]
    fn aggregate_external_wallet_binding_validation() {
        // Public synthetic signature scalars only: no key custody or wallet
        // signing. Recovery supplies an algebraic signer for exact-body checks.
        let unsigned = TxLegacy {
            chain_id: Some(424_245),
            nonce: 7,
            gas_price: 2,
            gas_limit: 30_000,
            to: Address::repeat_byte(3).into(),
            value: U256::from(4),
            input: Bytes::from(vec![5]),
        };
        let envelope: TxEnvelope = unsigned
            .clone()
            .into_signed(Signature::new(U256::from(1), U256::from(1), false))
            .into();
        let raw = envelope.encoded_2718();
        let prepared = crate::PreparedTransaction::new(raw.clone(), 424_245).unwrap();
        let intent = EvmTransactionIntent {
            chain_id: 424_245,
            nonce: 7,
            gas_limit: 30_000,
            to: Some(Address::repeat_byte(3)),
            value: U256::from(4),
            input: Bytes::from(vec![5]),
            fees: EvmFees::Legacy { gas_price: 2 },
            access_list: vec![],
        };
        let request = prepare_wallet_request(
            B256::repeat_byte(1),
            B256::repeat_byte(2),
            WalletNetwork::EvmL2 {
                chain_id: 424_245,
                genesis_id: B256::repeat_byte(6),
            },
            WalletAccount::EvmL2 {
                address: prepared.sender(),
            },
            WalletPayload::EvmL2 {
                transaction: intent.clone(),
            },
        )
        .unwrap();
        let response = WalletResponse {
            binding: request.binding.clone(),
            result: WalletResponseOutcome::SignedEvm {
                signed_transaction: Bytes::from(raw.clone()),
            },
        };
        assert!(matches!(
            validate_wallet_response(&request, &response),
            Ok(ValidatedWalletResponse::Evm(_))
        ));
        let mut template = ExternalWalletAdapterTemplate;
        assert!(template.capabilities().evm_l2 == CapabilitySupport::Unsupported);
        assert!(matches!(
            validate_wallet_response(&request, &template.request_signature(&request).unwrap()),
            Ok(ValidatedWalletResponse::Unsupported(
                WalletCapability::EvmL2Transaction
            ))
        ));
        for change in [
            |b: &mut WalletRequestBinding| b.request_id = B256::repeat_byte(8),
            |b: &mut WalletRequestBinding| b.intent_id = B256::repeat_byte(8),
            |b: &mut WalletRequestBinding| b.protocol_version += 1,
            |b: &mut WalletRequestBinding| b.payload_keccak256 = B256::repeat_byte(8),
            |b: &mut WalletRequestBinding| b.intent_keccak256 = B256::repeat_byte(8),
        ] {
            let mut changed = response.clone();
            change(&mut changed.binding);
            assert!(validate_wallet_response(&request, &changed).is_err());
        }
        for change in [
            |t: &mut EvmTransactionIntent| t.nonce += 1,
            |t: &mut EvmTransactionIntent| t.gas_limit += 1,
            |t: &mut EvmTransactionIntent| t.value += U256::from(1),
            |t: &mut EvmTransactionIntent| t.to = None,
            |t: &mut EvmTransactionIntent| t.input = Bytes::from(vec![9]),
            |t: &mut EvmTransactionIntent| t.fees = EvmFees::Legacy { gas_price: 9 },
        ] {
            let mut changed_intent = intent.clone();
            change(&mut changed_intent);
            let changed = prepare_wallet_request(
                request.binding.request_id,
                request.binding.intent_id,
                request.binding.network.clone(),
                request.binding.from.clone(),
                WalletPayload::EvmL2 {
                    transaction: changed_intent,
                },
            )
            .unwrap();
            let mut wrong_body = response.clone();
            wrong_body.binding = changed.binding.clone();
            assert!(validate_wallet_response(&changed, &wrong_body).is_err());
        }
        let mut trailing = response.clone();
        let mut bytes = raw;
        bytes.push(0);
        trailing.result = WalletResponseOutcome::SignedEvm {
            signed_transaction: Bytes::from(bytes),
        };
        assert!(validate_wallet_response(&request, &trailing).is_err());
        let mut altered = request.clone();
        altered.binding.from = WalletAccount::AlephiumL1 {
            address: "synthetic-address".into(),
        };
        assert!(validate_wallet_request(&altered).is_err());
        let mut altered = request.clone();
        altered.binding.network = WalletNetwork::EvmL2 {
            chain_id: 0,
            genesis_id: B256::repeat_byte(6),
        };
        assert!(validate_wallet_request(&altered).is_err());
        let mut altered = response.clone();
        altered.binding.network = WalletNetwork::EvmL2 {
            chain_id: 424_245,
            genesis_id: B256::repeat_byte(7),
        };
        assert!(validate_wallet_response(&request, &altered).is_err());
        let l1 = prepare_wallet_request(
            B256::repeat_byte(1),
            B256::repeat_byte(2),
            WalletNetwork::AlephiumL1 {
                network_id: 1,
                genesis_id: B256::repeat_byte(6),
            },
            WalletAccount::AlephiumL1 {
                address: "synthetic-address".into(),
            },
            WalletPayload::AlephiumL1 {
                unsigned_encoded_tx: Bytes::from(vec![1]),
            },
        )
        .unwrap();
        let l1_signed = WalletResponse {
            binding: l1.binding.clone(),
            result: WalletResponseOutcome::SignedAlephium {
                signed_transaction: Bytes::from(vec![1]),
            },
        };
        assert!(matches!(
            validate_wallet_response(&l1, &l1_signed),
            Err(WalletAdapterError::UnsupportedL1Validation)
        ));
        let mut oversized = l1.clone();
        oversized.payload = WalletPayload::AlephiumL1 {
            unsigned_encoded_tx: Bytes::from(vec![1; MAX_WALLET_PAYLOAD_BYTES + 1]),
        };
        assert!(validate_wallet_request(&oversized).is_err());
        let mut no_id = request.clone();
        no_id.binding.request_id = B256::ZERO;
        assert!(validate_wallet_request(&no_id).is_err());
        let mut wrong_signer = response.clone();
        let alternate = prepare_wallet_request(
            request.binding.request_id,
            request.binding.intent_id,
            request.binding.network.clone(),
            WalletAccount::EvmL2 {
                address: Address::repeat_byte(13),
            },
            request.payload.clone(),
        )
        .unwrap();
        wrong_signer.binding = alternate.binding.clone();
        assert!(validate_wallet_response(&alternate, &wrong_signer).is_err());
        // Access-list order/content and both fee fields belong to the exact
        // EIP-1559 body; no field may be selected from wallet response metadata.
        let list_address = Address::repeat_byte(10);
        let storage_key = B256::repeat_byte(11);
        let typed = TxEip1559 {
            chain_id: 424_245,
            nonce: 8,
            gas_limit: 40_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 2,
            to: Address::repeat_byte(3).into(),
            value: U256::from(4),
            input: Bytes::from(vec![5]),
            access_list: AccessList(vec![AccessListItem {
                address: list_address,
                storage_keys: vec![storage_key],
            }]),
        };
        let typed: TxEnvelope = typed
            .into_signed(Signature::new(U256::from(1), U256::from(1), false))
            .into();
        let typed_raw = typed.encoded_2718();
        let typed_prepared = crate::PreparedTransaction::new(typed_raw.clone(), 424_245).unwrap();
        let typed_intent = EvmTransactionIntent {
            chain_id: 424_245,
            nonce: 8,
            gas_limit: 40_000,
            to: Some(Address::repeat_byte(3)),
            value: U256::from(4),
            input: Bytes::from(vec![5]),
            fees: EvmFees::Eip1559 {
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 2,
            },
            access_list: vec![WalletAccessListItem {
                address: list_address,
                storage_keys: vec![storage_key],
            }],
        };
        let typed_request = prepare_wallet_request(
            B256::repeat_byte(12),
            B256::repeat_byte(2),
            request.binding.network.clone(),
            WalletAccount::EvmL2 {
                address: typed_prepared.sender(),
            },
            WalletPayload::EvmL2 {
                transaction: typed_intent.clone(),
            },
        )
        .unwrap();
        let typed_response = WalletResponse {
            binding: typed_request.binding.clone(),
            result: WalletResponseOutcome::SignedEvm {
                signed_transaction: Bytes::from(typed_raw),
            },
        };
        assert!(matches!(
            validate_wallet_response(&typed_request, &typed_response),
            Ok(ValidatedWalletResponse::Evm(_))
        ));
        for change in [
            |t: &mut EvmTransactionIntent| t.access_list[0].storage_keys[0] = B256::repeat_byte(9),
            |t: &mut EvmTransactionIntent| {
                t.fees = EvmFees::Eip1559 {
                    max_fee_per_gas: 10,
                    max_priority_fee_per_gas: 3,
                }
            },
            |t: &mut EvmTransactionIntent| {
                t.fees = EvmFees::Eip1559 {
                    max_fee_per_gas: 11,
                    max_priority_fee_per_gas: 2,
                }
            },
        ] {
            let mut changed_intent = typed_intent.clone();
            change(&mut changed_intent);
            let changed = prepare_wallet_request(
                typed_request.binding.request_id,
                typed_request.binding.intent_id,
                typed_request.binding.network.clone(),
                typed_request.binding.from.clone(),
                WalletPayload::EvmL2 {
                    transaction: changed_intent,
                },
            )
            .unwrap();
            let mut wrong_body = typed_response.clone();
            wrong_body.binding = changed.binding.clone();
            assert!(validate_wallet_response(&changed, &wrong_body).is_err());
        }
    }
}
