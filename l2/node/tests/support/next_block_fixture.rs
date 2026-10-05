//! Public development fixtures and exact accounting for the live next-block test.
use alephium_l2_node::{development, protocol::*, storage::ReadView};
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::json;
use std::{fs::OpenOptions, path::Path};

pub(super) const GAS: u64 = 21_000;

#[derive(Clone)]
pub(super) struct Expected {
    pub sender: Address,
    pub recipient: Address,
    pub value: U256,
    pub hash: B256,
}

pub(super) struct Plan {
    pub genesis: Genesis,
    signers: Vec<PrivateKeySigner>,
    recipients: Vec<Address>,
}

impl Plan {
    pub(super) fn new(directory: &Path, count: usize) -> Result<Self, String> {
        // Scalars 1..100 are public fixtures, never production signing material.
        let signers: Vec<_> = (1..=count)
            .map(|scalar| PrivateKeySigner::from_bytes(&B256::from(U256::from(scalar))).unwrap())
            .collect();
        let genesis = Genesis {
            chain_id: CHAIN_ID,
            capacity: Default::default(),
            accounts: signers
                .iter()
                .map(|signer| GenesisAccount {
                    address: signer.address(),
                    balance: U256::from(development::INITIAL_BALANCE),
                })
                .collect(),
        };
        genesis.validate()?;
        let recipients: Vec<_> = (0..count)
            .map(|index| Address::repeat_byte(0x80 + index as u8))
            .collect();
        for recipient in &recipients {
            assert!(
                genesis
                    .accounts
                    .iter()
                    .all(|account| account.address != *recipient)
            );
            assert_ne!(*recipient, Address::ZERO);
        }
        // Synchronize public unsigned intent before any signing. The service
        // starts before sign(), and no fixture is pre-admitted into storage.
        let intents: Vec<_> = signers
            .iter()
            .zip(&recipients)
            .enumerate()
            .map(|(index, (signer, recipient))| {
                json!({"chain_id":CHAIN_ID,"sender":signer.address(),"to":recipient,
                    "nonce":0,"value":1000+index,"gas_limit":GAS,"gas_price":1})
            })
            .collect();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("unsigned-intents.json"))
            .map_err(|error| error.to_string())?;
        serde_json::to_writer(&mut file, &intents).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        Ok(Self {
            genesis,
            signers,
            recipients,
        })
    }

    pub(super) fn sign(&self) -> Result<Vec<(Expected, Vec<u8>)>, String> {
        let mut signed = Vec::with_capacity(self.signers.len());
        for (index, (signer, recipient)) in self.signers.iter().zip(&self.recipients).enumerate() {
            let value = U256::from(1000 + index);
            let transaction = TxLegacy {
                chain_id: Some(CHAIN_ID),
                nonce: 0,
                gas_price: 1,
                gas_limit: GAS,
                to: TxKind::Call(*recipient),
                value,
                input: Bytes::new(),
            };
            let signature = signer
                .sign_hash_sync(&transaction.signature_hash())
                .map_err(|_| "Fixture signing failed")?;
            let envelope: TxEnvelope = transaction.into_signed(signature).into();
            let raw = envelope.encoded_2718();
            signed.push((
                Expected {
                    sender: signer.address(),
                    recipient: *recipient,
                    value,
                    hash: keccak256(&raw),
                },
                raw,
            ));
        }
        Ok(signed)
    }
}

pub(super) fn verify(view: &ReadView, expected: &[Expected]) -> Result<Vec<Receipt>, String> {
    assert!(view.head.height >= 1 && view.head.height <= expected.len() as u64);
    let expected_hashes: std::collections::BTreeSet<_> =
        expected.iter().map(|item| item.hash).collect();
    let mut actual_hashes = std::collections::BTreeSet::new();
    for height in 1..=view.head.height {
        let block = view.replay_block(height)?.ok_or("Missing fixture block")?;
        assert!(block.rejected.is_empty());
        assert!(!block.transactions.is_empty());
        for hash in block.transactions {
            assert!(
                actual_hashes.insert(hash),
                "Duplicate committed transaction"
            );
        }
    }
    assert_eq!(actual_hashes, expected_hashes);
    let mut receipts = Vec::with_capacity(expected.len());
    let mut total = U256::ZERO;
    for item in expected {
        let receipt = view.receipt(item.hash)?.ok_or("Missing fixture receipt")?;
        let block = view
            .replay_block(receipt.block_height)?
            .ok_or("Missing receipt block")?;
        assert_eq!(receipt.hash, item.hash);
        assert_eq!(receipt.from, item.sender);
        assert_eq!(receipt.to, Some(item.recipient));
        assert_eq!(receipt.contract, None);
        assert!(receipt.success && receipt.logs.is_empty());
        assert_eq!(receipt.gas_used, GAS);
        assert_eq!(receipt.gas_price, 1);
        assert_eq!(receipt.block_hash, block.head.commit_id);
        assert_eq!(
            block.transactions.get(receipt.transaction_index as usize),
            Some(&item.hash)
        );
        assert_eq!(
            receipt.cumulative_gas,
            GAS * (receipt.transaction_index + 1)
        );
        assert_eq!(receipt.first_log_index, 0);
        let raw = view
            .raw_transaction(item.hash)?
            .ok_or("Missing canonical envelope")?;
        assert_eq!(keccak256(raw), item.hash);
        let status = view.status(item.hash)?.ok_or("Missing fixture status")?;
        assert_eq!(status.status, "committed");
        assert_eq!(status.block_height, Some(receipt.block_height));
        assert!(status.error.is_none());
        let sender = view.account(item.sender)?.ok_or("Missing fixture sender")?;
        let recipient = view
            .account(item.recipient)?
            .ok_or("Missing fixture recipient")?;
        assert_eq!(sender.nonce, 1);
        assert_eq!(
            sender.balance,
            U256::from(development::INITIAL_BALANCE) - item.value - U256::from(GAS)
        );
        assert_eq!(recipient.balance, item.value);
        assert_eq!(recipient.nonce, 0);
        total += sender.balance + recipient.balance;
        receipts.push(receipt);
    }
    let beneficiary = view
        .account(Address::ZERO)?
        .ok_or("Missing fee beneficiary")?;
    assert_eq!(
        beneficiary.balance,
        U256::from(GAS) * U256::from(expected.len())
    );
    assert_eq!(beneficiary.nonce, 0);
    total += beneficiary.balance;
    assert_eq!(
        total,
        U256::from(development::INITIAL_BALANCE) * U256::from(expected.len())
    );
    assert_eq!(view.pending_counter()?, expected.len() as u64);
    Ok(receipts)
}
