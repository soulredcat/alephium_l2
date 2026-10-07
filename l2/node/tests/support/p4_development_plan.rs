//! Selected genesis-funded public fixture wallets and four root transactions.
use super::storage_fixture::write_json;
use alephium_l2_node::{
    development,
    protocol::{Capacity, Genesis, GenesisAccount},
};
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::json;
use std::{collections::BTreeSet, path::Path};

pub(super) const TRANSFERS: usize = 996;
pub(super) const TOTAL: usize = 1_000;
pub(super) const WALLET_BALANCE: u64 = 1_000_000;

pub(super) struct Plan {
    pub total: usize,
    pub genesis: Genesis,
    pub contract: Address,
    pub root_recipient: Address,
    pub wallets: Vec<(PrivateKeySigner, Address, U256)>,
}

#[derive(Clone)]
pub(super) struct Expected {
    pub hash: B256,
    pub sender: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub gas_price: u128,
    pub success: bool,
}

pub(super) struct Signed {
    pub expected: Expected,
    pub raw: Vec<u8>,
}

impl Plan {
    // The separate closure harness selects its count explicitly.
    #[allow(dead_code)]
    pub(super) fn new(root: &Path) -> Result<Self, String> {
        Self::new_with_transactions(root, TOTAL)
    }

    pub(super) fn new_with_transactions(root: &Path, total: usize) -> Result<Self, String> {
        let transfers = total
            .checked_sub(4)
            .filter(|count| *count <= TRANSFERS)
            .ok_or(
                "P4 fixture count must contain four root transactions and at most 996 transfers",
            )?;
        let mut genesis = development::genesis();
        genesis.capacity = Capacity {
            block_gas: 3_000_000_000,
            block_bytes: 32 * 1024 * 1024,
            max_pending: TOTAL,
        };
        let sender = development::address();
        let contract = sender.create(1);
        let root_recipient = Address::repeat_byte(0x44);
        let mut unique = BTreeSet::from([Address::ZERO, sender, contract, root_recipient]);
        if unique.len() != 4 {
            return Err("Root fixture address collision".into());
        }
        for ordinal in 1..=10 {
            let mut precompile = [0; 20];
            precompile[19] = ordinal;
            if !unique.insert(Address::from(precompile)) {
                return Err("Root fixture collides with a Cancun precompile".into());
            }
        }
        let mut wallets = Vec::with_capacity(transfers);
        for index in 0..transfers {
            // These deterministic public development scalars must never hold real assets.
            let signer = PrivateKeySigner::from_bytes(&B256::from(U256::from(index + 2)))
                .map_err(|_| "Cannot derive public fixture wallet")?;
            let mut recipient = [0x80; 20];
            recipient[12..].copy_from_slice(&(index as u64).to_be_bytes());
            let recipient = Address::from(recipient);
            if !unique.insert(signer.address()) || !unique.insert(recipient) {
                return Err("Development wallet/recipient address collision".into());
            }
            genesis.accounts.push(GenesisAccount {
                address: signer.address(),
                balance: U256::from(WALLET_BALANCE),
            });
            wallets.push((signer, recipient, U256::from(1_000 + index)));
        }
        genesis.validate()?;
        let transfer_intents: Vec<_> = wallets
            .iter()
            .map(|(signer, to, value)| {
                json!({"sender":signer.address(),"nonce":0,"to":to,"value":value,
                "gas_limit":21000,"gas_price":1,"input_keccak":keccak256([])})
            })
            .collect();
        // This complete unsigned intent is durable before any signing call.
        write_json(
            &root.join("unsigned-intents.json"),
            &json!({
                "schema":1,"scope":"isolated-P4-development-correctness",
                "total_transactions":total,"setup_transactions":0,"genesis":genesis,
                "wallet_transfers":transfer_intents,
                "root_transactions":[
                    {"nonce":0,"to":root_recipient,"value":1000,"gas_limit":21000,
                        "gas_price":1,"input_keccak":keccak256([])},
                    {"nonce":1,"to":null,"value":0,"gas_limit":300000,
                        "max_fee":10,"priority_fee":3,
                        "input_keccak":keccak256(development::contract_init())},
                    {"nonce":2,"to":contract,"value":0,"gas_limit":100000,
                        "max_fee":10,"priority_fee":5,
                        "input_keccak":keccak256(development::contract_input(1,None))},
                    {"nonce":3,"to":contract,"value":77,"gas_limit":100000,
                        "max_fee":10,"priority_fee":1,
                        "input_keccak":keccak256(development::contract_input(2,None))}
                ]
            }),
        )?;
        write_json(&root.join("genesis.json"), &genesis)?;
        Ok(Self {
            total,
            genesis,
            contract,
            root_recipient,
            wallets,
        })
    }

    pub(super) fn transfers(&self) -> Result<Vec<Signed>, String> {
        self.wallets
            .iter()
            .map(|(signer, to, value)| {
                let tx = TxLegacy {
                    chain_id: Some(self.genesis.chain_id),
                    nonce: 0,
                    gas_price: 1,
                    gas_limit: 21_000,
                    to: TxKind::Call(*to),
                    value: *value,
                    input: Bytes::new(),
                };
                let signature = signer
                    .sign_hash_sync(&tx.signature_hash())
                    .map_err(|_| "Public fixture signing failed")?;
                let envelope: TxEnvelope = tx.into_signed(signature).into();
                Ok(signed(
                    envelope.encoded_2718(),
                    signer.address(),
                    Some(*to),
                    *value,
                    1,
                    true,
                ))
            })
            .collect()
    }

    pub(super) fn root_transaction(&self, step: usize) -> Result<Signed, String> {
        let (to, value, gas_price, success, raw) = match step {
            0 => (
                Some(self.root_recipient),
                U256::from(1_000),
                1,
                true,
                development::sign(
                    0,
                    Some(self.root_recipient),
                    U256::from(1_000),
                    vec![],
                    21_000,
                )?,
            ),
            1 => (
                None,
                U256::ZERO,
                3,
                true,
                development::sign_type2(
                    1,
                    None,
                    U256::ZERO,
                    development::contract_init(),
                    300_000,
                    10,
                    3,
                    Default::default(),
                )?,
            ),
            2 => (
                Some(self.contract),
                U256::ZERO,
                5,
                true,
                development::sign_type2(
                    2,
                    Some(self.contract),
                    U256::ZERO,
                    development::contract_input(1, None),
                    100_000,
                    10,
                    5,
                    Default::default(),
                )?,
            ),
            3 => (
                Some(self.contract),
                U256::from(77),
                1,
                false,
                development::sign_type2(
                    3,
                    Some(self.contract),
                    U256::from(77),
                    development::contract_input(2, None),
                    100_000,
                    10,
                    1,
                    Default::default(),
                )?,
            ),
            _ => return Err("Root fixture step is outside its four-transaction scope".into()),
        };
        Ok(signed(
            raw,
            development::address(),
            to,
            value,
            gas_price,
            success,
        ))
    }
}

fn signed(
    raw: Vec<u8>,
    sender: Address,
    to: Option<Address>,
    value: U256,
    gas_price: u128,
    success: bool,
) -> Signed {
    Signed {
        expected: Expected {
            hash: keccak256(&raw),
            sender,
            to,
            value,
            gas_price,
            success,
        },
        raw,
    }
}
