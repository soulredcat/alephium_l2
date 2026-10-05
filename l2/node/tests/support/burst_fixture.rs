//! Public development-only identities, synchronized intent and live EVM funding.
use alephium_l2_node::{
    development,
    protocol::{CHAIN_ID, Capacity, Genesis, Receipt},
    service::NodeHandle,
};
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::json;
use std::{fs::OpenOptions, path::Path, time::Duration};

pub(super) const TRANSFER_GAS: u64 = 21_000;
pub(super) const FUNDED_BALANCE: u64 = 1_000_000;
const FUNDING_GAS: u64 = 29_000_000;
const CHUNK: usize = 500;

#[derive(Clone)]
pub(super) struct Expected {
    pub sender: Address,
    pub recipient: Address,
    pub value: U256,
    pub hash: B256,
}

pub(super) struct Plan {
    pub genesis: Genesis,
    pub contract: Address,
    signers: Vec<PrivateKeySigner>,
    recipients: Vec<Address>,
}

/// Loop over right-aligned calldata addresses and transfer 1,000,000 wei each.
/// Every CALL must succeed or the entire funding transaction reverts. This is
/// isolated fixture bytecode, never a production treasury or bridge contract.
fn funding_runtime() -> Vec<u8> {
    let mut code = vec![0x5f, 0x5b, 0x80, 0x36, 0x14, 0x60, 0, 0x57];
    code.extend([0x5f, 0x5f, 0x5f, 0x5f, 0x62, 0x0f, 0x42, 0x40]);
    // DUP6 retrieves the loop's calldata offset beneath the CALL arguments.
    code.extend([0x85, 0x35, 0x5a, 0xf1, 0x15, 0x60, 0, 0x57]);
    code.extend([0x60, 0x20, 0x01, 0x60, 1, 0x56]);
    code[6] = code.len() as u8;
    code.extend([0x5b, 0x50, 0x00]);
    code[22] = code.len() as u8;
    code.extend([0x5b, 0x5f, 0x5f, 0xfd]);
    code
}

fn funding_init() -> Vec<u8> {
    let runtime = funding_runtime();
    let size = runtime.len() as u8;
    let mut init = vec![0x60, size, 0x60, 10, 0x5f, 0x39, 0x60, size, 0x5f, 0xf3];
    init.extend(runtime);
    init
}

impl Plan {
    pub(super) fn new(directory: &Path, count: usize, capacity: Capacity) -> Result<Self, String> {
        // Public scalars 2..10001; scalar 1 is the sole funded genesis root.
        let signers: Vec<_> = (2..=count + 1)
            .map(|scalar| PrivateKeySigner::from_bytes(&B256::from(U256::from(scalar))).unwrap())
            .collect();
        let recipients: Vec<_> = (0..count)
            .map(|index| {
                let mut address = [0x80; 20];
                address[12..].copy_from_slice(&(index as u64).to_be_bytes());
                Address::from(address)
            })
            .collect();
        let mut genesis = development::genesis();
        genesis.capacity = capacity;
        genesis.validate()?;
        let root = development::address();
        let contract = root.create(0);
        let mut addresses = std::collections::BTreeSet::new();
        for address in signers
            .iter()
            .map(|signer| signer.address())
            .chain(recipients.iter().copied())
        {
            assert!(
                addresses.insert(address),
                "Fixture addresses must be distinct"
            );
            assert_ne!(address, Address::ZERO);
            assert_ne!(address, contract);
            assert_ne!(address, root);
        }
        let funding: Vec<_> = signers
            .chunks(CHUNK)
            .enumerate()
            .map(|(index, chunk)| {
                json!({"sender":development::address(),"nonce":index+1,"to":contract,
                "value":FUNDED_BALANCE*chunk.len() as u64,"gas_limit":FUNDING_GAS,
                "gas_price":1,"recipients":chunk.iter().map(|s|s.address()).collect::<Vec<_>>()})
            })
            .collect();
        let transfers: Vec<_> = signers
            .iter()
            .zip(&recipients)
            .enumerate()
            .map(|(index, (signer, to))| {
                json!({"sender":signer.address(),"to":to,"nonce":0,"value":1000+index,
                "gas_limit":TRANSFER_GAS,"gas_price":1})
            })
            .collect();
        let intents = json!({"development_only":true,"chain_id":CHAIN_ID,"genesis":genesis,
            "deployment":{"sender":development::address(),"nonce":0,"gas_limit":100_000,
                "gas_price":1,"value":0,"init_hash":keccak256(funding_init())},
            "funding":funding,"measured_transfers":transfers});
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("unsigned-intents.json"))
            .map_err(|e| e.to_string())?;
        serde_json::to_writer(&mut file, &intents).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(Self {
            genesis,
            contract,
            signers,
            recipients,
        })
    }

    pub(super) async fn fund(&self, node: &NodeHandle) -> Result<Vec<Receipt>, String> {
        let init = development::sign(0, None, U256::ZERO, funding_init(), 100_000)?;
        let deployment = setup_submit(node, init).await?;
        if deployment.contract != Some(self.contract) {
            return Err("Funding fixture deployment identity differs".into());
        }
        let deployed = node
            .view()?
            .account(self.contract)?
            .ok_or("Missing funding contract")?;
        if node.view()?.code(deployed.code_hash)? != funding_runtime() {
            return Err("Deployed funding fixture code differs".into());
        }
        let mut receipts = vec![deployment];
        for (index, chunk) in self.signers.chunks(CHUNK).enumerate() {
            let mut input = Vec::with_capacity(chunk.len() * 32);
            for signer in chunk {
                input.extend([0u8; 12]);
                input.extend(signer.address().as_slice());
            }
            let raw = development::sign(
                index as u64 + 1,
                Some(self.contract),
                U256::from(FUNDED_BALANCE) * U256::from(chunk.len()),
                input,
                FUNDING_GAS,
            )?;
            receipts.push(setup_submit(node, raw).await?);
        }
        let view = node.view()?;
        for signer in &self.signers {
            let account = view
                .account(signer.address())?
                .ok_or("Missing funded EOA")?;
            if account.balance != U256::from(FUNDED_BALANCE)
                || account.nonce != 0
                || !view.code(account.code_hash)?.is_empty()
            {
                return Err("Live EVM funding produced an invalid EOA".into());
            }
        }
        if view
            .account(self.contract)?
            .ok_or("Missing funding contract")?
            .balance
            != U256::ZERO
            || node.pending_count() != 0
        {
            return Err("Funding fixture did not fully drain its balances/intents".into());
        }
        Ok(receipts)
    }

    pub(super) fn sign(&self) -> Result<Vec<(Expected, Vec<u8>)>, String> {
        self.signers
            .iter()
            .zip(&self.recipients)
            .enumerate()
            .map(|(index, (signer, to))| {
                let value = U256::from(1000 + index);
                let tx = TxLegacy {
                    chain_id: Some(CHAIN_ID),
                    nonce: 0,
                    gas_price: 1,
                    gas_limit: TRANSFER_GAS,
                    to: TxKind::Call(*to),
                    value,
                    input: Bytes::new(),
                };
                let signature = signer
                    .sign_hash_sync(&tx.signature_hash())
                    .map_err(|_| "Fixture signing failed")?;
                let envelope: TxEnvelope = tx.into_signed(signature).into();
                let raw = envelope.encoded_2718();
                Ok((
                    Expected {
                        sender: signer.address(),
                        recipient: *to,
                        value,
                        hash: keccak256(&raw),
                    },
                    raw,
                ))
            })
            .collect()
    }
}

pub(super) async fn receipt(node: &NodeHandle, hash: B256) -> Result<Receipt, String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut checked_head = None;
        loop {
            if node.failure().is_some() {
                return Err("Producer failed during receipt observation".into());
            }
            let view = node.view()?;
            // A missing committed receipt cannot appear at the same published
            // head. Avoid repeated database misses while the engine works.
            if checked_head != Some(view.head.commit_id) {
                checked_head = Some(view.head.commit_id);
                if let Some(receipt) = view.receipt(hash)? {
                    return Ok(receipt);
                }
            }
            drop(view);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "Receipt safety timeout".to_string())?
}

async fn setup_submit(node: &NodeHandle, raw: Vec<u8>) -> Result<Receipt, String> {
    let hash = keccak256(&raw);
    let (status, parent) = node.submit_with_head(raw).await?;
    if status.status != "durably_accepted" || status.hash != hash {
        return Err("Setup transaction lacked a durable admission ACK".into());
    }
    let receipt = receipt(node, hash).await?;
    if !receipt.success || receipt.block_height != parent.height + 1 {
        return Err("Funding transaction failed or missed its original next block".into());
    }
    Ok(receipt)
}
