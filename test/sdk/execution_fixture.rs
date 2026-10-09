//! Public synthetic pre-correlated data; no VM, signature or consensus claim.
use super::*;
use crate::alephium::{alephium_hash, codec, publisher_address_from_public_key};
use serde_json::{Value, json};

pub(super) const SCRIPT: &[u8] = &[1, 1, 0, 0, 0, 0];

pub(super) fn output_key(tx_id: B256, index: u32) -> B256 {
    let mut preimage = tx_id.as_slice().to_vec();
    preimage.extend_from_slice(&(index as i32).to_be_bytes());
    alephium_hash(&preimage)
}

fn public_owner_zero() -> [u8; 33] {
    // Standard public generator; no SecretKey or signing is used.
    let generator = secp256k1::PublicKey::from_slice(
        &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap(),
    )
    .unwrap();
    let mut point = generator;
    for _ in 0..128 {
        let key = point.serialize();
        if publisher_address_from_public_key(&key).unwrap().group() == 0 {
            return key;
        }
        point = point.combine(&generator).unwrap();
    }
    panic!("Public fixture group selection failed");
}

pub(super) fn build() -> (TransactionDetailsObservation, Vec<u8>) {
    let key = public_owner_zero();
    let owner = publisher_address_from_public_key(&key).unwrap();
    let hint = codec::owner_hint(owner.hash());
    let input_key = B256::repeat_byte(11);
    // Source-derived native compact literals: gas100000, price1e11, fixedALPH2.
    // This golden does not call compact::put_* or execution_unsigned.
    let mut raw = vec![0, 1, 1];
    raw.extend_from_slice(SCRIPT);
    raw.extend_from_slice(&hex::decode("800186a0c1174876e80001").unwrap());
    raw.extend_from_slice(&hint.to_be_bytes());
    raw.extend_from_slice(input_key.as_slice());
    raw.push(0);
    raw.extend_from_slice(&key);
    raw.extend_from_slice(&hex::decode("01c41bc16d674ec8000000").unwrap());
    raw.extend_from_slice(owner.hash().as_slice());
    raw.extend_from_slice(&[0; 10]);
    let tx_id = alephium_hash(&raw);
    let mut cid = output_key(tx_id, 1).0;
    cid[31] = 0;
    let contract = ContractAddress::from_id(B256::from(cid)).unwrap();
    let mut unlock = vec![0];
    unlock.extend_from_slice(&key);
    let details = json!({"unsigned":{"txId":hex::encode(tx_id),"version":0,"networkId":1,
        "scriptOpt":hex::encode(SCRIPT),"gasAmount":100000,"gasPrice":"100000000000",
        "inputs":[{"outputRef":{"hint":hint as i32,"key":hex::encode(input_key)},"unlockScript":hex::encode(unlock)}],
        "fixedOutputs":[{"hint":hint as i32,"key":hex::encode(output_key(tx_id,0)),
            "attoAlphAmount":"2000000000000000000","address":owner.as_str(),"tokens":[],"lockTime":0,"message":""}]},
        "scriptExecutionOk":true,"contractInputs":[],
        "generatedOutputs":[{"type":"ContractOutput","hint":(codec::owner_hint(contract.id()) & !1) as i32,
            "key":hex::encode(output_key(tx_id,1)),"attoAlphAmount":"100000000000000000","address":contract.as_str(),"tokens":[]},
            {"type":"AssetOutput","hint":hint as i32,"key":hex::encode(output_key(tx_id,2)),
            "attoAlphAmount":"1000000000000000","address":owner.as_str(),"tokens":[],"lockTime":0,"message":""}],
        "inputSignatures":["00".repeat(64)],"scriptSignatures":[]});
    let inclusion = InclusionStatus {
        block_hash: B256::repeat_byte(22),
        transaction_index: 0,
        confirmations: ConfirmationCounts {
            chain: 6,
            from_group: 6,
            to_group: 6,
        },
    };
    let header = ChainHeader {
        hash: inclusion.block_hash,
        height: 20,
        timestamp_ms: 10000,
        dependencies: [B256::repeat_byte(21); 7],
    };
    let identity = IdentityObservation {
        source_id: B256::repeat_byte(9),
        origin: OFFICIAL_TESTNET_ORIGIN.into(),
        version: NodeVersion::V4_7_1,
        network_id: 1,
        groups: 4,
        group_num_per_broker: 4,
        num_zeros_at_least_in_hash: 18,
        chain_0_0_genesis: GenesisPin {
            hash: B256::repeat_byte(8),
            provenance: GenesisProvenance::Independent,
        },
    };
    (
        TransactionDetailsObservation {
            observation: TransactionObservation {
                identity,
                transaction_id: tx_id,
                outcome: TransactionOutcome::ScriptSucceeded { inclusion, header },
            },
            retained_details: Some(details),
        },
        raw,
    )
}

pub(super) fn mutate(mutator: impl FnOnce(&mut Value)) -> (TransactionDetailsObservation, Vec<u8>) {
    let (mut observed, raw) = build();
    mutator(observed.retained_details.as_mut().unwrap());
    (observed, raw)
}
