//! Simulated funding facts only; no signer, RPC, consensus or VM is exercised.
use super::super::*;
use crate::alephium::{
    FundingPin, LocalScriptApproval, OperationSpec, SpendLimits, codec, compact,
    read_node::{
        ConfirmationCounts, GenesisPin, GenesisProvenance, HeaderObservation, IdentityObservation,
        NodeVersion, OFFICIAL_TESTNET_ORIGIN, UnanchoredUtxo,
    },
};
use alloy_primitives::U256;
use secp256k1::PublicKey;
use serde_json::{Value, json};

struct TransferApproval;
impl LocalScriptApproval for TransferApproval {
    fn approved_script(
        &self,
        _: &OperationSpec,
    ) -> Result<Option<Vec<u8>>, AlephiumValidationError> {
        Ok(None)
    }
}

pub(super) struct Fixture {
    pub operation: ApprovedOperation,
    pub details: Value,
    pub creator_id: B256,
    pub creator_raw: Vec<u8>,
    pub fixed: Vec<PreviousOutput>,
    pub observation: CurrentFixedFundingObservation,
    pub latest: UnanchoredUtxo,
    pub spend: Vec<u8>,
}

fn public_point() -> [u8; 33] {
    // The public secp256k1 generator, then bounded public-point additions.
    // No private scalar, key custody or signing operation is used.
    let generator = PublicKey::from_slice(
        &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap(),
    )
    .unwrap();
    let mut point = generator;
    for _ in 0..64 {
        let encoded = point.serialize();
        if codec::owner_group(alephium_hash(&encoded), 4).unwrap() == 0 {
            return encoded;
        }
        point = point.combine(&generator).unwrap();
    }
    panic!("Bounded public group-zero fixture point unavailable")
}

pub(super) fn reference(tx_id: B256, index: u32, hint: u32) -> OutputRef {
    let mut bytes = tx_id.as_slice().to_vec();
    bytes.extend_from_slice(&index.to_be_bytes());
    OutputRef {
        hint,
        key: alephium_hash(&bytes),
    }
}

pub(super) fn build(script: Option<&[u8]>) -> Fixture {
    let key = public_point();
    let owner = alephium_hash(&key);
    let hint = codec::owner_hint(owner);
    let address = P2pkhAddress::from_hash(owner);
    let input_ref = OutputRef {
        hint,
        key: B256::repeat_byte(9),
    };
    let input = json!({"outputRef":{"hint":hint as i32,"key":hex::encode(input_ref.key)},
        "unlockScript":hex::encode([vec![0],key.to_vec()].concat())});
    let amount = U256::from(2_000_000_000_000_000_000u64);
    let mut raw = vec![0, 1];
    if let Some(script) = script {
        raw.push(1);
        raw.extend_from_slice(script);
    } else {
        raw.push(0);
    }
    // Independently written from the pinned compact source, not creator::encode:
    // gas100000, price1e11, inputcount1.
    raw.extend_from_slice(&hex::decode("800186a0c1174876e80001").unwrap());
    raw.extend_from_slice(&hint.to_be_bytes());
    raw.extend_from_slice(input_ref.key.as_slice());
    raw.push(0);
    raw.extend_from_slice(&key);
    raw.push(2);
    for _ in 0..2 {
        // U256 2 ALPH, then P2PKH tag, owner, LockTime8 and empty tokens/data.
        raw.extend_from_slice(&hex::decode("c41bc16d674ec8000000").unwrap());
        raw.extend_from_slice(owner.as_slice());
        raw.extend_from_slice(&[0; 10]);
    }
    let id = alephium_hash(&raw);
    let mut fixed = Vec::new();
    let mut json_outputs = Vec::new();
    for index in 0..2 {
        let output_ref = reference(id, index, hint);
        let lock = [vec![0], owner.as_slice().to_vec()].concat();
        fixed.push(PreviousOutput {
            reference: output_ref,
            amount,
            locking_script: lock,
            lock_time_ms: 0,
            tokens: vec![],
            additional_data: vec![],
        });
        json_outputs.push(json!({"hint":hint as i32,"key":hex::encode(output_ref.key),
            "attoAlphAmount":amount.to_string(),"address":address.as_str(),"tokens":[],
            "lockTime":0,"message":""}));
    }
    let mut unsigned = json!({"txId":hex::encode(id),"version":0,"networkId":1,
        "gasAmount":100000,"gasPrice":"100000000000","inputs":[input],
        "fixedOutputs":json_outputs});
    if let Some(script) = script {
        unsigned["scriptOpt"] = json!(hex::encode(script));
    }
    let details = json!({"unsigned":unsigned,"scriptExecutionOk":true,
        "contractInputs":[],"generatedOutputs":[],"inputSignatures":[],"scriptSignatures":[]});
    let confirmations = ConfirmationCounts {
        chain: 3,
        from_group: 3,
        to_group: 3,
    };
    let policy = CurrentFundingPolicy {
        minimum_confirmations: confirmations,
        maximum_references: 8,
        maximum_creators: 8,
    };
    let genesis = GenesisPin {
        hash: B256::repeat_byte(5),
        provenance: GenesisProvenance::Independent,
    };
    let source_id = policy.source_id(OFFICIAL_TESTNET_ORIGIN, genesis).unwrap();
    let pin = FundingPin {
        model: FundingModel::CanonicalFixedCurrentV1,
        source_id,
        network_id: 1,
        network_genesis_id: B256::repeat_byte(5),
        group: 0,
        group_count: 4,
        head_hash: B256::repeat_byte(6),
        head_height: 20,
        timestamp_ms: 10_000,
    };
    let fee = U256::from(10_000_000_000_000_000u64);
    let operation = crate::alephium::approve_operation(
        OperationSpec {
            intent_id: B256::repeat_byte(1),
            operation_id: B256::repeat_byte(2),
            publication_scope: B256::repeat_byte(3),
            source_artifact_sha256: B256::repeat_byte(7),
            script_blake2b256: None,
            caller_public_key: key,
            funding: pin.clone(),
            limits: SpendLimits {
                min_gas_amount: 20_000,
                max_gas_amount: 100_000,
                max_gas_price: U256::from(100_000_000_000u64),
                max_fee: fee,
                contract_deposit: U256::ZERO,
                max_total_debit: fee,
                minimum_change: U256::from(1_000_000_000_000_000u64),
            },
        },
        &TransferApproval,
    )
    .unwrap();
    let header = HeaderObservation {
        identity: IdentityObservation {
            source_id: pin.source_id,
            origin: OFFICIAL_TESTNET_ORIGIN.into(),
            version: NodeVersion::V4_7_1,
            network_id: 1,
            groups: 4,
            group_num_per_broker: 4,
            num_zeros_at_least_in_hash: 0,
            chain_0_0_genesis: GenesisPin {
                hash: pin.network_genesis_id,
                provenance: GenesisProvenance::Independent,
            },
        },
        header: ChainHeader {
            hash: pin.head_hash,
            height: pin.head_height,
            timestamp_ms: pin.timestamp_ms,
            dependencies: [B256::repeat_byte(8); 7],
        },
    };
    let selected = fixed[1].clone();
    let observation = CurrentFixedFundingObservation {
        funding: FundingObservation {
            pin,
            outputs: vec![selected.clone()],
        },
        policy,
        provenance: vec![FixedOutputProvenance {
            reference: selected.reference,
            creator_transaction_id: id,
            fixed_output_index: 1,
            creator_block_height: 5,
            inclusion: InclusionStatus {
                block_hash: B256::repeat_byte(10),
                transaction_index: 0,
                confirmations,
            },
        }],
        before: header.clone(),
        after: header,
    };
    let latest = UnanchoredUtxo {
        reference: selected.reference,
        amount,
        tokens: vec![],
        lock_time_ms: Some(0),
        additional_data: Some(vec![]),
    };
    let mut spend = hex::decode("000100800186a0c1174876e80001").unwrap();
    spend.extend_from_slice(&hint.to_be_bytes());
    spend.extend_from_slice(selected.reference.key.as_slice());
    spend.push(0);
    spend.extend_from_slice(&key);
    spend.push(1);
    compact::put_amount(&mut spend, amount - fee);
    spend.push(0);
    spend.extend_from_slice(owner.as_slice());
    spend.extend_from_slice(&[0; 10]);
    Fixture {
        operation,
        details,
        creator_id: id,
        creator_raw: raw,
        fixed,
        observation,
        latest,
        spend,
    }
}
