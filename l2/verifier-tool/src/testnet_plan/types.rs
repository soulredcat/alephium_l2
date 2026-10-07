//! Private offline inputs. No signing, funding observation or network authority.
use super::artifacts::Hash;
use num_bigint::BigUint;
use serde_json::{Value, json};

pub(crate) struct Actor {
    pub public_key: [u8; 33],
    pub canonical_source: Hash,
}

pub(crate) struct Policy {
    pub l1_genesis: Hash,
    pub l2_chain_id: u64,
    pub l2_genesis: Hash,
    pub execution_profile: Hash,
    pub approved_image: Hash,
    pub program_sha256: Hash,
    pub genesis_checkpoint: Vec<u8>,
    pub genesis_checkpoint_sha256: Hash,
    pub genesis_head: [u8; 80],
    pub capacity: [u64; 3],
    pub transport_limits: [u8; 32],
    pub max_future_seconds: u64,
    pub confirmations: u64,
    pub minimum_contract_deposit: BigUint,
}

#[derive(Clone)]
pub(crate) struct OperationLimit {
    pub gas_amount_max: u32,
    pub gas_price_max: BigUint,
    pub fee_max: BigUint,
    pub deposit: BigUint,
    pub debit_max: BigUint,
    pub request_bytes_max: usize,
    pub response_bytes_max: usize,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
}

pub(crate) struct TotalLimit {
    pub fee_max: BigUint,
    pub deposit_max: BigUint,
    pub debit_max: BigUint,
}

impl OperationLimit {
    pub fn validate(&self, required_deposit: &BigUint) -> Result<(), String> {
        for value in [
            &self.gas_price_max,
            &self.fee_max,
            &self.deposit,
            &self.debit_max,
        ] {
            if value.bits() > 256 {
                return Err("Operation amount exceeds U256".into());
            }
        }
        if self.gas_amount_max < 20_000
            || self.gas_amount_max > 5_000_000
            || self.gas_price_max < BigUint::from(100_000_000_000_u64)
            || self.gas_price_max >= BigUint::from(10_u8).pow(27)
            || self.fee_max == BigUint::from(0_u8)
            || self.fee_max > BigUint::from(self.gas_amount_max) * &self.gas_price_max
            || self.deposit != *required_deposit
            || self.debit_max < &self.fee_max + &self.deposit
            || !(1..=1_048_576).contains(&self.request_bytes_max)
            || !(1..=1_048_576).contains(&self.response_bytes_max)
            || self.connect_timeout_ms == 0
            || self.request_timeout_ms == 0
        {
            return Err("Operation limits or exact deposit are inconsistent".into());
        }
        Ok(())
    }

    pub fn value(&self) -> Value {
        json!({"gasAmountMax": self.gas_amount_max,
            "gasPriceMaxAtto": self.gas_price_max.to_string(),
            "feeMaxAtto": self.fee_max.to_string(), "depositAtto": self.deposit.to_string(),
            "totalDebitMaxAtto": self.debit_max.to_string(),
            "requestBytesMax": self.request_bytes_max, "responseBytesMax": self.response_bytes_max,
            "connectTimeoutMs": self.connect_timeout_ms, "requestTimeoutMs": self.request_timeout_ms,
            "gasMeasured": false, "retries": 0})
    }
}

pub(crate) struct ScriptDraft {
    pub(super) kind: &'static str,
    pub(super) batch: Option<u8>,
    pub(super) source: String,
    pub(super) source_sha256: Hash,
    pub(super) argument_sha256: Hash,
    pub(super) expected_effect: Value,
    pub(super) expected_effect_sha256: Hash,
    pub(super) operation_policy_sha256: Hash,
    pub(super) limits: OperationLimit,
}

impl ScriptDraft {
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    pub fn batch(&self) -> Option<u8> {
        self.batch
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn source_sha256(&self) -> Hash {
        self.source_sha256
    }
    pub fn operation_policy_sha256(&self) -> Hash {
        self.operation_policy_sha256
    }
}

pub(crate) struct CompiledScript {
    pub(super) bytes: Vec<u8>,
    pub(super) artifact_sha256: Hash,
    pub(super) source_sha256: Hash,
    pub(super) script_sha256: Hash,
    pub(super) script_blake2b256: Hash,
}

pub(crate) struct ReviewedScriptPins {
    pub artifact_sha256: Hash,
    pub source_sha256: Hash,
    pub script_sha256: Hash,
    pub compiler_jar_sha256: Hash,
}

impl CompiledScript {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn artifact_sha256(&self) -> Hash {
        self.artifact_sha256
    }
    pub fn script_sha256(&self) -> Hash {
        self.script_sha256
    }
    pub fn script_blake2b256(&self) -> Hash {
        self.script_blake2b256
    }
    /// Pins must come from the separately reviewed pinned compiler output.
    /// A builder-returned script digest cannot approve its own bytes.
    pub fn from_reviewed_bytes(
        draft: &ScriptDraft,
        bytes: Vec<u8>,
        pins: &ReviewedScriptPins,
    ) -> Result<Self, String> {
        let digest = super::literal::sha(&bytes);
        if bytes.is_empty()
            || bytes.len() > 32768
            || digest != pins.script_sha256
            || pins.source_sha256 != draft.source_sha256
            || [
                pins.artifact_sha256,
                pins.source_sha256,
                pins.script_sha256,
                pins.compiler_jar_sha256,
            ]
            .contains(&[0; 32])
            || hex::encode(pins.compiler_jar_sha256) != crate::compiler::JAR_SHA256
        {
            return Err("Compiled script differs from its independent reviewed pin".into());
        }
        Ok(Self {
            script_blake2b256: super::literal::blake(&bytes),
            bytes,
            artifact_sha256: pins.artifact_sha256,
            source_sha256: pins.source_sha256,
            script_sha256: digest,
        })
    }
}

pub(crate) struct Deployment {
    pub(super) kind: &'static str,
    pub(super) contract_id: Hash,
    pub(super) tx_id: Hash,
    pub(super) unsigned_sha256: Hash,
    pub(super) script_sha256: Hash,
    pub(super) creation_output_index: u32,
    pub(super) group: u8,
    pub(super) artifact_sha256: Hash,
    pub(super) caller_public_key_sha256: Hash,
    pub(super) funding_head: Hash,
    pub(super) funding_source: Hash,
    pub(super) publication_scope: Hash,
    pub(super) expected_code_hash: Hash,
    pub(super) reserved_input_keys: Vec<Hash>,
}

impl Deployment {
    pub fn contract_id(&self) -> Hash {
        self.contract_id
    }
    pub fn tx_id(&self) -> Hash {
        self.tx_id
    }
}
