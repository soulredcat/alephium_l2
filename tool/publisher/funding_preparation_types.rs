//! Private durable self-split DATA. Deserialization grants no SDK/effect authority.
//! Caller identity is public-key data only; no secret key or wallet state exists.
use alephium_l2_sdk::alephium::{OutputRef, funding_preparation::ValidatedFundingPreparation};
use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FundingPreparationReference {
    pub hint: u32,
    pub key: B256,
}
impl FundingPreparationReference {
    pub fn native(&self) -> OutputRef {
        OutputRef {
            hint: self.hint,
            key: self.key,
        }
    }
    pub fn capture(value: OutputRef) -> Self {
        Self {
            hint: value.hint,
            key: value.key,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FundingPreparationOutput {
    pub index: u32,
    pub reference: FundingPreparationReference,
    pub amount: U256,
    pub owner_hash: B256,
    pub lock_time_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FundingPreparationImmutable {
    pub purpose_id: B256,
    pub operator_source: B256,
    pub network: u8,
    pub network_genesis_id: B256,
    pub funding_source_id: B256,
    pub caller_public_key: Vec<u8>,
    pub input_refs: Vec<FundingPreparationReference>,
    pub input_amount: U256,
    pub unsigned: Vec<u8>,
    pub transaction_id: B256,
    pub gas_amount: u32,
    pub gas_price: U256,
    pub fee: U256,
    pub outputs: Vec<FundingPreparationOutput>,
    pub minimum_confirmations: [u32; 3],
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FundingPreparationPhase {
    Planned,
    SignAttempted,
    SignAmbiguous,
    Signed,
    SubmitAttempted,
    SubmitAmbiguous,
    Submitted,
    Confirmed,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FundingPreparationInclusion {
    pub transaction_id: B256,
    pub block_hash: B256,
    pub height: u64,
    pub canonical_head: B256,
    pub observed_at_ms: u64,
    pub confirmations: [u32; 3],
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FundingPreparationRecord {
    pub schema: u32,
    pub revision: u64,
    pub immutable: FundingPreparationImmutable,
    pub phase: FundingPreparationPhase,
    pub sign_attempts: u8,
    pub submit_attempts: u8,
    pub signature: Option<Vec<u8>>,
    /// Historical canonical evidence only; never current output availability.
    pub inclusion: Option<FundingPreparationInclusion>,
}

impl FundingPreparationRecord {
    /// Capture a live sealed-source capability once. Recovery uses data-only
    /// wire auditing and controllers must revalidate funding before effects.
    pub fn planned(
        cap: &ValidatedFundingPreparation,
        minimum_confirmations: [u32; 3],
    ) -> Result<Self, FundingPreparationError> {
        if minimum_confirmations.iter().any(|minimum| *minimum < 6) {
            return Err(FundingPreparationError::InvalidData);
        }
        let spec = cap.spec();
        Ok(Self {
            schema: 1,
            revision: 1,
            immutable: FundingPreparationImmutable {
                purpose_id: spec.purpose_id,
                operator_source: spec.operator_source,
                network: 1,
                network_genesis_id: spec.network_genesis_id,
                funding_source_id: spec.funding_source_id,
                caller_public_key: spec.caller_public_key.to_vec(),
                input_refs: cap
                    .input_refs()
                    .iter()
                    .copied()
                    .map(FundingPreparationReference::capture)
                    .collect(),
                input_amount: cap.input_amount(),
                unsigned: cap.unsigned_bytes().to_vec(),
                transaction_id: cap.tx_id(),
                gas_amount: spec.gas_amount,
                gas_price: spec.gas_price,
                fee: cap.fee(),
                minimum_confirmations,
                outputs: cap
                    .outputs()
                    .iter()
                    .map(|output| FundingPreparationOutput {
                        index: output.index(),
                        reference: FundingPreparationReference::capture(output.reference()),
                        amount: output.amount(),
                        owner_hash: output.owner_hash(),
                        lock_time_ms: 0,
                    })
                    .collect(),
            },
            phase: FundingPreparationPhase::Planned,
            sign_attempts: 0,
            submit_attempts: 0,
            signature: None,
            inclusion: None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingPreparationError {
    InvalidData,
    InvalidSignature,
    InvalidTransition,
    Conflict,
    ResourceLimit,
    CorruptState,
    Storage,
}
impl std::fmt::Display for FundingPreparationError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Durable funding preparation refused: {self:?}")
    }
}
impl std::error::Error for FundingPreparationError {}
