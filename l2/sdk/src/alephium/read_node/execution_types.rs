//! Correlated execution facts, never script approval or an expected-effect claim.
use super::{
    ChainHeader, ContractAddress, IdentityObservation, InclusionStatus, P2pkhAddress, TokenAmount,
};
use crate::alephium::OutputRef;
use alloy_primitives::{B256, U256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecutedOutcome {
    Succeeded,
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ExecutedOutputAddress {
    Asset(P2pkhAddress),
    Contract(ContractAddress),
}

/// Data authenticated only within the configured trusted node's execution view.
/// Generated outputs are not committed by the unsigned transaction hash.
pub struct ExecutedOutput {
    pub(super) global_index: u32,
    pub(super) reference: OutputRef,
    pub(super) address: ExecutedOutputAddress,
    pub(super) amount: U256,
    pub(super) tokens: Vec<TokenAmount>,
    pub(super) lock_time_ms: Option<u64>,
    pub(super) additional_data: Option<Vec<u8>>,
}

impl ExecutedOutput {
    pub fn global_index(&self) -> u32 {
        self.global_index
    }
    pub fn reference(&self) -> OutputRef {
        self.reference
    }
    pub fn address(&self) -> &ExecutedOutputAddress {
        &self.address
    }
    pub fn group(&self) -> u8 {
        match &self.address {
            ExecutedOutputAddress::Asset(address) => address.group(),
            ExecutedOutputAddress::Contract(address) => address.group(),
        }
    }
    pub fn amount(&self) -> U256 {
        self.amount
    }
    pub fn tokens(&self) -> &[TokenAmount] {
        &self.tokens
    }
    pub fn lock_time_ms(&self) -> Option<u64> {
        self.lock_time_ms
    }
    pub fn additional_data(&self) -> Option<&[u8]> {
        self.additional_data.as_deref()
    }
}

/// Constructed only by the bounded decoder of an already correlated response.
/// No Debug/Serialize, unchecked constructor, funding or effect authority.
pub struct ExecutedTransactionEvidence {
    pub(super) identity: IdentityObservation,
    pub(super) inclusion: InclusionStatus,
    pub(super) header: ChainHeader,
    pub(super) transaction_id: B256,
    pub(super) script_hash: B256,
    pub(super) script: Vec<u8>,
    pub(super) fixed_output_count: u32,
    pub(super) outcome: ExecutedOutcome,
    pub(super) contract_inputs: Vec<OutputRef>,
    pub(super) generated_outputs: Vec<ExecutedOutput>,
}

impl ExecutedTransactionEvidence {
    pub fn identity(&self) -> &IdentityObservation {
        &self.identity
    }
    pub fn inclusion(&self) -> &InclusionStatus {
        &self.inclusion
    }
    pub fn header(&self) -> &ChainHeader {
        &self.header
    }
    pub fn transaction_id(&self) -> B256 {
        self.transaction_id
    }
    /// Native Blake2b256 of the complete serialized StatefulScript.
    pub fn script_hash(&self) -> B256 {
        self.script_hash
    }
    pub fn script_bytes(&self) -> &[u8] {
        &self.script
    }
    pub fn fixed_output_count(&self) -> u32 {
        self.fixed_output_count
    }
    pub fn outcome(&self) -> ExecutedOutcome {
        self.outcome
    }
    pub fn contract_inputs(&self) -> &[OutputRef] {
        &self.contract_inputs
    }
    pub fn generated_outputs(&self) -> &[ExecutedOutput] {
        &self.generated_outputs
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutedTransactionError {
    Bounds,
    Unconfirmed,
    Identity,
    Inclusion,
    Unsigned,
    Script,
    Profile,
    Generated,
    ContractInputs,
    Outcome,
    Signatures,
    Format,
}

impl std::fmt::Display for ExecutedTransactionError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Executed transaction evidence refused: {self:?}")
    }
}
impl std::error::Error for ExecutedTransactionError {}
