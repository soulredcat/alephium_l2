//! Private replay-derived inputs and a safe report for transition proof preparation.
use crate::protocol::checkpoint::ExecutionCheckpoint;
use crate::protocol::{BlockContext, Genesis, Head, Receipt};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionContext {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
}

impl From<BlockContext> for TransitionContext {
    fn from(context: BlockContext) -> Self {
        Self {
            number: context.number,
            timestamp: context.timestamp,
            gas_limit: context.gas_limit,
        }
    }
}

/// Contains a retained signed envelope. Never log or print this value.
/// Expected output is a replay oracle, not an accepted proof or state root.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionBundle {
    pub schema: u32,
    pub rpc_profile: String,
    pub execution_engine: String,
    pub genesis: Genesis,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub parent: Head,
    pub head: Head,
    pub context: TransitionContext,
    pub transaction_hash: B256,
    pub raw_envelope_hex: String,
    pub expected_receipt: Receipt,
    pub expected_state_digest: B256,
    pub semantic_replay_verified: bool,
    pub guest_proof_generated: bool,
    pub settlement_verified: bool,
}

/// Safe for CLI output: no signing material or signed payloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionReport {
    pub schema: u32,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub parent: Head,
    pub head: Head,
    pub transaction_hash: B256,
    pub expected_state_digest: B256,
    pub work_directory: PathBuf,
    pub bundle_path: PathBuf,
    pub bundle_sha256: B256,
    pub bundle_bytes: usize,
    pub blocks: u64,
    pub executed_transactions: u64,
    pub rejected_intents: u64,
    pub pending_count: usize,
    pub semantic_replay_verified: bool,
    pub guest_proof_generated: bool,
    pub settlement_verified: bool,
}

/// Initial full-history witness profile. This is not an unbounded mainnet limit.
pub const MAX_TRANSITION_BLOCKS: u64 = 256;

/// Explicit target domain; export never guesses a network or contract identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementDomain {
    pub l1_network: u8,
    pub l1_genesis_id: B256,
    pub settlement_contract_id: B256,
}

impl SettlementDomain {
    pub fn validate(&self) -> Result<(), String> {
        if self.l1_genesis_id == B256::ZERO || self.settlement_contract_id == B256::ZERO {
            return Err(
                "Settlement domain requires nonzero genesis and contract identities".into(),
            );
        }
        Ok(())
    }
}

/// Private signed input; never derive Debug or log this value.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionInput {
    pub transaction_hash: B256,
    pub raw_envelope_hex: String,
    pub expected_receipt: Receipt,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionBlock {
    pub parent: Head,
    pub head: Head,
    pub context: TransitionContext,
    pub transactions: Vec<TransitionInput>,
}

/// Complete genesis and ordered execution history authenticate the witness.
/// The proof derives the selected batch's old state at `batch_start - 1`.
/// This bounded full witness is not a sparse state witness or settlement proof.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchTransitionBundle {
    pub schema: u32,
    pub rpc_profile: String,
    pub execution_engine: String,
    pub genesis: Genesis,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub domain: SettlementDomain,
    pub batch_start: u64,
    pub parent: Head,
    pub head: Head,
    pub blocks: Vec<TransitionBlock>,
    pub expected_state_digest: B256,
    pub semantic_replay_verified: bool,
    pub guest_proof_generated: bool,
    pub settlement_verified: bool,
}

/// Safe export metadata; excludes signed envelopes and all signing material.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchTransitionReport {
    pub schema: u32,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub domain: SettlementDomain,
    pub batch_start: u64,
    pub parent: Head,
    pub head: Head,
    pub transaction_hashes: Vec<B256>,
    pub expected_state_digest: B256,
    pub work_directory: PathBuf,
    pub bundle_path: PathBuf,
    pub bundle_sha256: B256,
    pub bundle_bytes: usize,
    pub blocks: u64,
    pub executed_transactions: u64,
    pub rejected_intents: u64,
    pub pending_count: usize,
    pub semantic_replay_verified: bool,
    pub guest_proof_generated: bool,
    pub settlement_verified: bool,
}

/// Authenticated-parent input plus only the newly executed suffix. The guest
/// derives the old root; settlement must match it against the accepted parent.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTransitionBundle {
    pub schema: u32,
    pub rpc_profile: String,
    pub execution_engine: String,
    pub domain: SettlementDomain,
    pub checkpoint: ExecutionCheckpoint,
    pub blocks: Vec<TransitionBlock>,
    pub head: Head,
    pub expected_state_digest: B256,
}

/// Safe checkpoint export metadata; canonical checkpoint hash is an integrity
/// record, not proof acceptance or a settlement root.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTransitionReport {
    pub schema: u32,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub domain: SettlementDomain,
    pub parent: Head,
    pub head: Head,
    pub checkpoint_sha256: B256,
    pub transaction_hashes: Vec<B256>,
    pub expected_state_digest: B256,
    pub work_directory: PathBuf,
    pub bundle_path: PathBuf,
    pub bundle_sha256: B256,
    pub bundle_bytes: usize,
    pub blocks: u64,
    pub executed_transactions: u64,
    pub replayed_blocks: u64,
    pub semantic_replay_verified: bool,
    pub guest_proof_generated: bool,
    pub settlement_verified: bool,
}
