//! Versioned private input and public output share one host/guest dispatcher.
use crate::{
    BatchTransitionBundle, BatchTransitionJournal, CheckpointTransitionBundle,
    CheckpointTransitionOutput, TransitionBundle, TransitionJournal, prove_batch_transition,
    prove_checkpoint_transition, prove_transition,
};
use serde::{Deserialize, Serialize};

/// Neither variant implements Debug: inputs retain signed envelopes.
pub enum ProofInput {
    Native(TransitionBundle),
    Batch(BatchTransitionBundle),
    Checkpoint(CheckpointTransitionBundle),
}

/// Dispatch from the explicit version without Serde's untagged content buffer:
/// that buffer cannot deserialize the receipt's exact u128 gas-price fields.
/// Each selected type still rejects unknown/duplicate fields and invalid data.
pub fn decode_input(bytes: &[u8]) -> Result<ProofInput, &'static str> {
    #[derive(Deserialize)]
    struct Version {
        schema: u32,
    }
    if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
        return Err("private transition exceeds byte bound");
    }
    if crate::is_checkpoint_wire(bytes) {
        return crate::decode_checkpoint_transition(bytes)
            .map(ProofInput::Checkpoint)
            .map_err(|_| "invalid private binary checkpoint transition");
    }
    let version: Version =
        serde_json::from_slice(bytes).map_err(|_| "invalid private transition version")?;
    match version.schema {
        1 => serde_json::from_slice(bytes)
            .map(ProofInput::Native)
            .map_err(|_| "invalid private native transition"),
        2 => serde_json::from_slice(bytes)
            .map(ProofInput::Batch)
            .map_err(|_| "invalid private batch transition"),
        3 => serde_json::from_slice(bytes)
            .map(ProofInput::Checkpoint)
            .map_err(|_| "invalid private checkpoint transition"),
        _ => Err("unsupported private transition version"),
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum ProvenTransition {
    Native(TransitionJournal),
    Batch(BatchTransitionJournal),
    Checkpoint(CheckpointTransitionOutput),
}

impl ProvenTransition {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Native(journal) => journal.encode(),
            Self::Batch(journal) => journal.encode(),
            Self::Checkpoint(output) => output.journal.encode(),
        }
    }

    pub fn checkpoint(&self) -> Option<&crate::protocol::checkpoint::ExecutionCheckpoint> {
        match self {
            Self::Checkpoint(output) => Some(&output.checkpoint),
            _ => None,
        }
    }
}

pub fn prove_input(input: &ProofInput) -> Result<ProvenTransition, String> {
    match input {
        ProofInput::Native(bundle) => prove_transition(bundle).map(ProvenTransition::Native),
        ProofInput::Batch(bundle) => prove_batch_transition(bundle).map(ProvenTransition::Batch),
        ProofInput::Checkpoint(bundle) => {
            prove_checkpoint_transition(bundle).map(ProvenTransition::Checkpoint)
        }
    }
}
