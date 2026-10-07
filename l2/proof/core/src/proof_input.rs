//! Versioned private input and public output share one host/guest dispatcher.
use crate::{
    BatchTransitionBundle, BatchTransitionJournal, CheckpointTransitionBundle,
    CheckpointTransitionOutput, TransitionBundle, TransitionJournal, prove_batch_transition,
    prove_checkpoint_transition, prove_transition,
};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

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
    if bytes.is_empty() || bytes.len() > crate::protocol::proof_transport::ABSOLUTE_MAX_V4_INPUT {
        return Err("private transition exceeds byte bound");
    }
    if crate::is_large_checkpoint_wire(bytes) {
        return crate::decode_large_checkpoint_transition(bytes)
            .map(ProofInput::Checkpoint)
            .map_err(|_| "invalid private binary schema-four checkpoint transition");
    }
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("legacy private transition exceeds byte bound");
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

/// Schema four consumes a bounded frame reader, avoiding an additional full
/// wire buffer. Decoded state and envelopes remain owned, not constant-memory.
/// Earlier formats retain their exact decoder and sixteen MiB input bound.
pub fn decode_input_reader<R: Read>(
    reader: &mut R,
    total_len: usize,
) -> Result<ProofInput, &'static str> {
    if total_len == 0 || total_len > crate::protocol::proof_transport::ABSOLUTE_MAX_V4_INPUT {
        return Err("private transition exceeds byte bound");
    }
    let mut prefix = [0; crate::LARGE_CHECKPOINT_WIRE_MAGIC.len()];
    let prefix_len = total_len.min(prefix.len());
    reader
        .read_exact(&mut prefix[..prefix_len])
        .map_err(|_| "truncated private transition prefix")?;
    let mut input =
        Cursor::new(&prefix[..prefix_len]).chain(reader.take((total_len - prefix_len) as u64));
    if crate::is_large_checkpoint_wire(&prefix[..prefix_len]) {
        return crate::decode_large_checkpoint_transition_reader(&mut input, total_len)
            .map(ProofInput::Checkpoint)
            .map_err(|_| "invalid private binary schema-four checkpoint transition");
    }
    if total_len > 16 * 1024 * 1024 {
        return Err("legacy private transition exceeds byte bound");
    }
    let mut bytes = vec![0; total_len];
    input
        .read_exact(&mut bytes)
        .map_err(|_| "truncated private transition")?;
    decode_input(&bytes)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_enforces_version_bounds_before_allocating_a_complete_body() {
        let mut empty = Cursor::new([]);
        assert!(decode_input_reader(&mut empty, 0).is_err());
        assert!(
            decode_input_reader(
                &mut empty,
                crate::protocol::proof_transport::ABSOLUTE_MAX_V4_INPUT + 1
            )
            .is_err()
        );
        let mut prefix = Cursor::new(b"{\"schema\":3}".as_slice());
        assert!(decode_input_reader(&mut prefix, 17 * 1024 * 1024).is_err());
        assert!(
            decode_input(b"{\"schema\":4}").is_err(),
            "schema four is canonical bounded binary, not expanded private JSON"
        );
        let mut truncated = Cursor::new(crate::LARGE_CHECKPOINT_WIRE_MAGIC);
        assert!(decode_input_reader(&mut truncated, 100).is_err());
    }
}
