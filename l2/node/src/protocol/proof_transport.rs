//! Explicit bounded development witness transport. This does not establish
//! guest feasibility, proof acceptance or settlement for the selected limits.
use super::Capacity;

pub const ABSOLUTE_MAX_V4_INPUT: usize = 128 * 1024 * 1024;
pub const V4_CHECKPOINT_FRAME_BYTES: usize = 8 * 1024 * 1024;
const HEADER_RESERVE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofLimits {
    pub checkpoint_bytes: usize,
    pub transcript_bytes: usize,
    pub input_bytes: usize,
    pub frame_bytes: usize,
}

impl ProofLimits {
    pub fn for_capacity(capacity: Capacity) -> Result<Self, String> {
        capacity.validate()?;
        let checkpoint_bytes = capacity.runtime_checkpoint_bytes()?;
        let transcript_bytes = capacity.runtime_record_bytes()?;
        let input_bytes = checkpoint_bytes
            .checked_add(transcript_bytes)
            .and_then(|size| size.checked_add(HEADER_RESERVE))
            .ok_or("large proof input limit overflow")?;
        let limits = Self {
            checkpoint_bytes,
            transcript_bytes,
            input_bytes,
            frame_bytes: V4_CHECKPOINT_FRAME_BYTES,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn validate(self) -> Result<(), String> {
        let total = self
            .checkpoint_bytes
            .checked_add(self.transcript_bytes)
            .and_then(|size| size.checked_add(HEADER_RESERVE))
            .ok_or("large proof limit overflow")?;
        if self.checkpoint_bytes == 0
            || self.transcript_bytes == 0
            || self.input_bytes != total
            || total > ABSOLUTE_MAX_V4_INPUT
            || self.frame_bytes != V4_CHECKPOINT_FRAME_BYTES
        {
            return Err("selected runtime capacity exceeds the supported bounded schema-four proof transport".into());
        }
        Ok(())
    }

    pub fn validate_for_capacity(self, capacity: Capacity) -> Result<(), String> {
        if self != Self::for_capacity(capacity)? {
            return Err(
                "proof transport limits differ from the exact capacity-derived profile".into(),
            );
        }
        Ok(())
    }

    /// Canonical binding order: checkpoint, transcript, complete input, frame.
    pub fn binding_bytes(self) -> Result<[u8; 32], String> {
        self.validate()?;
        let mut bytes = [0; 32];
        for (chunk, value) in bytes.chunks_exact_mut(8).zip([
            self.checkpoint_bytes,
            self.transcript_bytes,
            self.input_bytes,
            self.frame_bytes,
        ]) {
            chunk.copy_from_slice(
                &u64::try_from(value)
                    .map_err(|_| "proof limit encoding overflow")?
                    .to_be_bytes(),
            );
        }
        Ok(bytes)
    }
}
