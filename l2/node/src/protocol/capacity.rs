//! A chain's explicit development execution capacity, pinned by genesis.
//! Values are operator selected; machine throughput is never inferred from them.
use super::{BLOCK_BYTES, BLOCK_GAS, MAX_PENDING, encoding::MAX_RECORD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
    pub block_gas: u64,
    pub block_bytes: usize,
    pub max_pending: usize,
}

impl Default for Capacity {
    fn default() -> Self {
        Self {
            block_gas: BLOCK_GAS,
            block_bytes: BLOCK_BYTES,
            max_pending: MAX_PENDING,
        }
    }
}

impl Capacity {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn checkpoint_schema(self) -> u32 {
        if self.is_default() { 1 } else { 2 }
    }

    pub fn validate(self) -> Result<(), String> {
        if self.block_gas < 21_000 {
            return Err("Block gas capacity must fit at least one intrinsic transaction".into());
        }
        if self.block_bytes < 4_096 || self.block_bytes > MAX_RECORD {
            return Err(format!(
                "Block payload capacity must be from 4096 to {MAX_RECORD} bytes for the current storage format"
            ));
        }
        if self.max_pending == 0 || u32::try_from(self.max_pending).is_err() {
            return Err(
                "Pending capacity must be a positive u32 count for the current block format".into(),
            );
        }
        Ok(())
    }
}
