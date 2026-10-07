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
        if self.is_default() {
            1
        } else if self.uses_extended_runtime_codec() {
            3
        } else {
            2
        }
    }

    /// Development records may grow with explicitly selected chain capacity.
    /// This is a format ceiling, not a guarantee every contract workload fits.
    pub fn runtime_record_bytes(self) -> Result<usize, String> {
        self.derived_bytes(512, true)
    }

    /// Room for sender/recipient account state without allocating that room.
    /// Actual state growth remains measured and refused before durable writes.
    pub fn runtime_checkpoint_bytes(self) -> Result<usize, String> {
        self.derived_bytes(256, false)
    }

    /// Preserve the existing eight MiB producer profile until an explicitly
    /// larger development capacity requires the extended runtime codec.
    pub fn producer_checkpoint_bytes(self) -> Result<usize, String> {
        let limit = self.runtime_checkpoint_bytes()?;
        Ok(if limit > MAX_RECORD {
            limit
        } else {
            8 * 1024 * 1024
        })
    }

    pub fn ensure_proof_transport(self) -> Result<(), String> {
        self.validate()?;
        if self.uses_extended_runtime_codec() {
            return Err("Expanded development runtime capacity is not supported by the fixed proof transport profile".into());
        }
        Ok(())
    }

    /// Extended development codecs require fresh identity and are outside the
    /// fixed proof transport profile. Default/small custom profiles stay exact.
    pub fn uses_extended_runtime_codec(self) -> bool {
        let record = self.max_pending as u128 * 512 + self.block_bytes as u128 + 1_048_576;
        let checkpoint = self.max_pending as u128 * 256 + 1_048_576;
        record > MAX_RECORD as u128 || checkpoint > MAX_RECORD as u128
    }

    fn derived_bytes(self, per_intent: u64, include_payload: bool) -> Result<usize, String> {
        let count = u64::try_from(self.max_pending).map_err(|_| "Capacity count overflow")?;
        let mut bytes = count
            .checked_mul(per_intent)
            .and_then(|bytes| bytes.checked_add(1_048_576))
            .ok_or("Runtime capacity byte derivation overflow")?;
        if include_payload {
            bytes = bytes
                .checked_add(u64::try_from(self.block_bytes).map_err(|_| "Capacity byte overflow")?)
                .ok_or("Runtime record capacity overflow")?;
        }
        // Fjall's journal value lengths and canonical field/counts are u32.
        // Clipping this heuristic preserves numeric capacity knobs; actual
        // oversized records still fail before persistence, without truncation.
        usize::try_from(bytes.max(MAX_RECORD as u64).min(u32::MAX as u64))
            .map_err(|_| "Runtime capacity is not representable on this host".into())
    }

    pub fn validate(self) -> Result<(), String> {
        if self.block_gas < 21_000 {
            return Err("Block gas capacity must fit at least one intrinsic transaction".into());
        }
        if self.block_bytes < 4_096 || u32::try_from(self.block_bytes).is_err() {
            return Err("Block payload capacity must fit a positive u32 byte length and the 4096-byte minimum".into());
        }
        if self.max_pending == 0 || u32::try_from(self.max_pending).is_err() {
            return Err(
                "Pending capacity must be a positive u32 count for the current block format".into(),
            );
        }
        self.runtime_record_bytes()?;
        self.runtime_checkpoint_bytes()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_profiles_keep_exact_format_and_producer_limits() {
        for capacity in [
            Capacity::default(),
            Capacity {
                block_gas: 300_000_000,
                max_pending: 10_000,
                ..Capacity::default()
            },
        ] {
            capacity.validate().unwrap();
            assert_eq!(capacity.runtime_record_bytes().unwrap(), MAX_RECORD);
            assert_eq!(capacity.runtime_checkpoint_bytes().unwrap(), MAX_RECORD);
            assert_eq!(
                capacity.producer_checkpoint_bytes().unwrap(),
                8 * 1024 * 1024
            );
            assert!(!capacity.uses_extended_runtime_codec());
            assert!(capacity.ensure_proof_transport().is_ok());
        }
        assert_eq!(Capacity::default().checkpoint_schema(), 1);
    }

    #[test]
    fn expanded_runtime_has_bounded_room_and_refuses_proof_transport() {
        let capacity = Capacity {
            block_gas: 3_000_000_000,
            block_bytes: 32 * 1024 * 1024,
            max_pending: 100_000,
        };
        capacity.validate().unwrap();
        assert_eq!(capacity.checkpoint_schema(), 3);
        assert_eq!(capacity.runtime_record_bytes().unwrap(), 85_803_008);
        assert!(capacity.runtime_record_bytes().unwrap() > 38_500_263);
        assert!(capacity.runtime_checkpoint_bytes().unwrap() >= 21_010_823);
        assert_eq!(
            capacity.producer_checkpoint_bytes().unwrap(),
            capacity.runtime_checkpoint_bytes().unwrap()
        );
        assert!(capacity.ensure_proof_transport().is_err());
    }

    #[test]
    fn large_numeric_knobs_keep_true_format_bound_without_allocating() {
        let capacity = Capacity {
            block_gas: 210_000_000_000,
            block_bytes: 1_500_000_000,
            max_pending: 10_000_000,
        };
        capacity.validate().unwrap();
        assert_eq!(capacity.runtime_record_bytes().unwrap(), u32::MAX as usize);
        assert_eq!(capacity.runtime_checkpoint_bytes().unwrap(), 2_561_048_576);
        let invalid = Capacity {
            max_pending: 0,
            ..capacity
        };
        assert!(invalid.validate().is_err());
        #[cfg(target_pointer_width = "64")]
        assert!(
            Capacity {
                max_pending: usize::MAX,
                ..capacity
            }
            .runtime_record_bytes()
            .is_err()
        );
    }
}
