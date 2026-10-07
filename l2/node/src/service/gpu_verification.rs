//! Optional real CUDA recovery, checked against the authoritative CPU result.
//! No GPU output bypasses canonical validation, state checks or durable ACK.
use super::preparation;
#[cfg(feature = "cuda")]
use crate::execution;
use crate::{
    config::{Config, VerificationBackend},
    execution::PreparedTransaction,
};
use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

#[derive(Clone, Serialize)]
pub struct GpuSnapshot {
    pub selected: &'static str,
    pub active: bool,
    pub device: Option<String>,
    pub batches: u64,
    pub verified: u64,
    pub failures: u64,
    pub cpu_oracle_checked: bool,
    pub elapsed_ns: u64,
    pub chunk_limit: usize,
}

pub(super) struct VerificationMetrics {
    selected: &'static str,
    active: AtomicBool,
    device: Option<String>,
    batches: AtomicU64,
    verified: AtomicU64,
    failures: AtomicU64,
    elapsed_ns: AtomicU64,
    chunk_limit: usize,
}

impl VerificationMetrics {
    pub(super) fn snapshot(&self) -> GpuSnapshot {
        GpuSnapshot {
            selected: self.selected,
            active: self.active.load(Ordering::Relaxed),
            device: self.device.clone(),
            batches: self.batches.load(Ordering::Relaxed),
            verified: self.verified.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            cpu_oracle_checked: true,
            elapsed_ns: self.elapsed_ns.load(Ordering::Relaxed),
            chunk_limit: self.chunk_limit,
        }
    }
}

pub(super) struct Verifier {
    pub(super) metrics: Arc<VerificationMetrics>,
    #[cfg(feature = "cuda")]
    backend: Option<alephium_l2_gpu::GpuBackend>,
}

impl Verifier {
    pub(super) fn new(config: &Config) -> Result<Self, String> {
        let selected = match config.verification_backend {
            VerificationBackend::Cpu => "cpu",
            VerificationBackend::Cuda => "cuda",
        };
        #[cfg(feature = "cuda")]
        let backend = if config.verification_backend == VerificationBackend::Cuda {
            let backend =
                std::panic::catch_unwind(|| alephium_l2_gpu::GpuBackend::new(config.gpu_device))
                    .map_err(|_| "CUDA initialization failed; no node data opened")??;
            Some(backend)
        } else {
            None
        };
        #[cfg(feature = "cuda")]
        let (device, chunk_limit) = backend.as_ref().map_or((None, 0), |backend| {
            (
                Some(backend.device_name().to_owned()),
                backend.suggested_chunk(),
            )
        });
        #[cfg(not(feature = "cuda"))]
        let (device, chunk_limit): (Option<String>, usize) = (None, 0);
        #[cfg(not(feature = "cuda"))]
        if config.verification_backend == VerificationBackend::Cuda {
            return Err("CUDA backend requires a build with --features cuda".into());
        }
        Ok(Self {
            metrics: Arc::new(VerificationMetrics {
                selected,
                active: AtomicBool::new(device.is_some()),
                device,
                chunk_limit,
                batches: AtomicU64::new(0),
                verified: AtomicU64::new(0),
                failures: AtomicU64::new(0),
                elapsed_ns: AtomicU64::new(0),
            }),
            #[cfg(feature = "cuda")]
            backend,
        })
    }

    pub(super) fn prepare(
        &mut self,
        inputs: &[&[u8]],
        chain: u64,
        budget: usize,
    ) -> Result<Vec<Result<PreparedTransaction, String>>, String> {
        #[cfg(feature = "cuda")]
        if self.backend.is_some() {
            // The CPU oracle and GPU compute independently, without a
            // collection timer or a dependency on CPU completion to launch.
            let (prepared, outcome) = std::thread::scope(|scope| {
                let cpu = scope.spawn(move || preparation::prepare_parallel(inputs, chain, budget));
                let gpu = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.run_gpu(inputs, chain)
                }));
                let prepared = cpu.join().map_err(|_| "CPU oracle worker failed")??;
                Ok::<_, String>((prepared, gpu))
            })?;
            if !matches!(&outcome, Ok(Ok(outputs)) if matches_prepared(outputs, &prepared)) {
                // The entire chunk already has authoritative CPU outcomes.
                // Disable this backend before admission consumes any result.
                self.metrics.failures.fetch_add(1, Ordering::Relaxed);
                self.metrics.active.store(false, Ordering::Relaxed);
                self.backend = None;
            } else {
                let verified = prepared.iter().filter(|input| input.is_ok()).count();
                self.metrics
                    .verified
                    .fetch_add(verified as u64, Ordering::Relaxed);
            }
            return Ok(prepared);
        }
        preparation::prepare_parallel(inputs, chain, budget)
    }

    #[cfg(feature = "cuda")]
    fn run_gpu(&mut self, inputs: &[&[u8]], chain: u64) -> Result<Vec<Option<GpuOutcome>>, String> {
        use alephium_l2_gpu::RecoveryInput;
        use std::time::Instant;
        let mut requests = Vec::new();
        let mut positions = Vec::new();
        let mut outcomes = vec![None; inputs.len()];
        for (index, raw) in inputs.iter().enumerate() {
            if let Ok(input) = execution::gpu_inputs::recovery_input(raw, chain) {
                requests.push(RecoveryInput {
                    msg_hash: input.msg_hash,
                    signature: input.signature,
                    recovery_id: input.recovery_id,
                });
                positions.push((index, input.raw_hash));
            }
        }
        let backend = self.backend.as_mut().ok_or("GPU backend unavailable")?;
        let limit = backend.suggested_chunk();
        for (requests, positions) in requests.chunks(limit).zip(positions.chunks(limit)) {
            let started = Instant::now();
            let results = backend.recover(requests)?;
            self.metrics.elapsed_ns.fetch_add(
                started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            if results.len() != positions.len() {
                return Err("GPU output count differs from input".into());
            }
            for (key, &(index, hash)) in results.into_iter().zip(positions) {
                outcomes[index] = Some(GpuOutcome { hash, key });
            }
            self.metrics.batches.fetch_add(1, Ordering::Relaxed);
        }
        Ok(outcomes)
    }
}

#[cfg(feature = "cuda")]
#[derive(Clone)]
struct GpuOutcome {
    hash: alloy_primitives::B256,
    key: Option<alephium_l2_gpu::RecoveredKey>,
}

#[cfg(feature = "cuda")]
fn matches_prepared(
    outputs: &[Option<GpuOutcome>],
    prepared: &[Result<PreparedTransaction, String>],
) -> bool {
    outputs.len() == prepared.len()
        && outputs
            .iter()
            .zip(prepared)
            .all(|(output, cpu)| match (output, cpu) {
                (Some(output), Ok(cpu)) => {
                    output.hash == cpu.info().hash
                        && matches_cpu(&[output.key], &[cpu.info().sender])
                }
                (None, Err(_)) => true,
                (Some(output), Err(_)) => output.key.is_none(),
                _ => false,
            })
}

#[cfg(feature = "cuda")]
fn matches_cpu(
    results: &[Option<alephium_l2_gpu::RecoveredKey>],
    expected: &[alloy_primitives::Address],
) -> bool {
    use alloy_primitives::{Address, keccak256};
    results.len() == expected.len()
        && results.iter().zip(expected).all(|(key, sender)| {
            key.as_ref().is_some_and(|key| {
                key.public_key[0] == 4
                    && Address::from_slice(&key.address) == *sender
                    && Address::from_slice(&keccak256(&key.public_key[1..])[12..]) == *sender
            })
        })
}

#[cfg(all(test, feature = "cuda"))]
mod tests {
    use super::*;
    use alloy_primitives::{Address, keccak256};

    #[test]
    fn output_count_invalid_point_and_sender_mismatch_fail_closed() {
        let mut public_key = [1u8; 65];
        public_key[0] = 4;
        let expected = Address::from_slice(&keccak256(&public_key[1..])[12..]);
        let mut key = alephium_l2_gpu::RecoveredKey {
            public_key,
            address: expected.into_array(),
        };
        assert!(matches_cpu(&[Some(key)], &[expected]));
        assert!(!matches_cpu(&[], &[expected]));
        assert!(!matches_cpu(&[None], &[expected]));
        assert!(!matches_cpu(&[Some(key)], &[Address::ZERO]));
        key.public_key[0] = 3;
        assert!(!matches_cpu(&[Some(key)], &[expected]));
    }
}
