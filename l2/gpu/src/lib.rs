//! Native CUDA boundary for public signature recovery, with bounded owned buffers.
//! The caller retains canonical CPU validation and durable state ownership.
mod cuda;
mod host_staging;
pub use cuda::GpuBackend;

/// Public recovery material; never contains a private signing key.
pub struct RecoveryInput {
    pub msg_hash: [u8; 32],
    pub signature: [u8; 64],
    pub recovery_id: i32,
}

/// Device-computed recovery and Ethereum address, independently checked by caller.
#[derive(Clone, Copy)]
pub struct RecoveredKey {
    pub public_key: [u8; 65],
    pub address: [u8; 20],
}
