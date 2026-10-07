//! Bounded workload selection and the independent verification-worker factor.
use alephium_l2_node::config::VerificationBackend;
use alephium_l2_node::protocol::Capacity;

/// One explicit development profile for every size; never chosen by count.
pub(super) fn capacity() -> Capacity {
    Capacity {
        block_gas: 3_000_000_000,
        block_bytes: 32 * 1024 * 1024,
        max_pending: 100_000,
    }
}

pub(super) fn count() -> Result<usize, String> {
    let count = match std::env::var("L2_BURST_TRANSFERS") {
        Ok(value) => value
            .parse()
            .map_err(|_| "Invalid burst transaction count")?,
        Err(std::env::VarError::NotPresent) => 100,
        Err(_) => return Err("Invalid burst transaction count encoding".into()),
    };
    if ![100, 1000, 10_000, 100_000].contains(&count) {
        return Err("Burst transaction count must be 100, 1000, 10000 or 100000".into());
    }
    Ok(count)
}

pub(super) fn worker_factor() -> Result<usize, String> {
    let factor = match std::env::var("L2_VERIFY_WORKERS_PER_CPU") {
        Ok(value) => value
            .parse()
            .map_err(|_| "Invalid verification-worker factor")?,
        Err(std::env::VarError::NotPresent) => 1,
        Err(_) => return Err("Invalid verification-worker factor encoding".into()),
    };
    if factor == 0 {
        return Err("Verification-worker factor must be positive".into());
    }
    Ok(factor)
}

pub(super) fn backend() -> Result<VerificationBackend, String> {
    match std::env::var("L2_VERIFY_BACKEND") {
        Ok(value) => VerificationBackend::parse(&value),
        Err(std::env::VarError::NotPresent) => Ok(VerificationBackend::Cuda),
        Err(_) => Err("Invalid verification backend encoding".into()),
    }
}

pub(super) fn gpu_device() -> Result<usize, String> {
    match std::env::var("L2_GPU_DEVICE") {
        Ok(value) => value.parse().map_err(|_| "Invalid GPU device index".into()),
        Err(std::env::VarError::NotPresent) => Ok(0),
        Err(_) => Err("Invalid GPU device index encoding".into()),
    }
}

pub(super) fn client_runtime() -> Result<(tokio::runtime::Runtime, usize), String> {
    let workers = std::thread::available_parallelism()
        .map_err(|e| e.to_string())?
        .get()
        .saturating_sub(1)
        .max(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    Ok((runtime, workers))
}
