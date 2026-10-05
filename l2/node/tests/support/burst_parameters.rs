//! Bounded workload selection and the independent verification-worker factor.
pub(super) fn count() -> Result<usize, String> {
    let count = match std::env::var("L2_BURST_TRANSFERS") {
        Ok(value) => value
            .parse()
            .map_err(|_| "Invalid burst transaction count")?,
        Err(std::env::VarError::NotPresent) => 100,
        Err(_) => return Err("Invalid burst transaction count encoding".into()),
    };
    if ![100, 1000, 10_000].contains(&count) {
        return Err("Burst transaction count must be 100, 1000 or 10000".into());
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
