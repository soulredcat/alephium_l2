//! Offline DA preparation for the existing proof format; no settlement authority.
pub mod da;

#[allow(dead_code)]
mod inputs;
type HostResult<T> = Result<T, &'static str>;
