//! Offline DA preparation for the existing proof format; no settlement authority.
pub mod da;
pub mod settlement;

#[allow(dead_code)]
mod inputs;
type HostResult<T> = Result<T, &'static str>;
