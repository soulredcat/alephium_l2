//! HTTP resource policy is local to a server, independent of chain capacity.
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RpcLimits {
    pub request_inflight: usize,
    pub request_bytes: usize,
    pub read_inflight: usize,
    pub simulation_inflight: usize,
    pub batch_calls: usize,
    /// Budget for dispatching later batch members. One profile-bounded member
    /// and error/ID metadata can exceed this; it is not a hard HTTP byte cap.
    pub response_bytes: usize,
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            request_inflight: 32,
            request_bytes: 1024 * 1024,
            read_inflight: 32,
            simulation_inflight: 4,
            batch_calls: 100,
            response_bytes: 4 * 1024 * 1024,
        }
    }
}

impl RpcLimits {
    pub fn validate(self) -> Result<(), String> {
        for (name, value) in [
            ("request_inflight", self.request_inflight),
            ("read_inflight", self.read_inflight),
            ("simulation_inflight", self.simulation_inflight),
        ] {
            if value == 0 || value > Semaphore::MAX_PERMITS {
                return Err(format!(
                    "RPC {name} must be positive and fit the semaphore representation"
                ));
            }
        }
        for (name, value) in [
            ("request_bytes", self.request_bytes),
            ("response_bytes", self.response_bytes),
            ("batch_calls", self.batch_calls),
        ] {
            if value == 0 || value > isize::MAX as usize {
                return Err(format!(
                    "RPC {name} must be positive and fit the allocation representation"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RpcLimits;
    use tokio::sync::Semaphore;

    #[test]
    fn limits_accept_operator_capacity_and_reject_unrepresentable_values() {
        let limits = RpcLimits {
            request_inflight: 256,
            request_bytes: 32 * 1024 * 1024,
            read_inflight: 128,
            simulation_inflight: 8,
            batch_calls: 10_000,
            response_bytes: 64 * 1024 * 1024,
        };
        assert!(limits.validate().is_ok());
        assert!(RpcLimits::default().validate().is_ok());
        assert!(
            RpcLimits {
                batch_calls: 0,
                ..limits
            }
            .validate()
            .is_err()
        );
        assert!(
            RpcLimits {
                request_bytes: usize::MAX,
                ..limits
            }
            .validate()
            .is_err()
        );
        assert!(
            RpcLimits {
                request_inflight: Semaphore::MAX_PERMITS + 1,
                ..limits
            }
            .validate()
            .is_err()
        );
    }
}
