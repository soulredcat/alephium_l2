//! Public execution progress only; private segment assets are never retained.

use serde::Serialize;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofErrorCategory {
    CudaOutOfMemory,
    CudaIllegalAccess,
    SessionLimit,
    Component,
    Unsupported,
    Other,
}

/// A safe hint from the returned SDK text, not a claim of an established cause.
/// The original text stays private; unknown or opaque failures remain Other.
pub fn proof_error_category(cause: &str, cuda_requested: bool) -> ProofErrorCategory {
    if contains_any(cause, &["session limit exceeded"]) {
        ProofErrorCategory::SessionLimit
    } else if contains_any(
        cause,
        &[
            "cuda_error_illegal_address",
            "cuda_error_illegal_memory_access",
        ],
    ) || cuda_requested
        && (contains_any(cause, &["illegal memory access", "illegal address"])
            || contains_code(cause, b"sppark::error #700"))
    {
        ProofErrorCategory::CudaIllegalAccess
    } else if contains_any(cause, &["cuda_error_out_of_memory"])
        || cuda_requested
            && (contains_any(cause, &["out of memory", "outofmemory"])
                || contains_code(cause, b"sppark::error #2"))
    {
        ProofErrorCategory::CudaOutOfMemory
    } else if contains_any(
        cause,
        &[
            "missing required `risc0-groth16`",
            "missing required risc0-groth16",
            "failed to initialize rzup",
            "required native cuda risc0groth16",
        ],
    ) || contains_any(cause, &["no such file", "file not found"])
        && contains_any(
            cause,
            &[
                "stark_verify_graph.bin",
                "stark_verify_final.zkey",
                "preprocessed_coeffs.bin",
                "fuzzed_msm_results.bin",
            ],
        )
    {
        ProofErrorCategory::Component
    } else if contains_any(
        cause,
        &[
            "unsupported",
            "not supported",
            "cuda_error_no_binary_for_gpu",
            "no kernel image",
            "invalid device function",
            "no binary for gpu",
        ],
    ) {
        ProofErrorCategory::Unsupported
    } else {
        ProofErrorCategory::Other
    }
}

fn contains_any(cause: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        cause
            .as_bytes()
            .windows(pattern.len())
            .any(|window| window.eq_ignore_ascii_case(pattern.as_bytes()))
    })
}

fn contains_code(cause: &str, token: &[u8]) -> bool {
    let bytes = cause.as_bytes();
    bytes
        .windows(token.len())
        .enumerate()
        .any(|(index, window)| {
            window.eq_ignore_ascii_case(token)
                && bytes
                    .get(index + token.len())
                    .is_none_or(|next| !next.is_ascii_digit())
        })
}

pub fn emit_proof_failure(category: ProofErrorCategory) {
    // This type cannot carry an error string, path, proof asset or payload.
    let record = ProofFailureDiagnostic {
        schema: 1,
        status: "failed",
        category,
        category_scope: "safe-SDK-error-text-hint; not-established-root-cause",
        receipt_accepted: false,
        private_details_suppressed: true,
    };
    if let Ok(json) = serde_json::to_string(&record) {
        eprintln!("Proof generation diagnostic: {json}");
    } else {
        eprintln!("Proof generation diagnostic unavailable; private payload suppressed.");
    }
}

#[derive(Serialize)]
struct ProofFailureDiagnostic {
    schema: u32,
    status: &'static str,
    category: ProofErrorCategory,
    category_scope: &'static str,
    receipt_accepted: bool,
    private_details_suppressed: bool,
}

#[derive(Default)]
pub struct ExecutionProgress {
    completed_segments: u64,
    completed_user_cycles_lower_bound: u64,
    maximum_completed_segment_po2: u32,
}

impl ExecutionProgress {
    pub fn include(&mut self, po2: u32, cycles: u32) -> std::io::Result<()> {
        let segments = self
            .completed_segments
            .checked_add(1)
            .ok_or(std::io::ErrorKind::InvalidData)?;
        let user_cycles = self
            .completed_user_cycles_lower_bound
            .checked_add(u64::from(cycles))
            .ok_or(std::io::ErrorKind::InvalidData)?;
        self.completed_segments = segments;
        self.completed_user_cycles_lower_bound = user_cycles;
        self.maximum_completed_segment_po2 = self.maximum_completed_segment_po2.max(po2);
        Ok(())
    }

    pub fn emit_failure(
        &self,
        category: &'static str,
        max_cycles: u64,
        input_bytes_fed: usize,
        input_bytes_total: usize,
    ) {
        let record = FailureDiagnostic {
            schema: 1,
            status: "failed",
            category,
            max_user_cycles: max_cycles,
            completed_segments: self.completed_segments,
            completed_user_cycles_lower_bound: self.completed_user_cycles_lower_bound,
            maximum_completed_segment_po2: self.maximum_completed_segment_po2,
            input_bytes_fed,
            input_bytes_total,
            input_count_scope: "SDK-buffer-read-ahead; not-completed-guest-execution",
            proof_generated: false,
        };
        if let Ok(json) = serde_json::to_string(&record) {
            eprintln!("Execution-only diagnostic: {json}");
        } else {
            eprintln!("Execution-only diagnostic unavailable; private payload suppressed.");
        }
    }
}

#[derive(Serialize)]
struct FailureDiagnostic {
    schema: u32,
    status: &'static str,
    category: &'static str,
    max_user_cycles: u64,
    completed_segments: u64,
    completed_user_cycles_lower_bound: u64,
    maximum_completed_segment_po2: u32,
    input_bytes_fed: usize,
    input_bytes_total: usize,
    input_count_scope: &'static str,
    proof_generated: bool,
}

#[cfg(test)]
mod tests {
    use super::{
        ExecutionProgress, ProofErrorCategory, ProofFailureDiagnostic, proof_error_category,
    };

    #[test]
    fn proof_categories_cover_reviewed_sdk_errors_without_echoing_details() {
        let private_marker = "PRIVATE_INPUT_AND_PROOF_MARKER";
        for (cause, expected) in [
            (
                "CUDA_ERROR_OUT_OF_MEMORY",
                ProofErrorCategory::CudaOutOfMemory,
            ),
            ("out of memory", ProofErrorCategory::CudaOutOfMemory),
            (
                "CUDA_ERROR_ILLEGAL_ADDRESS",
                ProofErrorCategory::CudaIllegalAccess,
            ),
            (
                "an illegal memory access was encountered",
                ProofErrorCategory::CudaIllegalAccess,
            ),
            (
                "Session limit exceeded: 536870913 >= 536870912",
                ProofErrorCategory::SessionLimit,
            ),
            (
                "Missing required `risc0-groth16` rzup component",
                ProofErrorCategory::Component,
            ),
            (
                "stark_verify_graph.bin: No such file or directory",
                ProofErrorCategory::Component,
            ),
            ("unsupported PTX version", ProofErrorCategory::Unsupported),
            (
                "no kernel image is available for execution on the device",
                ProofErrorCategory::Unsupported,
            ),
            ("Child finished with: 101", ProofErrorCategory::Other),
        ] {
            let category = proof_error_category(&format!("{cause}; {private_marker}"), true);
            assert!(category == expected);
            let serialized = serde_json::to_string(&ProofFailureDiagnostic {
                schema: 1,
                status: "failed",
                category,
                category_scope: "safe-SDK-error-text-hint; not-established-root-cause",
                receipt_accepted: false,
                private_details_suppressed: true,
            })
            .unwrap();
            assert!(!serialized.contains(private_marker));
            assert!(!serialized.contains(cause));
        }
        assert!(proof_error_category("out of memory", false) == ProofErrorCategory::Other);
        assert!(proof_error_category("illegal address", false) == ProofErrorCategory::Other);
        assert!(
            proof_error_category("SPPARK::Error #2", true) == ProofErrorCategory::CudaOutOfMemory
        );
        assert!(
            proof_error_category("sppark::Error #700: private context", true)
                == ProofErrorCategory::CudaIllegalAccess
        );
        assert!(proof_error_category("sppark::Error #200", true) == ProofErrorCategory::Other);
        assert!(
            proof_error_category("Invalid memory allocation", true) == ProofErrorCategory::Other
        );
        assert!(
            proof_error_category("unrecognized private context", true) == ProofErrorCategory::Other
        );
    }

    #[test]
    fn completed_segment_counters_are_checked_lower_bounds() {
        let mut progress = ExecutionProgress::default();
        progress.include(19, 300).unwrap();
        progress.include(18, 200).unwrap();
        assert_eq!(progress.completed_segments, 2);
        assert_eq!(progress.completed_user_cycles_lower_bound, 500);
        assert_eq!(progress.maximum_completed_segment_po2, 19);
        progress.completed_user_cycles_lower_bound = u64::MAX;
        assert!(progress.include(19, 1).is_err());
        assert_eq!(progress.completed_segments, 2);
    }
}
