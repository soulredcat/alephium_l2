//! Public partial-segment correctness diagnostic; not a completed guest proof.
//! Include only under the pinned SDK's existing prove::tests module.
use risc0_binfmt::MemoryImage;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{
    execute::{testutil, CycleLimit},
    prove::segment_prover,
    MAX_INSN_CYCLES,
};

#[test]
fn public_partial_segment19_proves_and_verifies() {
    // Run this single test with --test-threads=1: the hook is process-global.
    // Preserve all SDK guards while suppressing field values in panic payloads.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut stage = "execute";
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let image = MemoryImage::new_kernel(testutil::kernel::simple_loop(500_000));
        let session = testutil::execute(
            image,
            19,
            MAX_INSN_CYCLES,
            CycleLimit::Soft(300_000),
            &testutil::NullSyscall,
            None,
        )
        .expect("public execution failed");
        stage = "segment_shape";
        assert_eq!(session.segments.len(), 1, "expected one partial segment");
        let segment = &session.segments[0];
        assert_eq!(segment.po2, 19, "expected actual po2=19 domain");
        assert!(
            segment.claim.terminate_state.is_none(),
            "fixture must remain partial"
        );
        stage = "prove";
        let seal = segment_prover()
            .expect("segment prover initialization failed")
            .prove(segment)
            .expect("public segment proof failed");
        stage = "verify";
        crate::verify(&seal).expect("public segment seal verification failed");
    }));
    if let Err(payload) = &outcome {
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        let fields: Vec<_> = message.split(", ").collect();
        if let [chunks, index, cycles, reference] = fields.as_slice() {
            if let (Some(chunks), Some(index), Some(cycles), Some(reference)) = (
                chunks
                    .strip_prefix("CUDA polynomial division invariant failed: chunks=")
                    .and_then(|v| v.parse::<usize>().ok()),
                index
                    .strip_prefix("index=")
                    .and_then(|v| v.parse::<usize>().ok()),
                cycles
                    .strip_prefix("cycles=")
                    .and_then(|v| v.parse::<usize>().ok()),
                reference
                    .strip_prefix("cpu_reference_zero=")
                    .and_then(|v| v.parse::<bool>().ok()),
            ) {
                eprintln!("SAFE_DIVISION_DIAGNOSTIC chunks={chunks} index={index} cycles={cycles} cpu_reference_zero={reference}");
            }
        }
    }
    std::panic::set_hook(previous_hook);
    assert!(
        outcome.is_ok(),
        "public segment19 qualification failed at stage={stage}"
    );
}
