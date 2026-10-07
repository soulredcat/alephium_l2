//! Bounded public-fixture qualification of the actual CUDA combos_divide path.
//! Copy into the pinned SDK's risc0/zkp/examples and build with its cuda feature.
use risc0_core::field::{
    Elem as _, RootsOfUnity,
    baby_bear::{BabyBear, Elem, ExtElem},
};
use risc0_zkp::{
    core::hash::poseidon2::Poseidon2HashSuite,
    hal::{Buffer, Hal, cpu::CpuHal, cuda::CudaHalPoseidon2},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

const COMBOS: usize = 4;
const MAX_CYCLES: usize = 1 << 19;

fn coefficient(index: usize, combo: usize) -> ExtElem {
    let value = ((index as u64 * 17 + combo as u64 * 103 + 1) % 100_003) as u32;
    ExtElem::new(
        Elem::new(value),
        Elem::new(value + 3),
        Elem::new(value + 7),
        Elem::new(value + 11),
    )
}

fn roots(combo: usize, cycles: usize) -> Vec<ExtElem> {
    if cycles == 4 {
        return vec![coefficient(3, combo + 7), coefficient(9, combo + 11)];
    }
    let back_one = ExtElem::from(Elem::ROU_REV[cycles.trailing_zeros() as usize]);
    let z = coefficient(3, combo + 7);
    let backs: &[usize] = if combo % 2 == 0 {
        &[0, 2, 7, 15, 16]
    } else {
        &[0, 1, 2, 7, 15, 16]
    };
    backs.iter().map(|back| z * back_one.pow(*back)).collect()
}

/// In-place coefficient construction of (X - root) * polynomial.
/// Descending traversal reads both old coefficients before either is overwritten.
fn multiply_root(polynomial: &mut Vec<ExtElem>, root: ExtElem) {
    let old_len = polynomial.len();
    polynomial.push(ExtElem::ZERO);
    for index in (1..=old_len).rev() {
        let old_at_index = if index == old_len {
            ExtElem::ZERO
        } else {
            polynomial[index]
        };
        polynomial[index] = polynomial[index - 1] - root * old_at_index;
    }
    polynomial[0] = -root * polynomial[0];
}

fn case(cpu: &CpuHal<BabyBear>, cuda: &CudaHalPoseidon2, cycles: usize) -> Result<(), String> {
    let count = COMBOS.checked_mul(cycles).ok_or("fixture size overflow")?;
    let mut input = Vec::with_capacity(count);
    let mut expected = Vec::with_capacity(count);
    let mut chunks = Vec::with_capacity(COMBOS);
    for combo in 0..COMBOS {
        let selected_roots = roots(combo, cycles);
        let quotient: Vec<_> = (0..cycles - selected_roots.len())
            .map(|index| coefficient(index, combo))
            .collect();
        let mut polynomial = quotient.clone();

        for root in &selected_roots {
            multiply_root(&mut polynomial, *root);
        }
        if polynomial.len() != cycles {
            return Err(format!(
                "fixture length mismatch: cycles={cycles} combo={combo}"
            ));
        }
        input.extend(polynomial);
        expected.extend(quotient);
        expected.extend(vec![ExtElem::ZERO; selected_roots.len()]);
        chunks.push((combo, selected_roots));
    }
    let cpu_buffer = cpu.copy_from_extelem("division_public_input", &input);
    catch_unwind(AssertUnwindSafe(|| {
        cpu.combos_divide(&cpu_buffer, chunks.clone(), cycles)
    }))
    .map_err(|_| format!("CPU remainder invariant failed: cycles={cycles} combos={COMBOS}"))?;
    let cpu_result = cpu_buffer.to_vec();
    if cpu_result.len() != expected.len() {
        return Err(format!("CPU quotient length mismatch: cycles={cycles}"));
    }
    if let Some(index) = cpu_result.iter().zip(&expected).position(|(a, b)| a != b) {
        return Err(format!(
            "CPU quotient mismatch: cycles={cycles} index={index}"
        ));
    }
    let cuda_buffer = cuda.copy_from_extelem("division_public_input", &input);
    catch_unwind(AssertUnwindSafe(|| {
        cuda.combos_divide(&cuda_buffer, chunks, cycles)
    }))
    .map_err(|_| format!("CUDA remainder invariant failed: cycles={cycles} combos={COMBOS}"))?;
    let cuda_result = cuda_buffer.to_vec();
    if cuda_result.len() != cpu_result.len() {
        return Err(format!("CUDA quotient length mismatch: cycles={cycles}"));
    }
    if let Some(index) = cuda_result
        .iter()
        .zip(&cpu_result)
        .position(|(a, b)| a != b)
    {
        return Err(format!(
            "CUDA quotient mismatch: cycles={cycles} index={index}"
        ));
    }
    println!("PASS cycles={cycles} combos={COMBOS} coefficients={count}");
    Ok(())
}

fn main() -> std::process::ExitCode {
    // SDK remainder assertions may print field values. Keep them active and
    // catch their panics, but emit only bounded case metadata below.
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let cpu = CpuHal::<BabyBear>::new(Poseidon2HashSuite::new_suite());
        let cuda = CudaHalPoseidon2::new();
        for cycles in [4, 32, 256, 4096, MAX_CYCLES] {
            case(&cpu, &cuda, cycles)?;
        }
        Ok::<_, String>(())
    }));
    match result {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        Ok(Err(error)) => {
            eprintln!("FAIL {error}");
            std::process::ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("FAIL qualification initialization or result access");
            std::process::ExitCode::FAILURE
        }
    }
}
