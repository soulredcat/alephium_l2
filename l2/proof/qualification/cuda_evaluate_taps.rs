//! Public deterministic qualification of varied polynomial selection/tap roots.
use risc0_core::field::{
    Elem as _, RootsOfUnity,
    baby_bear::{BabyBear, Elem, ExtElem},
};
use risc0_zkp::{
    core::hash::poseidon2::Poseidon2HashSuite,
    hal::{Buffer, Hal, cpu::CpuHal, cuda::CudaHalPoseidon2},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

const POLYNOMIALS: usize = 16;
const RV32IM_BACKS: &[usize] = &[0, 2, 7, 15, 16];
const RECURSION_BACKS: &[usize] = &[0, 1, 2, 7, 15, 16];

fn coefficients(cycles: usize) -> Result<Vec<Elem>, String> {
    let count = POLYNOMIALS
        .checked_mul(cycles)
        .ok_or("coefficient count overflow")?;
    Ok((0..count)
        .map(|index| {
            let polynomial = index / cycles;
            let coefficient = index % cycles;
            Elem::new(((coefficient as u64 * 17 + polynomial as u64 * 101 + 1) % 100_003) as u32)
        })
        .collect())
}

fn selections(cycles: usize, backs: &[usize]) -> (Vec<u32>, Vec<ExtElem>) {
    let po2 = cycles.trailing_zeros() as usize;
    let back_one = ExtElem::from(Elem::ROU_REV[po2]);
    let z = ExtElem::new(Elem::new(19), Elem::new(23), Elem::new(29), Elem::new(31));
    let mut which = Vec::new();
    let mut xs = Vec::new();
    // Cover all 16 polynomial selections, including the last polynomial.
    for polynomial in 0..POLYNOMIALS {
        which.push(polynomial as u32);
        xs.push(back_one.pow(backs[polynomial % backs.len()]) * z);
    }
    // Exercise every exact back for two nonzero selections, with repeated IDs.
    for polynomial in [3, POLYNOMIALS - 1] {
        for back in backs {
            which.push(polynomial as u32);
            xs.push(back_one.pow(*back) * z);
        }
    }
    (which, xs)
}

fn horner(coefficients: &[Elem], x: ExtElem) -> ExtElem {
    coefficients
        .iter()
        .rev()
        .fold(ExtElem::ZERO, |acc, coefficient| {
            acc * x + ExtElem::from(*coefficient)
        })
}

fn pattern(
    cpu: &CpuHal<BabyBear>,
    cuda: &CudaHalPoseidon2,
    cycles: usize,
    name: &str,
    backs: &[usize],
    coefficients: &[Elem],
) -> Result<(), String> {
    let (which, xs) = selections(cycles, backs);
    let cpu_coefficients = cpu.copy_from_elem("public_tap_coefficients", coefficients);
    let cuda_coefficients = cuda.copy_from_elem("public_tap_coefficients", coefficients);
    let cpu_which = cpu.copy_from_u32("public_tap_which", &which);
    let cuda_which = cuda.copy_from_u32("public_tap_which", &which);
    let cpu_xs = cpu.copy_from_extelem("public_tap_roots", &xs);
    let cuda_xs = cuda.copy_from_extelem("public_tap_roots", &xs);
    let cpu_output = cpu.alloc_extelem("public_tap_results", which.len());
    let cuda_output = cuda.alloc_extelem("public_tap_results", which.len());
    cpu.batch_evaluate_any(
        &cpu_coefficients,
        POLYNOMIALS,
        &cpu_which,
        &cpu_xs,
        &cpu_output,
    );
    cuda.batch_evaluate_any(
        &cuda_coefficients,
        POLYNOMIALS,
        &cuda_which,
        &cuda_xs,
        &cuda_output,
    );
    let cpu_values = cpu_output.to_vec();
    let cuda_values = cuda_output.to_vec();
    if cpu_values.len() != which.len() || cuda_values.len() != which.len() {
        return Err(format!(
            "stage={name} cycles={cycles} result count mismatch"
        ));
    }
    if cycles == 32 {
        for (index, (&polynomial, &x)) in which.iter().zip(&xs).enumerate() {
            let start = polynomial as usize * cycles;
            if cpu_values[index] != horner(&coefficients[start..start + cycles], x) {
                return Err(format!(
                    "stage={name}_cpu_horner cycles={cycles} index={index}"
                ));
            }
        }
    }
    if let Some(index) = cpu_values
        .iter()
        .zip(&cuda_values)
        .position(|(a, b)| a != b)
    {
        return Err(format!(
            "stage={name}_cpu_cuda cycles={cycles} index={index}"
        ));
    }
    println!(
        "PASS stage={name} cycles={cycles} polynomials={POLYNOMIALS} evaluations={}",
        which.len()
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let cpu = CpuHal::<BabyBear>::new(Poseidon2HashSuite::new_suite());
        let cuda = CudaHalPoseidon2::new();
        for cycles in [32, 256, 4096, 1 << 19] {
            println!("CASE cycles={cycles} polynomials={POLYNOMIALS}");
            let coefficients = coefficients(cycles)?;
            for (name, backs) in [
                ("rv32im_taps", RV32IM_BACKS),
                ("recursion_taps", RECURSION_BACKS),
            ] {
                pattern(&cpu, &cuda, cycles, name, backs, &coefficients)?;
            }
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
            eprintln!("FAIL tap qualification initialization or stage assertion");
            std::process::ExitCode::FAILURE
        }
    }
}
