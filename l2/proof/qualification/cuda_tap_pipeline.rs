//! Public eval/interpolation/mix/preparation/division integration qualification.
use risc0_core::field::{
    Elem as _, RootsOfUnity,
    baby_bear::{BabyBear, Elem, ExtElem},
};
use risc0_zkp::{
    core::{hash::poseidon2::Poseidon2HashSuite, poly::poly_interpolate},
    hal::{Buffer, Hal, cpu::CpuHal, cuda::CudaHalPoseidon2},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

const REGISTERS: usize = 2;
const RV32IM: &[usize] = &[0, 2, 7, 15, 16];
const RECURSION: &[usize] = &[0, 1, 2, 7, 15, 16];

fn roots(cycles: usize, backs: &[usize]) -> (ExtElem, Vec<ExtElem>) {
    let z = ExtElem::new(Elem::new(19), Elem::new(23), Elem::new(29), Elem::new(31));
    let back_one = ExtElem::from(Elem::ROU_REV[cycles.trailing_zeros() as usize]);
    (
        z,
        backs.iter().map(|back| z * back_one.pow(*back)).collect(),
    )
}

fn horner(coefficients: &[ExtElem], x: ExtElem) -> ExtElem {
    coefficients
        .iter()
        .rev()
        .fold(ExtElem::ZERO, |acc, coefficient| acc * x + *coefficient)
}

struct Output {
    evaluations: Vec<ExtElem>,
    quotient: Vec<ExtElem>,
}

fn pipeline<H: Hal<Field = BabyBear, Elem = Elem, ExtElem = ExtElem>>(
    hal: &H,
    cycles: usize,
    backs: &[usize],
    coefficients: &[Elem],
) -> Result<Output, String> {
    let (z, ordinary_roots) = roots(cycles, backs);
    let root_count = ordinary_roots.len();
    let input = hal.copy_from_elem("public_pipeline_coefficients", coefficients);
    let selections: Vec<_> = (0..REGISTERS)
        .flat_map(|register| std::iter::repeat_n(register as u32, root_count))
        .collect();
    let evaluation_roots: Vec<_> = (0..REGISTERS)
        .flat_map(|_| ordinary_roots.iter().copied())
        .collect();
    let which = hal.copy_from_u32("public_pipeline_which", &selections);
    let xs = hal.copy_from_extelem("public_pipeline_roots", &evaluation_roots);
    let evaluation_buffer = hal.alloc_extelem("public_pipeline_evaluations", selections.len());
    hal.batch_evaluate_any(&input, REGISTERS, &which, &xs, &evaluation_buffer);
    let evaluations = evaluation_buffer.to_vec();
    if evaluations.len() != REGISTERS * root_count {
        return Err("stage=evaluate result count mismatch".into());
    }
    let mut coeff_u = vec![ExtElem::ZERO; evaluations.len()];
    for register in 0..REGISTERS {
        let start = register * root_count;
        let values = &evaluations[start..start + root_count];
        let interpolant = &mut coeff_u[start..start + root_count];
        poly_interpolate(interpolant, &ordinary_roots, values, root_count);
        for (index, root) in ordinary_roots.iter().enumerate() {
            if horner(interpolant, *root) != values[index] {
                return Err(format!(
                    "stage=interpolate register={register} index={index}"
                ));
            }
        }
    }
    // These exact CHECK_SIZE values are the evaluations of all-zero check
    // polynomials. The normal check mixing path is nevertheless exercised.
    coeff_u.extend(vec![ExtElem::ZERO; H::CHECK_SIZE]);
    let combos = hal.alloc_extelem_zeroed("public_pipeline_combos", cycles * 2);
    let ids = hal.copy_from_u32("public_pipeline_combo_ids", &[0, 0]);
    let mix = ExtElem::new(Elem::new(37), Elem::new(41), Elem::new(43), Elem::new(47));
    hal.mix_poly_coeffs(
        &combos,
        &ExtElem::ONE,
        &mix,
        &input,
        &ids,
        REGISTERS,
        cycles,
    );
    {
        let checks = hal.alloc_elem_init(
            "public_pipeline_zero_checks",
            H::CHECK_SIZE * cycles,
            Elem::ZERO,
        );
        let check_ids = hal.copy_from_u32("public_pipeline_check_ids", &vec![1; H::CHECK_SIZE]);
        hal.mix_poly_coeffs(
            &combos,
            &mix.pow(REGISTERS),
            &mix,
            &checks,
            &check_ids,
            H::CHECK_SIZE,
            cycles,
        );
    }
    let sizes = vec![root_count as u32; REGISTERS];
    hal.combos_prepare(&combos, &coeff_u, 1, cycles, &sizes, &[0, 0], &mix);
    // No readback/barrier is inserted between the actual preparation and
    // division APIs. Each backend keeps its real completion/ordering behavior.
    hal.combos_divide(
        &combos,
        vec![(0, ordinary_roots), (1, vec![z.pow(4)])],
        cycles,
    );
    Ok(Output {
        evaluations,
        quotient: combos.to_vec(),
    })
}

fn compare(stage: &str, cpu: &[ExtElem], cuda: &[ExtElem]) -> Result<(), String> {
    if cpu.len() != cuda.len() {
        return Err(format!("stage={stage} result count mismatch"));
    }
    if let Some(index) = cpu.iter().zip(cuda).position(|(a, b)| a != b) {
        return Err(format!("stage={stage} index={index}"));
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let cpu = CpuHal::<BabyBear>::new(Poseidon2HashSuite::new_suite());
        let cuda = CudaHalPoseidon2::new();
        for cycles in [32, 256, 4096, 1 << 19] {
            let coefficients: Vec<_> = (0..REGISTERS * cycles)
                .map(|index| {
                    let register = index / cycles;
                    let coefficient = index % cycles;
                    Elem::new(
                        ((coefficient as u64 * 17 + register as u64 * 101 + 1) % 100_003) as u32,
                    )
                })
                .collect();
            for (name, backs) in [("rv32im", RV32IM), ("recursion", RECURSION)] {
                println!(
                    "CASE pattern={name} cycles={cycles} registers={REGISTERS} roots={}",
                    backs.len()
                );
                let cpu_output = catch_unwind(AssertUnwindSafe(|| {
                    pipeline(&cpu, cycles, backs, &coefficients)
                }))
                .map_err(|_| {
                    format!("stage=cpu_pipeline pattern={name} cycles={cycles} invariant")
                })??;
                let cuda_output = catch_unwind(AssertUnwindSafe(|| {
                    pipeline(&cuda, cycles, backs, &coefficients)
                }))
                .map_err(|_| {
                    format!("stage=cuda_pipeline pattern={name} cycles={cycles} invariant")
                })??;
                compare(
                    "evaluations",
                    &cpu_output.evaluations,
                    &cuda_output.evaluations,
                )?;
                compare("quotient", &cpu_output.quotient, &cuda_output.quotient)?;
                println!(
                    "PASS pattern={name} cycles={cycles} coefficients={}",
                    cpu_output.quotient.len()
                );
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
            eprintln!("FAIL pipeline qualification initialization or allocation");
            std::process::ExitCode::FAILURE
        }
    }
}
