//! Bounded public-fixture CPU/CUDA comparisons of mixing and preparation.
//! Calls each backend separately; no inherited DualHal host implementation.
use risc0_core::field::baby_bear::{BabyBear, Elem, ExtElem};
use risc0_zkp::{
    core::hash::poseidon2::Poseidon2HashSuite,
    hal::{Buffer, Hal, cpu::CpuHal, cuda::CudaHalPoseidon2},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

const COMBO_COUNT: usize = 3;
const REG_IDS: [u32; 6] = [0, 1, 0, 2, 1, 2];
const REG_SIZES: [u32; 6] = [1, 2, 3, 1, 2, 3];

fn element(index: usize, salt: usize) -> Elem {
    Elem::new(((index as u64 * 17 + salt as u64 * 101 + 1) % 100_003) as u32)
}

fn extension(index: usize, salt: usize) -> ExtElem {
    ExtElem::new(
        element(index, salt),
        element(index, salt + 1),
        element(index, salt + 3),
        element(index, salt + 7),
    )
}

fn compare(stage: &str, cycles: usize, cpu: &[ExtElem], cuda: &[ExtElem]) -> Result<(), String> {
    if cpu.len() != cuda.len() {
        return Err(format!("stage={stage} cycles={cycles} length mismatch"));
    }
    if let Some(index) = cpu.iter().zip(cuda).position(|(a, b)| a != b) {
        return Err(format!("stage={stage} cycles={cycles} index={index}"));
    }
    println!(
        "PASS stage={stage} cycles={cycles} coefficients={}",
        cpu.len()
    );
    Ok(())
}

fn mixing(cpu: &CpuHal<BabyBear>, cuda: &CudaHalPoseidon2, cycles: usize) -> Result<(), String> {
    let count = cycles
        .checked_mul(COMBO_COUNT + 1)
        .ok_or("mixing size overflow")?;
    let cpu_output = cpu.alloc_extelem_zeroed("public_mix_output", count);
    let cuda_output = cuda.alloc_extelem_zeroed("public_mix_output", count);
    let mix = extension(4, 13);
    let mut mix_start = extension(7, 19);
    for (group, ids) in [
        REG_IDS.to_vec(),
        vec![COMBO_COUNT as u32; CpuHal::<BabyBear>::CHECK_SIZE],
    ]
    .into_iter()
    .enumerate()
    {
        let input_count = cycles
            .checked_mul(ids.len())
            .ok_or("mixing input overflow")?;
        let input: Vec<_> = (0..input_count)
            .map(|index| element(index, group + 31))
            .collect();
        let cpu_input = cpu.copy_from_elem("public_mix_input", &input);
        let cuda_input = cuda.copy_from_elem("public_mix_input", &input);
        let cpu_ids = cpu.copy_from_u32("public_mix_ids", &ids);
        let cuda_ids = cuda.copy_from_u32("public_mix_ids", &ids);
        cpu.mix_poly_coeffs(
            &cpu_output,
            &mix_start,
            &mix,
            &cpu_input,
            &cpu_ids,
            ids.len(),
            cycles,
        );
        cuda.mix_poly_coeffs(
            &cuda_output,
            &mix_start,
            &mix,
            &cuda_input,
            &cuda_ids,
            ids.len(),
            cycles,
        );
        compare(
            if group == 0 {
                "mix_registers"
            } else {
                "mix_check"
            },
            cycles,
            &cpu_output.to_vec(),
            &cuda_output.to_vec(),
        )?;
        for _ in &ids {
            mix_start *= mix;
        }
    }
    Ok(())
}

fn preparation(
    cpu: &CpuHal<BabyBear>,
    cuda: &CudaHalPoseidon2,
    cycles: usize,
) -> Result<(), String> {
    let count = cycles
        .checked_mul(COMBO_COUNT + 1)
        .ok_or("preparation size overflow")?;
    // Start with nonzero coefficients so unchanged high-degree coefficients
    // and repeated updates to the same combo are both observed.
    let initial: Vec<_> = (0..count).map(|index| extension(index, 41)).collect();
    let coeff_count =
        REG_SIZES.iter().map(|size| *size as usize).sum::<usize>() + CpuHal::<BabyBear>::CHECK_SIZE;
    let coeff_u: Vec<_> = (0..coeff_count).map(|index| extension(index, 53)).collect();
    let mix = extension(3, 61);
    let cpu_output = cpu.copy_from_extelem("public_prepare_input", &initial);
    let cuda_output = cuda.copy_from_extelem("public_prepare_input", &initial);
    cpu.combos_prepare(
        &cpu_output,
        &coeff_u,
        COMBO_COUNT,
        cycles,
        &REG_SIZES,
        &REG_IDS,
        &mix,
    );
    cuda.combos_prepare(
        &cuda_output,
        &coeff_u,
        COMBO_COUNT,
        cycles,
        &REG_SIZES,
        &REG_IDS,
        &mix,
    );
    // Readback follows the real API call; no extra preparation stream barrier
    // or modified production kernel is introduced by this qualification.
    compare(
        "prepare",
        cycles,
        &cpu_output.to_vec(),
        &cuda_output.to_vec(),
    )
}

fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let cpu = CpuHal::<BabyBear>::new(Poseidon2HashSuite::new_suite());
        let cuda = CudaHalPoseidon2::new();
        for cycles in [4, 32, 256, 4096, 1 << 19] {
            println!("CASE cycles={cycles} combos={}", COMBO_COUNT + 1);
            mixing(&cpu, &cuda, cycles)?;
            preparation(&cpu, &cuda, cycles)?;
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
            eprintln!("FAIL public qualification initialization or stage assertion");
            std::process::ExitCode::FAILURE
        }
    }
}
