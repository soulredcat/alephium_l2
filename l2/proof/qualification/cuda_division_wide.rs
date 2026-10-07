//! One fixed public full-field fixture for actual CUDA combos_divide arithmetic.
//! Copy into the pinned SDK's risc0/zkp/examples; build with its cuda feature.
//! This is bounded correctness qualification, not fuzzing or a benchmark.
use risc0_core::field::{
    baby_bear::{BabyBear, Elem, ExtElem, P},
    Elem as _, RootsOfUnity,
};
use risc0_zkp::{
    core::hash::poseidon2::Poseidon2HashSuite,
    hal::{cpu::CpuHal, cuda::CudaHalPoseidon2, Buffer, Hal},
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PROFILE: &str = "public-wide-rv32im-v1";
const SEED: u64 = 0xa419_67c2_503d_8eb1;
const ROOT_DOMAIN: u64 = 0x726f_6f74_735f_7631;
const COEFFICIENT_DOMAIN: u64 = 0x636f_6566_665f_7631;
const CYCLES: [usize; 3] = [32, 4096, 524_288];
const COMBOS: usize = 5;
// Exact ordinary combo ordering from the pinned RV32IM zirgen/taps.rs.
const BACKS: [&[usize]; 4] = [&[0], &[0, 1], &[0, 1, 2, 3, 4, 68], &[0, 2, 7, 15, 16]];

/// SplitMix64: deterministic public test data only, never signing randomness.
struct PublicPrng(u64);

impl PublicPrng {
    fn word(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn element(&mut self) -> Elem {
        // Reject the incomplete residue range, avoiding modulo bias. Every
        // extension component consumes an independent PRNG draw, not offsets
        // of a shared small scalar. Bound rejection work for this fixed case.
        let limit = ((1u64 << 32) / u64::from(P)) * u64::from(P);
        for _ in 0..32 {
            let value = self.word() >> 32;
            if value < limit {
                return Elem::new((value % u64::from(P)) as u32);
            }
        }
        panic!("public PRNG rejection bound exceeded");
    }

    fn extension(&mut self) -> ExtElem {
        ExtElem::new(
            self.element(),
            self.element(),
            self.element(),
            self.element(),
        )
    }
}

fn roots(cycles: usize) -> Result<Vec<Vec<ExtElem>>, String> {
    let mut random = PublicPrng(SEED ^ ROOT_DOMAIN ^ cycles as u64);
    let z = random.extension();
    if z == ExtElem::ZERO {
        return Err(format!("stage=fixture_zero_challenge cycles={cycles}"));
    }
    let back_one = ExtElem::from(Elem::ROU_REV[cycles.trailing_zeros() as usize]);
    let mut chunks: Vec<Vec<_>> = BACKS
        .iter()
        .map(|backs| backs.iter().map(|back| z * back_one.pow(*back)).collect())
        .collect();
    // Match the actual check divisor. Unlike earlier pipeline fixtures, its
    // polynomial below has a nonzero full-field quotient rather than zeros.
    chunks.push(vec![z.pow(4)]);
    Ok(chunks)
}

/// Exact coefficient construction of (X - root) * polynomial.
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

fn compare(
    stage: &str,
    cycles: usize,
    actual: &[ExtElem],
    expected: &[ExtElem],
) -> Result<(), String> {
    if actual.len() != expected.len() {
        return Err(format!("stage={stage}_length cycles={cycles}"));
    }
    if let Some(index) = actual.iter().zip(expected).position(|(a, b)| a != b) {
        return Err(format!(
            "stage={stage} cycles={cycles} combo={} coefficient={}",
            index / cycles,
            index % cycles
        ));
    }
    Ok(())
}

fn case(cpu: &CpuHal<BabyBear>, cuda: &CudaHalPoseidon2, cycles: usize) -> Result<(), String> {
    let count = COMBOS.checked_mul(cycles).ok_or("fixture size overflow")?;
    let mut random = PublicPrng(SEED ^ COEFFICIENT_DOMAIN ^ cycles as u64);
    let selected_roots = roots(cycles)?;
    let mut input = Vec::with_capacity(count);
    let mut expected = Vec::with_capacity(count);
    let mut chunks = Vec::with_capacity(COMBOS);
    for (combo, roots) in selected_roots.into_iter().enumerate() {
        let quotient: Vec<_> = (0..cycles - roots.len())
            .map(|_| random.extension())
            .collect();
        // Refuse a degenerate predetermined fixture rather than changing seed
        // or silently accepting an all-zero check polynomial.
        if quotient.last() == Some(&ExtElem::ZERO) {
            return Err(format!(
                "stage=fixture_zero_leading_coefficient cycles={cycles} combo={combo}"
            ));
        }
        let mut polynomial = quotient.clone();
        for &root in &roots {
            multiply_root(&mut polynomial, root);
        }
        if polynomial.len() != cycles {
            return Err(format!(
                "stage=fixture_length cycles={cycles} combo={combo}"
            ));
        }
        input.extend(polynomial);
        expected.extend(quotient);
        expected.extend(std::iter::repeat_n(ExtElem::ZERO, roots.len()));
        chunks.push((combo, roots));
    }
    println!("CASE profile={PROFILE} cycles={cycles} combos={COMBOS} coefficients={count}");
    let cpu_buffer = cpu.copy_from_extelem("division_public_wide", &input);
    catch_unwind(AssertUnwindSafe(|| {
        cpu.combos_divide(&cpu_buffer, chunks.clone(), cycles)
    }))
    .map_err(|_| format!("stage=cpu_remainder cycles={cycles} combos={COMBOS}"))?;
    let mut cpu_result = Vec::with_capacity(count);
    cpu_buffer.view(|values| cpu_result.extend_from_slice(values));
    compare("cpu_quotient", cycles, &cpu_result, &expected)?;
    drop(cpu_buffer);

    let cuda_buffer = cuda.copy_from_extelem("division_public_wide", &input);
    catch_unwind(AssertUnwindSafe(|| {
        cuda.combos_divide(&cuda_buffer, chunks, cycles)
    }))
    .map_err(|_| format!("stage=cuda_division_invariant cycles={cycles} combos={COMBOS}"))?;
    let mut cuda_result = Vec::with_capacity(count);
    cuda_buffer.view(|values| cuda_result.extend_from_slice(values));
    compare("cuda_quotient", cycles, &cuda_result, &cpu_result)?;
    println!("PASS profile={PROFILE} cycles={cycles} combos={COMBOS} coefficients={count}");
    Ok(())
}

fn main() -> std::process::ExitCode {
    // Forward only the reviewed V3 metadata diagnostic. Other SDK assertions
    // can format field elements and must remain suppressed.
    std::panic::set_hook(Box::new(|info| {
        let message = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied());
        if let Some(message) = message.filter(|message| {
            message.starts_with("CUDA polynomial division invariant failed: diagnostic=v3, ")
        }) {
            eprintln!("{message}");
        }
    }));
    let result = catch_unwind(AssertUnwindSafe(|| {
        println!(
            "PROFILE name={PROFILE} prng=splitmix64 seed={SEED:016x} modulus={P} \
             root_domain={ROOT_DOMAIN:016x} coefficient_domain={COEFFICIENT_DOMAIN:016x}"
        );
        println!("PROFILE cycles=32,4096,524288 combo_root_counts=1,2,6,5,1 check=nonzero");
        println!("PROFILE backs=0;0,1;0,1,2,3,4,68;0,2,7,15,16 check_root=z^4");
        // At 32 cycles, back=68 aliases back=4 as the actual cyclic roots do;
        // repeated-factor construction and division remain mathematically exact.
        let cpu = CpuHal::<BabyBear>::new(Poseidon2HashSuite::new_suite());
        let cuda = CudaHalPoseidon2::new();
        for cycles in CYCLES {
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
            eprintln!("FAIL public wide qualification initialization or result access");
            std::process::ExitCode::FAILURE
        }
    }
}
