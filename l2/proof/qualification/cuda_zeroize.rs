//! Public slice-canary qualification of actual CPU/CUDA element zeroization.
use cust::memory::DevicePointer;
use risc0_core::field::{
    baby_bear::{BabyBear, Elem, ExtElem},
    Elem as _, ExtElem as _,
};
use risc0_zkp::{
    core::hash::poseidon2::Poseidon2HashSuite,
    hal::{cpu::CpuHal, cuda::CudaHalPoseidon2, Buffer, Hal},
};
use std::{
    os::raw::c_char,
    panic::{catch_unwind, AssertUnwindSafe},
};

const PREFIX: usize = 1;
const SUFFIX: usize = 512;

fn fp_case(cpu: &CpuHal<BabyBear>, cuda: &CudaHalPoseidon2, count: usize) -> Result<(), String> {
    let mut input = vec![Elem::INVALID; PREFIX + count + SUFFIX];
    for index in 0..count {
        if index % 2 != 0 {
            input[PREFIX + index] = Elem::new(index as u32 + 7);
        }
    }
    let cpu_allocation = cpu.copy_from_elem("public_zeroize_canaries", &input);
    let cuda_allocation = cuda.copy_from_elem("public_zeroize_canaries", &input);
    cpu.eltwise_zeroize_elem(&cpu_allocation.slice(PREFIX, count));
    cuda.eltwise_zeroize_elem(&cuda_allocation.slice(PREFIX, count));
    let mut cpu_values = Vec::new();
    let mut cuda_values = Vec::new();
    // Read the full allocation through bounded view, not the SDK's sliced
    // to_vec implementation. Canaries occupy the same owned allocation.
    cpu_allocation.view(|values| cpu_values.extend_from_slice(values));
    cuda_allocation.view(|values| cuda_values.extend_from_slice(values));
    if cpu_values.len() != input.len() || cuda_values.len() != input.len() {
        return Err(format!("count={count} result length mismatch"));
    }
    for index in 0..input.len() {
        let expected = if (PREFIX..PREFIX + count).contains(&index) {
            if input[index] == Elem::INVALID {
                Elem::ZERO
            } else {
                input[index]
            }
        } else {
            Elem::INVALID
        };
        if cpu_values[index] != expected {
            return Err(format!("count={count} stage=cpu index={index}"));
        }
        if cuda_values[index] != expected {
            let stage = if index < PREFIX || index >= PREFIX + count {
                "cuda_canary"
            } else {
                "cuda_target"
            };
            return Err(format!("count={count} stage={stage} index={index}"));
        }
    }
    println!("PASS kind=fp count={count} prefix={PREFIX} suffix={SUFFIX}");
    Ok(())
}

fn fpext_case(cpu: &CpuHal<BabyBear>, cuda: &CudaHalPoseidon2, count: usize) -> Result<(), String> {
    let invalid = ExtElem::new(Elem::INVALID, Elem::INVALID, Elem::INVALID, Elem::INVALID);
    let mut input = vec![invalid; PREFIX + count + SUFFIX];
    for index in 0..count {
        let value = Elem::new(index as u32 + 7);
        input[PREFIX + index] = match index % 3 {
            0 => invalid,
            1 => ExtElem::new(value, Elem::INVALID, Elem::ZERO, Elem::INVALID),
            _ => ExtElem::new(value, Elem::ONE, Elem::ZERO, value),
        };
    }
    // The HAL has no FpExt zeroization method. Use its Fp implementation as a
    // componentwise CPU reference and call the existing CUDA FpExt FFI directly.
    let flat: Vec<_> = input
        .iter()
        .flat_map(|value| value.subelems().iter().copied())
        .collect();
    let cpu_allocation = cpu.copy_from_elem("public_zeroize_ext_canaries", &flat);
    let cuda_allocation = cuda.copy_from_extelem("public_zeroize_ext_canaries", &input);
    cpu.eltwise_zeroize_elem(&cpu_allocation.slice(PREFIX * 4, count * 4));
    let cuda_slice = cuda_allocation.slice(PREFIX, count);
    extern "C" {
        fn risc0_zkp_cuda_eltwise_zeroize_fpext(
            elems: DevicePointer<u8>,
            count: u32,
        ) -> *const c_char;
    }
    // SAFETY: this is the pinned SDK's C FFI signature; the owned allocation
    // contains count FpExt values at the slice pointer and outlives the call.
    risc0_sys::ffi_wrap(|| unsafe {
        risc0_zkp_cuda_eltwise_zeroize_fpext(
            cuda_slice.as_device_ptr(),
            u32::try_from(count).expect("bounded fixture count"),
        )
    })
    .map_err(|_| format!("count={count} stage=cuda_launch"))?;
    let mut cpu_values = Vec::new();
    let mut cuda_values = Vec::new();
    cpu_allocation.view(|values| cpu_values.extend_from_slice(values));
    cuda_allocation.view(|values| cuda_values.extend_from_slice(values));
    if cpu_values.len() != flat.len() || cuda_values.len() != input.len() {
        return Err(format!("count={count} result length mismatch"));
    }
    for index in 0..input.len() {
        let target = (PREFIX..PREFIX + count).contains(&index);
        let expected: Vec<_> = input[index]
            .subelems()
            .iter()
            .map(|&value| {
                if target && value == Elem::INVALID {
                    Elem::ZERO
                } else {
                    value
                }
            })
            .collect();
        if cpu_values[index * 4..(index + 1) * 4] != expected {
            return Err(format!("count={count} stage=cpu index={index}"));
        }
        if cuda_values[index].subelems() != expected {
            let stage = if target { "cuda_target" } else { "cuda_canary" };
            return Err(format!("count={count} stage={stage} index={index}"));
        }
    }
    println!("PASS kind=fpext count={count} prefix={PREFIX} suffix={SUFFIX}");
    Ok(())
}

fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let cpu = CpuHal::<BabyBear>::new(Poseidon2HashSuite::new_suite());
        let cuda = CudaHalPoseidon2::new();
        let mut failures = 0;
        // Empty slices are constructible, but the pinned launcher computes
        // grid=0 and has no no-op handling. Do not claim zero-count support.
        println!("SKIP count=0 reason=pinned_launcher_has_no_empty_grid_support");
        for count in [1, 90, 255, 256, 257] {
            for (kind, result) in [
                ("fp", fp_case(&cpu, &cuda, count)),
                ("fpext", fpext_case(&cpu, &cuda, count)),
            ] {
                match result {
                    Ok(()) => {}
                    Err(error) => {
                        eprintln!("FAIL kind={kind} {error}");
                        failures += 1;
                    }
                }
            }
        }
        failures == 0
    }));
    match result {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(_) => {
            eprintln!("FAIL zeroization initialization or stage assertion");
            std::process::ExitCode::FAILURE
        }
    }
}
