use std::{env, path::PathBuf, process::Command};

fn main() {
    for name in ["CUDA_PATH", "L2_CUDA_ARCH", "L2_CUDA_HOST_COMPILER"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = root.join("kernels/recovery.cu");
    let includes = root.join("vendor/include");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", includes.display());
    let arch = env::var("L2_CUDA_ARCH").unwrap_or_else(|_| "75".into());
    assert!(
        (2..=3).contains(&arch.len()) && arch.bytes().all(|byte| byte.is_ascii_digit()),
        "L2_CUDA_ARCH must be a numeric CUDA architecture, for example 75 or 86"
    );
    let arch_number: u32 = arch.parse().expect("invalid CUDA architecture");
    assert!(arch_number >= 75, "CUDA architecture must be at least 75");
    let nvcc = match env::var_os("CUDA_PATH") {
        Some(path) => {
            PathBuf::from(path)
                .join("bin")
                .join(if cfg!(windows) { "nvcc.exe" } else { "nvcc" })
        }
        None => PathBuf::from("nvcc"),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("recovery.ptx");
    let mut command = Command::new(nvcc);
    command.args(["--ptx", "--std=c++17", "-O3"]);
    command.arg(format!("--gpu-architecture=compute_{arch}"));
    command.arg("-I").arg(includes);
    if let Some(compiler) = env::var_os("L2_CUDA_HOST_COMPILER") {
        command.arg("--compiler-bindir").arg(compiler);
    }
    let status = command
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .status()
        .expect("CUDA feature needs an installed NVCC compiler (set CUDA_PATH)");
    assert!(
        status.success(),
        "CUDA public recovery PTX compilation failed"
    );
}
