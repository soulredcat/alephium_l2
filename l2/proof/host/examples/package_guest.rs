//! Package a compiled user ELF with the pinned patched RISC0 kernel.
//! This is the official risc0-build packaging step; it executes no guest.

use risc0_binfmt::{ProgramBinary, compute_image_id};
use risc0_zkos_v1compat::V1COMPAT_ELF;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{DirBuilder, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

const MAX_USER_ELF_BYTES: u64 = 32 * 1024 * 1024;
const USAGE: &str = "Usage: package_guest --user-elf <compiled-user-ELF> --output <new-directory>";
type PackageResult<T> = Result<T, &'static str>;

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("Guest packaging stopped after an internal error; payload suppressed.");
    }));
    match run() {
        Ok(path) => {
            println!("Guest program packaged: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> PackageResult<PathBuf> {
    let (input, output) = arguments()?;
    let user_elf = read_user_elf(&input)?;
    // Exactly the default kernel and API used by pinned risc0-build 3.0.3.
    // Caller-selected kernels and handwritten container formats are forbidden.
    let program = ProgramBinary::new(&user_elf, V1COMPAT_ELF).encode();
    if program.len() as u64 > MAX_USER_ELF_BYTES {
        return Err("Packaged program exceeds the proof host's 32 MiB bound.");
    }
    let image_id = compute_image_id(&program)
        .map_err(|_| "Packaged user ELF and pinned kernel are not a valid RISC0 program.")?;
    let manifest = Manifest {
        schema: 1,
        guest_format: "risc0-ProgramBinary-v1",
        sdk_version: "3.0.3",
        sdk_revision: "14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6",
        kernel_package: "risc0-zkos-v1compat/2.2.0",
        user_elf_bytes: user_elf.len(),
        user_elf_sha256: sha(&user_elf),
        kernel_elf_bytes: V1COMPAT_ELF.len(),
        kernel_elf_sha256: sha(V1COMPAT_ELF),
        program_bytes: program.len(),
        program_sha256: sha(&program),
        image_id: hex::encode(image_id.as_bytes()),
        guest_executed: false,
        proof_generated: false,
    };
    let manifest = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| "Cannot encode guest packaging manifest.")?;
    let mut directory = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory
        .create(&output)
        .map_err(|_| "Output must be a new directory under an existing writable parent.")?;
    write_new(&output.join("guest.bin"), &program)?;
    write_new(&output.join("imageid.bin"), image_id.as_bytes())?;
    sync_directory(&output)?;
    // Manifest is the final completion marker, after package and identity sync.
    write_new(&output.join("manifest.json"), &manifest)?;
    sync_directory(&output)?;
    Ok(output.join("manifest.json"))
}

fn arguments() -> PackageResult<(PathBuf, PathBuf)> {
    let (mut input, mut output) = (None, None);
    let mut args = env::args_os().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(USAGE)?;
        if value.is_empty() || value.to_string_lossy().starts_with("--") {
            return Err(USAGE);
        }
        let slot = if flag == "--user-elf" {
            &mut input
        } else if flag == "--output" {
            &mut output
        } else {
            return Err(USAGE);
        };
        if slot.replace(PathBuf::from(value)).is_some() {
            return Err("Duplicate packaging option.");
        }
    }
    let output = output.ok_or(USAGE)?;
    if output.to_string_lossy().chars().any(char::is_control) {
        return Err("Output path contains a control character.");
    }
    Ok((input.ok_or(USAGE)?, output))
}

fn read_user_elf(path: &Path) -> PackageResult<Vec<u8>> {
    let file = File::open(path).map_err(|_| "Cannot open compiled user ELF.")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect compiled user ELF.")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_USER_ELF_BYTES {
        return Err("Compiled user ELF exceeds its bounded regular-file limit.");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_USER_ELF_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read compiled user ELF.")?;
    if bytes.len() as u64 != metadata.len() || !bytes.starts_with(b"\x7fELF") {
        return Err("Input changed while reading or is not a raw user ELF.");
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> PackageResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Cannot create guest artifact.")?;
    file.write_all(bytes)
        .map_err(|_| "Cannot write guest artifact.")?;
    file.sync_all()
        .map_err(|_| "Cannot synchronize guest artifact.")
}

fn sync_directory(path: &Path) -> PackageResult<()> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| "Cannot synchronize guest artifact directory.")?;
    #[cfg(not(unix))]
    std::fs::metadata(path).map_err(|_| "Cannot inspect guest artifact directory.")?;
    Ok(())
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Serialize)]
struct Manifest {
    schema: u32,
    guest_format: &'static str,
    sdk_version: &'static str,
    sdk_revision: &'static str,
    kernel_package: &'static str,
    user_elf_bytes: usize,
    user_elf_sha256: String,
    kernel_elf_bytes: usize,
    kernel_elf_sha256: String,
    program_bytes: usize,
    program_sha256: String,
    image_id: String,
    guest_executed: bool,
    proof_generated: bool,
}
