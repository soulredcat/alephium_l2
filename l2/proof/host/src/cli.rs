//! Exact CLI surface and local-only prover routing policy.

use crate::{HostResult, inputs};
use std::{env, ffi::OsString, path::PathBuf, process::Command};

const USAGE: &str = "Usage: alephium-l2-transition-prover --input <private-transition.json> --guest <ProgramBinary> --expected-image-id <64-hex> --prover-sha256 <64-hex> (--output <new-directory> | --execute-only)";
pub const SDK_VERSION: &str = "3.0.3";
pub const SDK_REVISION: &str = "14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6";

pub struct Config {
    pub input: PathBuf,
    pub guest: PathBuf,
    /// Absent exactly when the run is an execution-only preflight.
    pub output: Option<PathBuf>,
    pub expected_image_id: [u8; 32],
    pub prover_sha256: [u8; 32],
}

impl Config {
    pub fn parse() -> HostResult<Self> {
        let mut input = None;
        let mut guest = None;
        let mut output = None;
        let mut image_id = None;
        let mut prover_sha256 = None;
        let mut execute_only = false;
        let mut args = env::args_os().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--execute-only" {
                if std::mem::replace(&mut execute_only, true) {
                    return Err("Duplicate CLI option.");
                }
                continue;
            }
            let value = args.next().ok_or(USAGE)?;
            if value.is_empty() || value.to_string_lossy().starts_with("--") {
                return Err(USAGE);
            }
            let slot = if flag == "--input" {
                &mut input
            } else if flag == "--guest" {
                &mut guest
            } else if flag == "--output" {
                &mut output
            } else if flag == "--expected-image-id" {
                &mut image_id
            } else if flag == "--prover-sha256" {
                &mut prover_sha256
            } else {
                return Err(USAGE);
            };
            if slot.replace(PathBuf::from(value)).is_some() {
                return Err("Duplicate CLI option.");
            }
        }
        // A preflight writes no artifacts; a proof always needs a new directory.
        if execute_only == output.is_some() {
            return Err(USAGE);
        }
        let config = Self {
            input: input.ok_or(USAGE)?,
            guest: guest.ok_or(USAGE)?,
            output,
            expected_image_id: parse_digest(image_id.ok_or(USAGE)?)?,
            prover_sha256: parse_digest(prover_sha256.ok_or(USAGE)?)?,
        };
        // This path is the only user-provided text printed on successful exit.
        if config
            .output
            .as_ref()
            .is_some_and(|output| output.to_string_lossy().chars().any(char::is_control))
        {
            return Err("Output directory contains a control character.");
        }
        Ok(config)
    }
}

pub struct LocalProver {
    pub server_path: PathBuf,
    pub server_sha256: [u8; 32],
}

impl LocalProver {
    /// Docker is only inspected when a Groth16 proof will actually be produced.
    pub fn validate(expected_sha256: [u8; 32], groth16: bool) -> HostResult<Self> {
        if risc0_zkvm::VERSION != SDK_VERSION {
            return Err("Host SDK does not match the reviewed 3.0.3 pin.");
        }
        if env::var_os("RISC0_DEV_MODE").is_some() {
            return Err("RISC0_DEV_MODE must be absent for a real proof.");
        }
        // Inspect names only. Never render environment values or credentials.
        if env::vars_os().any(|(name, _)| {
            name.to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("BONSAI_")
        }) {
            return Err("Bonsai configuration is forbidden for this local proof host.");
        }
        if env::var_os("RISC0_PROVER") != Some(OsString::from("ipc")) {
            return Err("Set RISC0_PROVER=ipc explicitly; other routing is forbidden.");
        }
        if env::var_os("RISC0_EXECUTOR").is_some_and(|value| value != "ipc") {
            return Err("Only local IPC execution is permitted.");
        }
        if env::var_os("RISC0_PPROF_OUT").is_some() || env::var_os("RISC0_KECCAK_PO2").is_some() {
            return Err("Inherited profiler or execution overrides are forbidden.");
        }
        // The Groth16 subprocess writes intermediate seals and proofs here when
        // set. Its default private temporary directory is the only allowed path.
        if env::var_os("RISC0_WORK_DIR").is_some() {
            return Err("Inherited RISC0_WORK_DIR is forbidden for private proof material.");
        }
        // r0vm inherits process output and initializes its own tracing subscriber.
        if env::var_os("RUST_LOG") != Some(OsString::from("off")) {
            return Err("Set RUST_LOG=off to suppress inherited prover trace output.");
        }
        if env::var_os("RUST_BACKTRACE").is_some_and(|value| value != "0")
            || env::var_os("RUST_LIB_BACKTRACE").is_some_and(|value| value != "0")
        {
            return Err("Disable inherited backtraces before handling private proof inputs.");
        }
        let server_arg = env::var_os("RISC0_SERVER_PATH")
            .ok_or("Set an explicit absolute RISC0_SERVER_PATH.")?;
        let server_arg = PathBuf::from(server_arg);
        if !server_arg.is_absolute() {
            return Err("RISC0_SERVER_PATH must be absolute.");
        }
        let server_path = server_arg
            .canonicalize()
            .map_err(|_| "Cannot resolve the explicit r0vm executable.")?;
        if !server_path.is_file() {
            return Err("RISC0_SERVER_PATH must identify a regular executable file.");
        }
        let server_sha256 = inputs::sha256_bounded(&server_path, 512 * 1024 * 1024)?;
        if server_sha256 != expected_sha256 {
            return Err("Explicit r0vm executable differs from its approved SHA-256 pin.");
        }
        let version = Command::new(&server_path)
            .arg("--version")
            .output()
            .map_err(|_| "Cannot inspect the explicit r0vm version.")?;
        if !version.status.success()
            || version.stdout.len() > 4096
            || std::str::from_utf8(&version.stdout)
                .ok()
                .and_then(|text| text.split_whitespace().last())
                != Some(SDK_VERSION)
        {
            return Err("Explicit r0vm does not report the required 3.0.3 version.");
        }
        if groth16 {
            validate_local_docker()?;
        }
        Ok(Self {
            server_path,
            server_sha256,
        })
    }
}

fn parse_digest(value: PathBuf) -> HostResult<[u8; 32]> {
    let value = value
        .to_str()
        .ok_or("Artifact digest must be 64 lowercase hex characters.")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Artifact digest must be 64 lowercase hex characters.");
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| "Artifact digest must be 64 lowercase hex characters.")?;
    Ok(bytes)
}

fn validate_local_docker() -> HostResult<()> {
    // DOCKER_CONTEXT takes precedence over DOCKER_HOST. Inspect that exact
    // context so an inherited remote context cannot hide behind a local host.
    let context = env::var_os("DOCKER_CONTEXT");
    let endpoint = if context.is_none() && env::var_os("DOCKER_HOST").is_some() {
        let host = env::var_os("DOCKER_HOST").ok_or("Missing Docker endpoint.")?;
        host.into_string()
            .map_err(|_| "Invalid Docker endpoint encoding.")?
    } else {
        let context = match context {
            Some(context) => context,
            None => {
                let output = Command::new("docker")
                    .args(["context", "show"])
                    .output()
                    .map_err(|_| "Cannot inspect the selected Docker context.")?;
                if !output.status.success() || output.stdout.len() > 4096 {
                    return Err("Cannot inspect the selected Docker context.");
                }
                let context = String::from_utf8(output.stdout)
                    .map_err(|_| "Invalid Docker context encoding.")?;
                OsString::from(context.trim())
            }
        };
        let output = Command::new("docker")
            .args([
                "context",
                "inspect",
                "--format",
                "{{.Endpoints.docker.Host}}",
            ])
            .arg(context)
            .output()
            .map_err(|_| "Cannot inspect the selected local Docker endpoint.")?;
        if !output.status.success() || output.stdout.len() > 4096 {
            return Err("Cannot inspect the selected local Docker endpoint.");
        }
        String::from_utf8(output.stdout).map_err(|_| "Invalid Docker endpoint encoding.")?
    };
    let endpoint = endpoint.trim();
    if !endpoint.starts_with("unix:///") && !endpoint.starts_with("npipe:////./pipe/") {
        return Err("Groth16 requires a local Docker socket; remote endpoints are forbidden.");
    }
    Ok(())
}
