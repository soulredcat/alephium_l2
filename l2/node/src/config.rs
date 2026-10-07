use crate::operator::MAX_CONTINUATION_CHECKPOINT_BYTES;
use crate::protocol::{CHAIN_ID, Genesis, validate_chain_id};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

const MAX_GENESIS_BYTES: u64 = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationBackend {
    Cpu,
    Cuda,
}

impl VerificationBackend {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "cpu" => Ok(Self::Cpu),
            "cuda" => Ok(Self::Cuda),
            _ => Err("Verification backend must be cpu or cuda".into()),
        }
    }
}

pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub genesis: Genesis,
    /// Admission-only floor on the effective gas price; not a consensus rule.
    pub min_gas_price: u128,
    /// Producer checkpoint budget, including reserved hash-window growth.
    /// Expanded development profiles do not imply proof transport acceptance.
    pub max_checkpoint_bytes: usize,
    pub rpc: crate::rpc::RpcLimits,
    /// Independent signature workers per available CPU budget; state stays ordered.
    pub verification_workers_per_cpu: usize,
    pub verification_backend: VerificationBackend,
    pub gpu_device: usize,
}

impl Config {
    pub fn parse() -> Result<Self, String> {
        let mut args = std::env::args().skip(1);
        let mut listen: SocketAddr = "127.0.0.1:19545".parse().expect("constant address");
        let mut data_dir = PathBuf::from(".local/l2-next-development");
        let mut genesis_file = None;
        let mut chain_id = CHAIN_ID;
        let mut min_gas_price = 0;
        let mut max_checkpoint_bytes = MAX_CONTINUATION_CHECKPOINT_BYTES;
        let mut rpc = crate::rpc::RpcLimits::default();
        let mut verification_workers_per_cpu = 1;
        let mut verification_backend = if cfg!(feature = "cuda") {
            VerificationBackend::Cuda
        } else {
            VerificationBackend::Cpu
        };
        let mut gpu_device = 0;
        let mut options = BTreeSet::new();
        while let Some(arg) = args.next() {
            if !options.insert(arg.clone()) {
                return Err(format!("Duplicate option: {arg}"));
            }
            let value = args
                .next()
                .ok_or_else(|| format!("Missing value for {arg}"))?;
            match arg.as_str() {
                "--listen" => listen = value.parse().map_err(|_| "Invalid listen address")?,
                "--data-dir" => data_dir = value.into(),
                "--genesis" => genesis_file = Some(PathBuf::from(value)),
                "--chain-id" => chain_id = parse_chain_id(&value)?,
                "--min-gas-price" => min_gas_price = parse_gas_price(&value)?,
                "--max-checkpoint-bytes" => max_checkpoint_bytes = parse_checkpoint_bytes(&value)?,
                "--rpc-inflight" => rpc.request_inflight = positive_count(&value)?,
                "--rpc-body-bytes" => rpc.request_bytes = positive_count(&value)?,
                "--rpc-read-inflight" => rpc.read_inflight = positive_count(&value)?,
                "--rpc-simulations" => rpc.simulation_inflight = positive_count(&value)?,
                "--rpc-batch-calls" => rpc.batch_calls = positive_count(&value)?,
                "--rpc-response-bytes" => rpc.response_bytes = positive_count(&value)?,
                "--verification-workers-per-cpu" => {
                    verification_workers_per_cpu = positive_count(&value)?
                }
                "--verification-backend" => {
                    verification_backend = VerificationBackend::parse(&value)?
                }
                "--gpu-device" => {
                    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err("GPU device must be a nonnegative decimal ordinal".into());
                    }
                    gpu_device = value.parse().map_err(|_| "GPU device exceeds usize")?;
                }
                _ => return Err(format!("Unknown option: {arg}")),
            }
        }
        if !listen.ip().is_loopback() {
            return Err("Development runtime must bind to loopback".into());
        }
        if data_dir.as_os_str().is_empty() {
            return Err("Explicit owned development data directory required".into());
        }
        let path = genesis_file.ok_or("Pass --genesis <fresh-development-genesis.json>")?;
        let genesis = load_genesis(&path, chain_id)?;
        let maximum = genesis.capacity.producer_checkpoint_bytes()?;
        if !(1..=maximum).contains(&max_checkpoint_bytes) {
            return Err(format!(
                "Checkpoint capacity must be from 1 to {maximum} bytes for this genesis"
            ));
        }
        rpc.validate()?;
        Ok(Self {
            listen,
            data_dir,
            genesis,
            min_gas_price,
            max_checkpoint_bytes,
            rpc,
            verification_workers_per_cpu,
            verification_backend,
            gpu_device,
        })
    }
}

fn positive_count(value: &str) -> Result<usize, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("RPC capacity must be a positive decimal integer".into());
    }
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| "RPC capacity must be a positive usize".into())
}

/// Capacity belongs to a fresh genesis, never an override of persisted state.
pub fn genesis_command(args: &[String]) -> Result<(PathBuf, Genesis), String> {
    let path = args.get(2).filter(|path| !path.is_empty())
        .ok_or("Usage: --make-genesis <new-file> [--chain-id <id>] [--block-gas <gas>] [--block-bytes <bytes>] [--max-pending <count>]")?;
    let mut genesis = crate::development::genesis();
    let mut options = BTreeSet::new();
    let mut values = args[3..].iter();
    while let Some(option) = values.next() {
        if !options.insert(option) {
            return Err(format!("Duplicate genesis option: {option}"));
        }
        let value = values
            .next()
            .ok_or_else(|| format!("Missing value for {option}"))?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("{option} requires a positive decimal integer"));
        }
        match option.as_str() {
            "--chain-id" => genesis.chain_id = parse_chain_id(value)?,
            "--block-gas" => {
                genesis.capacity.block_gas = value.parse().map_err(|_| "Block gas exceeds u64")?
            }
            "--block-bytes" => {
                genesis.capacity.block_bytes =
                    value.parse().map_err(|_| "Block bytes exceeds usize")?
            }
            "--max-pending" => {
                genesis.capacity.max_pending =
                    value.parse().map_err(|_| "Pending count exceeds usize")?
            }
            _ => return Err(format!("Unknown genesis option: {option}")),
        }
    }
    genesis.validate()?;
    Ok((path.into(), genesis))
}

pub fn parse_checkpoint_bytes(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|bytes| {
            value.bytes().all(|byte| byte.is_ascii_digit())
                && *bytes > 0
                && *bytes <= u32::MAX as usize
        })
        .ok_or_else(|| {
            "Checkpoint capacity must be a positive decimal byte count fitting the storage format"
                .to_owned()
        })
}

pub fn parse_gas_price(value: &str) -> Result<u128, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Minimum gas price must be a decimal wei amount".into());
    }
    value
        .parse()
        .map_err(|_| "Minimum gas price exceeds u128".into())
}

pub fn parse_chain_id(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Chain identity must be a nonzero decimal u64".into());
    }
    let chain_id = value.parse().map_err(|_| "Chain identity exceeds u64")?;
    validate_chain_id(chain_id)?;
    Ok(chain_id)
}

/// Shared CLI preflight; storage independently validates the same genesis.
pub fn load_genesis(path: &Path, chain_id: u64) -> Result<Genesis, String> {
    validate_chain_id(chain_id)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_GENESIS_BYTES
    {
        return Err("Genesis must be a bounded regular development file".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_GENESIS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != metadata.len() {
        return Err("Genesis changed during its bounded read".into());
    }
    let genesis: Genesis =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid development genesis")?;
    genesis.validate()?;
    if genesis.chain_id != chain_id {
        return Err("Configured chain identity differs from development genesis".into());
    }
    Ok(genesis)
}
