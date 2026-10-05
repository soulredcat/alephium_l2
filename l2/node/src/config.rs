use crate::protocol::{CHAIN_ID, Genesis, validate_chain_id};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

const MAX_GENESIS_BYTES: u64 = 1_048_576;

pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub genesis: Genesis,
}

impl Config {
    pub fn parse() -> Result<Self, String> {
        let mut args = std::env::args().skip(1);
        let mut listen: SocketAddr = "127.0.0.1:19545".parse().expect("constant address");
        let mut data_dir = PathBuf::from(".local/l2-next-development");
        let mut genesis_file = None;
        let mut chain_id = CHAIN_ID;
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
        Ok(Self {
            listen,
            data_dir,
            genesis,
        })
    }
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
