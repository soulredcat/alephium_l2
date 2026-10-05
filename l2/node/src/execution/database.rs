use crate::storage::ReadView;
use alloy_primitives::{Address, B256, U256, keccak256};
use revm::database_interface::{DBErrorMarker, DatabaseRef};
use revm::primitives::KECCAK_EMPTY;
use revm::state::{AccountInfo, Bytecode};
use std::fmt;

/// A pinned committed view is immutable; CacheDB supplies the warm private layer.
pub(super) struct ViewDatabase(pub ReadView);

#[derive(Debug)]
pub(super) struct ReadError(pub String);

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ReadError {}
impl DBErrorMarker for ReadError {}

impl DatabaseRef for ViewDatabase {
    type Error = ReadError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.0.account(address).map_err(ReadError).map(|account| {
            account.map(|account| AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                code: None,
                ..Default::default()
            })
        })
    }

    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        if hash == KECCAK_EMPTY || hash == B256::ZERO {
            return Ok(Bytecode::default());
        }
        let code = self.0.code(hash).map_err(ReadError)?;
        if keccak256(&code) != hash {
            return Err(ReadError("stored code does not match its identity".into()));
        }
        Ok(Bytecode::new_raw(code.into()))
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.0.slot(address, slot).map_err(ReadError)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.0.block_hash(number).map_err(ReadError)
    }
}
