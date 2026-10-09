//! Scoped native publisher signing. Only Publisher may dispatch this callback
//! after its durable SignAttempt; this tool never broadcasts or writes responses.
use crate::configured_signer_env as configuration;

use crate::publisher::{ExternalFailure, ExternalSigner, Scope, Token};
use alephium_l2_sdk::alephium::{
    ValidatedUnsignedAlephium, alephium_hash, publisher_address_from_public_key,
    read_node::P2pkhAddress, verify_detached_signature,
};
use alloy_primitives::B256;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::{collections::BTreeSet, path::Path};

/// Metadata-only failures; never attach an env value, account or key to them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfiguredSignerError {
    InvalidEnvironmentPath,
    EnvironmentUnavailable,
    EnvironmentChanged,
    UnsupportedPlatform,
    InvalidConfiguration,
    InvalidScope,
    AccountMismatch,
    InvalidPublisherKey,
}

impl std::fmt::Display for ConfiguredSignerError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::InvalidEnvironmentPath => "Signer requires the authoritative repository env",
            Self::EnvironmentUnavailable => "Signer environment is unavailable",
            Self::EnvironmentChanged => "Signer environment changed during bounded read",
            Self::UnsupportedPlatform => "Safe signer environment opening is unsupported",
            Self::InvalidConfiguration => "Signer configuration is incomplete or invalid",
            Self::InvalidScope => "Signer approval scope is invalid",
            Self::AccountMismatch => "Dedicated publisher account differs from configured scope",
            Self::InvalidPublisherKey => "Dedicated publisher key is invalid",
        })
    }
}
impl std::error::Error for ConfiguredSignerError {}

/// No Debug/Serialize/Clone. The key remains scoped memory, not a wallet backend.
/// Durable once-only/restart authority belongs to Publisher, not this local set.
pub struct ConfiguredNativeSigner {
    scope: Scope,
    scope_id: B256,
    key: Option<SecretKey>,
    group: u8,
    used_intents: BTreeSet<B256>,
    used_operations: BTreeSet<B256>,
    used_transactions: BTreeSet<B256>,
    last_revision: u64,
    last_fence: u64,
}

impl Drop for ConfiguredNativeSigner {
    fn drop(&mut self) {
        // The pinned library exposes best-effort erasure; this is not a claim
        // that compiler/runtime copies or all process memory are zeroized.
        if let Some(key) = &mut self.key {
            key.non_secure_erase();
        }
    }
}

impl ConfiguredNativeSigner {
    /// Read one bounded env snapshot. The driver must drop/recreate this signer
    /// when revoking its explicit authority or changing the signing interlock.
    pub fn from_env(
        path: &Path,
        expected_scope: Scope,
        explicitly_enabled: bool,
    ) -> Result<Self, ConfiguredSignerError> {
        let bytes = configuration::read(path)?;
        Self::from_text(bytes.text()?, expected_scope, explicitly_enabled)
    }

    fn from_text(
        text: &str,
        scope: Scope,
        explicitly_enabled: bool,
    ) -> Result<Self, ConfiguredSignerError> {
        use ConfiguredSignerError as Error;
        let scope_id = scope.identity().map_err(|_| Error::InvalidScope)?;
        let values = configuration::parse(text)?;
        let value = |name| values.get(name).copied().ok_or(Error::InvalidConfiguration);
        let number = |name| {
            let text = value(name)?;
            if !text.bytes().all(|byte| byte.is_ascii_digit())
                || text.len() > 1 && text.starts_with('0')
            {
                return Err(Error::InvalidConfiguration);
            }
            text.parse::<u8>().map_err(|_| Error::InvalidConfiguration)
        };
        let network = number("L2_P5_L1_NETWORK_ID")?;
        let group = number("L2_P5_L1_GROUP")?;
        if network != scope.l1_network
            || group >= 4
            || values.contains_key("ALEPHIUM_NETWORK_ID")
                && number("ALEPHIUM_NETWORK_ID")? != network
        {
            return Err(Error::InvalidScope);
        }
        let public_text = value("L2_P5_PUBLISHER_PUBLIC_KEY")?;
        let public_text = public_text.strip_prefix("0x").unwrap_or(public_text);
        let public: [u8; 33] = hex::decode(public_text)
            .map_err(|_| Error::AccountMismatch)?
            .try_into()
            .map_err(|_| Error::AccountMismatch)?;
        let owner =
            publisher_address_from_public_key(&public).map_err(|_| Error::AccountMismatch)?;
        let address = P2pkhAddress::parse(value("L2_P5_PUBLISHER_ADDRESS")?)
            .map_err(|_| Error::AccountMismatch)?;
        if public.as_slice() != scope.publisher_key.as_slice()
            || owner != address
            || owner.group() != group
        {
            return Err(Error::AccountMismatch);
        }
        let interlock = value("L2_P5_LIVE_SIGNING_ENABLED")?;
        if !matches!(interlock, "0" | "1") {
            return Err(Error::InvalidConfiguration);
        }
        let key = if explicitly_enabled && interlock == "1" {
            let secret = value("L2_P5_PUBLISHER_PRIVATE_KEY")?;
            let secret = secret.strip_prefix("0x").unwrap_or(secret);
            let mut scalar = [0; 32];
            let decoded = hex::decode_to_slice(secret, &mut scalar);
            if decoded.is_err() {
                scalar.fill(0);
                return Err(Error::InvalidPublisherKey);
            }
            let parsed = SecretKey::from_byte_array(scalar);
            scalar.fill(0);
            let mut parsed = parsed.map_err(|_| Error::InvalidPublisherKey)?;
            if PublicKey::from_secret_key(&Secp256k1::signing_only(), &parsed).serialize() != public
            {
                parsed.non_secure_erase();
                return Err(Error::AccountMismatch);
            }
            Some(parsed)
        } else {
            None
        };
        Ok(Self {
            scope,
            scope_id,
            key,
            group,
            used_intents: BTreeSet::new(),
            used_operations: BTreeSet::new(),
            used_transactions: BTreeSet::new(),
            last_revision: 0,
            last_fence: 0,
        })
    }

    fn check(&self, attempt: Token, unsigned: &ValidatedUnsignedAlephium) -> bool {
        let spec = unsigned.operation().spec();
        let pin = &spec.funding;
        attempt.revision != 0
            && attempt.fencing_epoch != 0
            && attempt.canonical_head != B256::ZERO
            && attempt.revision > self.last_revision
            && attempt.fencing_epoch >= self.last_fence
            && attempt.canonical_head == pin.head_hash
            && unsigned.publication_scope() == self.scope_id
            && spec.caller_public_key.as_slice() == self.scope.publisher_key.as_slice()
            && pin.network_id == self.scope.l1_network
            && pin.network_genesis_id == self.scope.l1_genesis
            && pin.source_id == self.scope.canonical_source
            && pin.group == self.group
            && pin.group_count == 4
            && [
                unsigned.intent_id(),
                unsigned.operation_id(),
                unsigned.tx_id(),
                spec.source_artifact_sha256,
            ]
            .iter()
            .all(|value| *value != B256::ZERO)
            && spec
                .script_blake2b256
                .is_some_and(|hash| hash != B256::ZERO)
            && alephium_hash(unsigned.unsigned_bytes()) == unsigned.tx_id()
            && !self.used_intents.contains(&unsigned.intent_id())
            && !self.used_operations.contains(&unsigned.operation_id())
            && !self.used_transactions.contains(&unsigned.tx_id())
            && self.used_transactions.len() < crate::publisher::types::MAX_PUBLICATIONS
    }
}

impl ExternalSigner for ConfiguredNativeSigner {
    fn enabled(&self) -> bool {
        self.key.is_some()
    }

    fn sign(
        &mut self,
        attempt: Token,
        unsigned: &ValidatedUnsignedAlephium,
    ) -> Result<Vec<u8>, ExternalFailure> {
        if !self.enabled() {
            return Err(ExternalFailure::Disabled);
        }
        if !self.check(attempt, unsigned) {
            return Err(ExternalFailure::Rejected);
        }
        // Consume before cryptographic work. Rejection/restart cannot recreate
        // a durable permission; Publisher still owns persistent attempt counts.
        self.used_intents.insert(unsigned.intent_id());
        self.used_operations.insert(unsigned.operation_id());
        self.used_transactions.insert(unsigned.tx_id());
        self.last_revision = attempt.revision;
        self.last_fence = attempt.fencing_epoch;
        let key = self.key.as_ref().ok_or(ExternalFailure::Disabled)?;
        let mut signature =
            Secp256k1::signing_only().sign_ecdsa(Message::from_digest(unsigned.tx_id().0), key);
        signature.normalize_s();
        let compact = signature.serialize_compact();
        verify_detached_signature(unsigned, &compact).map_err(|_| ExternalFailure::Rejected)?;
        Ok(compact.to_vec())
    }
}

#[cfg(test)]
#[path = "../../test/publisher/configured_signer_checks.rs"]
mod checks;

#[cfg(test)]
pub fn run_configured_signer_checks() -> usize {
    checks::run_checks()
}
