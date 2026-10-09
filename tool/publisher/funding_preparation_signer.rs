//! Dedicated native funding-preparation signing; no factory scope or broadcast.
//! The controller loads the committed SignAttempted record and refreshes source
//! evidence before calling. Deserialized DATA alone is never durable authority.
use crate::configured_signer_env as configuration;

use crate::funding_preparation::{FundingPreparationPhase, FundingPreparationRecord};
pub use crate::publisher::configured_signer::ConfiguredSignerError;
use alephium_l2_sdk::alephium::{
    FundingModel, FundingPin, OutputRef, alephium_hash,
    funding_preparation::{
        FUNDING_PREPARATION_GAS, FUNDING_PREPARATION_GAS_PRICE, FUNDING_PREPARATION_PROFILE,
        FundingPreparationOutput, FundingPreparationSpec, ValidatedFundingPreparation,
        verify_funding_preparation_signature,
    },
    publisher_address_from_public_key,
    read_node::P2pkhAddress,
};
use alloy_primitives::{B256, U256};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::path::Path;

/// Safe classifications only: no keys, identities, signatures or raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingPreparationSignerError {
    Disabled,
    RecordMismatch,
    Consumed,
    InvalidSignature,
}

impl std::fmt::Display for FundingPreparationSignerError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Disabled => "Funding preparation signer is disabled",
            Self::RecordMismatch => "Funding preparation differs from approved durable attempt",
            Self::Consumed => "Funding preparation signing attempt is consumed",
            Self::InvalidSignature => "Funding preparation signature validation failed",
        })
    }
}
impl std::error::Error for FundingPreparationSignerError {}

/// One operator-selected purpose. No Debug, Clone, serialization or generic
/// digest-signing API. Persistent attempt/restart authority remains in Store.
pub struct FundingPreparationSigner {
    expected: FundingPreparationSpec,
    key: Option<SecretKey>,
    consumed: bool,
}

impl Drop for FundingPreparationSigner {
    fn drop(&mut self) {
        // Best effort only; compiler/runtime copies are not guaranteed erased.
        if let Some(key) = &mut self.key {
            key.non_secure_erase();
        }
    }
}

struct NativeFacts<'a> {
    spec: &'a FundingPreparationSpec,
    pin: &'a FundingPin,
    raw: &'a [u8],
    transaction_id: B256,
    inputs: &'a [OutputRef],
    input_amount: U256,
    fee: U256,
    outputs: &'a [FundingPreparationOutput],
}

impl<'a> NativeFacts<'a> {
    fn from_cap(cap: &'a ValidatedFundingPreparation) -> Self {
        Self {
            spec: cap.spec(),
            pin: cap.pin(),
            raw: cap.unsigned_bytes(),
            transaction_id: cap.tx_id(),
            inputs: cap.input_refs(),
            input_amount: cap.input_amount(),
            fee: cap.fee(),
            outputs: cap.outputs(),
        }
    }
}

impl FundingPreparationSigner {
    /// Read one bounded root-env snapshot. Revoking the interlock requires the
    /// controller to drop/recreate this signer; it never polls process env.
    pub fn from_env(
        path: &Path,
        expected: FundingPreparationSpec,
        explicitly_enabled: bool,
    ) -> Result<Self, ConfiguredSignerError> {
        let bytes = configuration::read(path)?;
        Self::from_text(bytes.text()?, expected, explicitly_enabled)
    }

    fn from_text(
        text: &str,
        expected: FundingPreparationSpec,
        explicitly_enabled: bool,
    ) -> Result<Self, ConfiguredSignerError> {
        use ConfiguredSignerError as Error;
        if [
            expected.purpose_id,
            expected.operator_source,
            expected.network_genesis_id,
            expected.funding_source_id,
        ]
        .contains(&B256::ZERO)
            || expected.gas_amount != FUNDING_PREPARATION_GAS
            || expected.gas_price != U256::from(FUNDING_PREPARATION_GAS_PRICE)
        {
            return Err(Error::InvalidScope);
        }
        let owner = publisher_address_from_public_key(&expected.caller_public_key)
            .map_err(|_| Error::AccountMismatch)?;
        if owner.group() != 0 {
            return Err(Error::AccountMismatch);
        }
        let values = configuration::parse(text)?;
        let value = |name| values.get(name).copied().ok_or(Error::InvalidConfiguration);
        if value("L2_P5_L1_NETWORK_ID")? != "1"
            || value("L2_P5_L1_GROUP")? != "0"
            || values
                .get("ALEPHIUM_NETWORK_ID")
                .is_some_and(|value| *value != "1")
        {
            return Err(Error::InvalidScope);
        }
        let public = value("L2_P5_PUBLISHER_PUBLIC_KEY")?;
        let public = public.strip_prefix("0x").unwrap_or(public);
        let public: [u8; 33] = hex::decode(public)
            .map_err(|_| Error::AccountMismatch)?
            .try_into()
            .map_err(|_| Error::AccountMismatch)?;
        let address = P2pkhAddress::parse(value("L2_P5_PUBLISHER_ADDRESS")?)
            .map_err(|_| Error::AccountMismatch)?;
        if public != expected.caller_public_key || address != owner {
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
            expected,
            key,
            consumed: false,
        })
    }

    pub fn enabled(&self) -> bool {
        self.key.is_some()
    }

    /// Only a live validated capability plus the exact loaded durable record is
    /// accepted. The signer never creates Planned/SignAttempted or renews input
    /// availability, and a crash requires reconciliation, not another callback.
    pub fn sign(
        &mut self,
        record: &FundingPreparationRecord,
        cap: &ValidatedFundingPreparation,
    ) -> Result<Vec<u8>, FundingPreparationSignerError> {
        if cap.profile() != FUNDING_PREPARATION_PROFILE {
            return Err(FundingPreparationSignerError::RecordMismatch);
        }
        let signature = self.sign_facts(record, &NativeFacts::from_cap(cap))?;
        verify_funding_preparation_signature(cap, &signature)
            .map_err(|_| FundingPreparationSignerError::InvalidSignature)?;
        Ok(signature)
    }

    fn matches(&self, record: &FundingPreparationRecord, facts: &NativeFacts<'_>) -> bool {
        let actual = &record.immutable;
        let spec = facts.spec;
        let pin = facts.pin;
        let expected = &self.expected;
        record.schema == 1
            && record.revision >= 2
            && record.phase == FundingPreparationPhase::SignAttempted
            && record.sign_attempts == 1
            && record.submit_attempts == 0
            && record.signature.is_none()
            && record.inclusion.is_none()
            && actual
                .minimum_confirmations
                .iter()
                .all(|minimum| *minimum >= 6)
            && actual.network == 1
            && spec.purpose_id == expected.purpose_id
            && spec.operator_source == expected.operator_source
            && spec.caller_public_key == expected.caller_public_key
            && spec.network_genesis_id == expected.network_genesis_id
            && spec.funding_source_id == expected.funding_source_id
            && spec.gas_amount == expected.gas_amount
            && spec.gas_price == expected.gas_price
            && pin.model == FundingModel::CanonicalFixedCurrentV1
            && pin.network_id == 1
            && pin.group == 0
            && pin.group_count == 4
            && pin.head_hash != B256::ZERO
            && pin.network_genesis_id == expected.network_genesis_id
            && pin.source_id == expected.funding_source_id
            && actual.purpose_id == spec.purpose_id
            && actual.operator_source == spec.operator_source
            && actual.caller_public_key.as_slice() == spec.caller_public_key.as_slice()
            && actual.network_genesis_id == spec.network_genesis_id
            && actual.funding_source_id == spec.funding_source_id
            && actual.gas_amount == spec.gas_amount
            && actual.gas_price == spec.gas_price
            && actual.unsigned.as_slice() == facts.raw
            && actual.transaction_id == facts.transaction_id
            && facts.transaction_id != B256::ZERO
            && alephium_hash(facts.raw) == facts.transaction_id
            && actual.input_amount == facts.input_amount
            && actual.fee == facts.fee
            && facts.inputs.len() == 1
            && actual.input_refs.len() == 1
            && actual.input_refs[0].native() == facts.inputs[0]
            && facts.outputs.len() == 4
            && actual.outputs.len() == 4
            && actual
                .outputs
                .iter()
                .zip(facts.outputs)
                .all(|(stored, output)| {
                    stored.index == output.index()
                        && stored.reference.native() == output.reference()
                        && stored.amount == output.amount()
                        && stored.owner_hash == output.owner_hash()
                        && stored.lock_time_ms == 0
                })
    }

    fn sign_facts(
        &mut self,
        record: &FundingPreparationRecord,
        facts: &NativeFacts<'_>,
    ) -> Result<Vec<u8>, FundingPreparationSignerError> {
        use FundingPreparationSignerError as Error;
        if !self.enabled() {
            return Err(Error::Disabled);
        }
        if self.consumed {
            return Err(Error::Consumed);
        }
        if !self.matches(record, facts) {
            return Err(Error::RecordMismatch);
        }
        self.consumed = true; // Consume before secp work, including verification failure.
        let key = self.key.as_ref().ok_or(Error::Disabled)?;
        let mut signature =
            Secp256k1::signing_only().sign_ecdsa(Message::from_digest(facts.transaction_id.0), key);
        signature.normalize_s();
        Ok(signature.serialize_compact().to_vec())
    }
}

impl crate::funding_preparation_service::PreparationSigner for FundingPreparationSigner {
    fn sign(
        &mut self,
        durable: &FundingPreparationRecord,
        cap: &ValidatedFundingPreparation,
    ) -> Result<Vec<u8>, crate::funding_preparation_service::PreparationExternalError> {
        use crate::funding_preparation_service::PreparationExternalError as External;
        FundingPreparationSigner::sign(self, durable, cap).map_err(|error| match error {
            FundingPreparationSignerError::Disabled => External::Disabled,
            FundingPreparationSignerError::RecordMismatch => External::Rejected,
            FundingPreparationSignerError::Consumed => External::Consumed,
            FundingPreparationSignerError::InvalidSignature => External::InvalidSignature,
        })
    }
}

#[cfg(test)]
#[path = "../../test/publisher/funding_preparation_signer_checks.rs"]
mod checks;

#[cfg(test)]
pub fn run_funding_preparation_signer_checks() -> usize {
    checks::run_checks()
}
