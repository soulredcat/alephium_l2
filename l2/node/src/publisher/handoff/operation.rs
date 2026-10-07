//! Stable policy identity and restart DTO conversion, separate from capabilities.
use super::types::*;
use alephium_l2_sdk::alephium::{ApprovedOperation, FundingPin, OperationSpec, SpendLimits};
use alloy_primitives::B256;
use sha2::{Digest, Sha256};

/// Includes every static approved input, including exact source-approved script
/// bytes. Only canonical funding head/hash-height/time may be renewed later.
pub fn operation_policy_hash(operation: &ApprovedOperation) -> B256 {
    policy_hash(operation.spec(), operation.script_bytes())
}

fn policy_hash(spec: &OperationSpec, script: Option<&[u8]>) -> B256 {
    let mut hash = Sha256::new();
    hash.update(b"ALPH/L2/publisher-operation-policy/v1");
    let profile = alephium_l2_sdk::alephium::SUPPORTED_PROFILE.as_bytes();
    hash.update((profile.len() as u32).to_be_bytes());
    hash.update(profile);
    for value in [
        spec.intent_id,
        spec.operation_id,
        spec.publication_scope,
        spec.source_artifact_sha256,
    ] {
        hash.update(value);
    }
    match spec.script_blake2b256 {
        Some(value) => {
            hash.update([1]);
            hash.update(value);
        }
        None => hash.update([0]),
    }
    hash.update(spec.caller_public_key);
    hash.update([spec.funding.model as u8]);
    hash.update(spec.funding.source_id);
    hash.update([spec.funding.network_id]);
    hash.update(spec.funding.network_genesis_id);
    hash.update([spec.funding.group, spec.funding.group_count]);
    hash.update(spec.limits.min_gas_amount.to_be_bytes());
    hash.update(spec.limits.max_gas_amount.to_be_bytes());
    for value in [
        spec.limits.max_gas_price,
        spec.limits.max_fee,
        spec.limits.contract_deposit,
        spec.limits.max_total_debit,
        spec.limits.minimum_change,
    ] {
        hash.update(value.to_be_bytes::<32>());
    }
    match script {
        Some(script) => {
            hash.update([1]);
            hash.update((script.len() as u64).to_be_bytes());
            hash.update(script);
        }
        None => hash.update([0]),
    }
    B256::from_slice(&hash.finalize())
}

impl OperationRecord {
    pub(super) fn policy_hash(&self) -> Result<B256, HandoffError> {
        let spec = self.spec(self.funding.restore())?;
        let script = self
            .approved_script_hex
            .as_ref()
            .map(|value| decode_hex(value, alephium_l2_sdk::alephium::MAX_SCRIPT_BYTES))
            .transpose()?;
        Ok(policy_hash(&spec, script.as_deref()))
    }
    pub(super) fn capture(operation: &ApprovedOperation) -> Self {
        let spec = operation.spec();
        Self {
            intent_id: spec.intent_id,
            operation_id: spec.operation_id,
            publication_scope: spec.publication_scope,
            source_artifact_sha256: spec.source_artifact_sha256,
            script_blake2b256: spec.script_blake2b256,
            caller_public_key_hex: hex::encode(spec.caller_public_key),
            funding: FundingRecord::capture(&spec.funding),
            limits: SpendRecord::capture(&spec.limits),
            approved_script_hex: operation.script_bytes().map(hex::encode),
        }
    }

    /// Data reconstruction only. The caller MUST pass this through independent
    /// LocalScriptApproval and CanonicalFundingSource SDK validation afterwards.
    pub(super) fn spec(&self, fresh: FundingPin) -> Result<OperationSpec, HandoffError> {
        if fresh.model != self.funding.model
            || fresh.source_id != self.funding.source_id
            || fresh.network_id != self.funding.network_id
            || fresh.network_genesis_id != self.funding.network_genesis_id
            || fresh.group != self.funding.group
            || fresh.group_count != self.funding.group_count
        {
            return Err(HandoffError::Binding);
        }
        let key: [u8; 33] = decode_hex(&self.caller_public_key_hex, 33)?
            .try_into()
            .map_err(|_| HandoffError::Format)?;
        Ok(OperationSpec {
            intent_id: self.intent_id,
            operation_id: self.operation_id,
            publication_scope: self.publication_scope,
            source_artifact_sha256: self.source_artifact_sha256,
            script_blake2b256: self.script_blake2b256,
            caller_public_key: key,
            funding: fresh,
            limits: self.limits.restore(),
        })
    }
}
impl FundingRecord {
    fn capture(pin: &FundingPin) -> Self {
        Self {
            model: pin.model,
            source_id: pin.source_id,
            network_id: pin.network_id,
            network_genesis_id: pin.network_genesis_id,
            group: pin.group,
            group_count: pin.group_count,
            head_hash: pin.head_hash,
            head_height: pin.head_height,
            timestamp_ms: pin.timestamp_ms,
        }
    }
    pub fn restore(&self) -> FundingPin {
        FundingPin {
            model: self.model,
            source_id: self.source_id,
            network_id: self.network_id,
            network_genesis_id: self.network_genesis_id,
            group: self.group,
            group_count: self.group_count,
            head_hash: self.head_hash,
            head_height: self.head_height,
            timestamp_ms: self.timestamp_ms,
        }
    }
}
impl SpendRecord {
    fn capture(value: &SpendLimits) -> Self {
        Self {
            min_gas_amount: value.min_gas_amount,
            max_gas_amount: value.max_gas_amount,
            max_gas_price: value.max_gas_price,
            max_fee: value.max_fee,
            contract_deposit: value.contract_deposit,
            max_total_debit: value.max_total_debit,
            minimum_change: value.minimum_change,
        }
    }
    fn restore(&self) -> SpendLimits {
        SpendLimits {
            min_gas_amount: self.min_gas_amount,
            max_gas_amount: self.max_gas_amount,
            max_gas_price: self.max_gas_price,
            max_fee: self.max_fee,
            contract_deposit: self.contract_deposit,
            max_total_debit: self.max_total_debit,
            minimum_change: self.minimum_change,
        }
    }
}

pub(super) fn decode_hex(value: &str, maximum: usize) -> Result<Vec<u8>, HandoffError> {
    if !value.len().is_multiple_of(2) || value.len() / 2 > maximum {
        return Err(HandoffError::Bounds);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HandoffError::Format);
    }
    hex::decode(value).map_err(|_| HandoffError::Format)
}
