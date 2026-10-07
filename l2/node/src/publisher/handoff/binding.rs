//! Ledger binding uses retained durable attempts, never a wallet's asserted flag.
use super::{
    document::sha,
    operation::{decode_hex, operation_policy_hash},
    types::*,
};
use crate::publisher::{AuditKind, PublisherSnapshot};
use alephium_l2_sdk::alephium::{
    FundingModel, FundingPin, LocalScriptApproval, MAX_UNSIGNED_BYTES, ValidatedUnsignedAlephium,
    approve_operation,
    current_funding::{
        CreatorScriptRegistry, CurrentFundingPolicy, observe_current_fixed_funding,
        validate_current_unsigned,
    },
    read_node::ReadNode,
    unsigned_input_refs,
};

/// Only a request matched against the actual durable ledger can be used by the
/// restart/import helpers. File DTO deserialization cannot construct this type.
pub struct BoundRequest {
    pub(super) document: RequestDocument,
}
impl BoundRequest {
    pub fn document(&self) -> &RequestDocument {
        &self.document
    }

    /// Explicit current-mode restart: this call performs the configured node's
    /// read-only observations. It never falls back to an exact-head snapshot or
    /// changes the retained funding model, static policy or unsigned bytes.
    pub fn revalidate_current_unsigned(
        &self,
        fresh_funding: FundingPin,
        approval: &impl LocalScriptApproval,
        node: &ReadNode,
        policy: &CurrentFundingPolicy,
        registry: &impl CreatorScriptRegistry,
    ) -> Result<ValidatedUnsignedAlephium, HandoffError> {
        let request = &self.document;
        request.validate()?;
        if fresh_funding.model != FundingModel::CanonicalFixedCurrentV1 {
            return Err(HandoffError::Binding);
        }
        let record = &request.body.operation;
        let spec = record.spec(fresh_funding)?;
        let approved =
            approve_operation(spec, approval).map_err(|_| HandoffError::SdkValidation)?;
        let binding = &request.body.binding;
        if operation_policy_hash(&approved) != binding.operation_policy_sha256
            || approved.script_bytes().map(hex::encode) != record.approved_script_hex
        {
            return Err(HandoffError::Binding);
        }
        let raw = decode_hex(&request.body.unsigned_hex, MAX_UNSIGNED_BYTES)?;
        let references =
            unsigned_input_refs(&approved, &raw).map_err(|_| HandoffError::SdkValidation)?;
        let funding = observe_current_fixed_funding(&approved, &references, node, policy, registry)
            .map_err(|_| HandoffError::SdkValidation)?;
        let unsigned = validate_current_unsigned(&approved, &funding, &raw)
            .map_err(|_| HandoffError::SdkValidation)?;
        if unsigned.intent_id() != binding.intent_id
            || unsigned.operation_id() != binding.operation_id
            || unsigned.publication_scope() != binding.scope_id
            || unsigned.tx_id() != binding.tx_id
            || sha(unsigned.unsigned_bytes()) != binding.unsigned_sha256
            || unsigned.unsigned_bytes() != raw
        {
            return Err(HandoffError::Binding);
        }
        Ok(unsigned)
    }
}

pub(super) fn bind(
    document: RequestDocument,
    snapshot: &PublisherSnapshot,
) -> Result<BoundRequest, HandoffError> {
    document.validate()?;
    crate::publisher::codec::validate_snapshot(snapshot)?;
    let binding = &document.body.binding;
    let row = snapshot
        .records
        .iter()
        .find(|record| record.intent.id == binding.intent_id)
        .ok_or(HandoffError::Binding)?;
    let kind = match binding.kind {
        RequestKind::Sign => AuditKind::SignAttempt,
        RequestKind::Submit => AuditKind::SubmitAttempt,
    };
    let audit = snapshot
        .history
        .iter()
        .find(|event| event.revision == binding.attempt.revision)
        .ok_or(HandoffError::Binding)?;
    if audit.kind != kind
        || audit.intent_id != Some(binding.intent_id)
        || audit.fencing_epoch != binding.attempt.fencing_epoch
        || audit.canonical_head != binding.attempt.canonical_head
        || document.body.scope != snapshot.scope
        || binding.scope_id != snapshot.scope.identity()?
        || row.intent.operation_id != binding.operation_id
        || row.intent.tx_id != binding.tx_id
        || row.intent.network != binding.network_id
        || row.intent.l1_genesis != binding.network_genesis_id
        || row.intent.authority_key != decode_hex(&binding.authority_key_hex, 33)?
        || row.intent.operation_policy_sha256 != binding.operation_policy_sha256
        || row.intent.unsigned
            != decode_hex(
                &document.body.unsigned_hex,
                alephium_l2_sdk::alephium::MAX_UNSIGNED_BYTES,
            )?
        || sha(&row.intent.unsigned) != binding.unsigned_sha256
        || row.sign_attempts != 1
    {
        return Err(HandoffError::Binding);
    }
    if binding.kind == RequestKind::Submit {
        let signature = row.signature.as_deref().ok_or(HandoffError::Binding)?;
        if row.submit_attempts != 1
            || Some(sha(signature)) != binding.signature_sha256
            || Some(hex::encode(signature)) != document.body.signature_hex
        {
            return Err(HandoffError::Binding);
        }
    }
    Ok(BoundRequest { document })
}
