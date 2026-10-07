//! Explicit offline response import. No signature request or submission is made.
use super::{
    adapter::FileOutbox,
    binding::BoundRequest,
    document::sha,
    operation::{decode_hex, operation_policy_hash},
    repository,
    types::*,
};
use crate::publisher::{Publisher, Repository, Token};
use alephium_l2_sdk::alephium::{
    CanonicalFundingSource, FundingPin, LocalScriptApproval, ValidatedSignedAlephium,
    ValidatedUnsignedAlephium, approve_operation, observe_funding, unsigned_input_refs,
    validate_detached_signature, validate_unsigned,
};
use alloy_primitives::B256;
use std::path::Path;

impl BoundRequest {
    /// Rebuild capabilities on restart using independently configured approval
    /// and current canonical funding sources. Saved metadata is not approval.
    /// The caller may renew ONLY the funding head/hash-height/time; the persisted
    /// operation-policy digest and exact unsigned bytes must remain unchanged.
    pub fn revalidate_unsigned(
        &self,
        fresh_funding: FundingPin,
        approval: &impl LocalScriptApproval,
        source: &impl CanonicalFundingSource,
    ) -> Result<ValidatedUnsignedAlephium, HandoffError> {
        let request = &self.document;
        request.validate()?;
        let record = &request.body.operation;
        let spec = record.spec(fresh_funding)?;
        let approved =
            approve_operation(spec, approval).map_err(|_| HandoffError::SdkValidation)?;
        if operation_policy_hash(&approved) != request.body.binding.operation_policy_sha256
            || approved.script_bytes().map(hex::encode) != record.approved_script_hex
        {
            return Err(HandoffError::Binding);
        }
        let raw = decode_hex(
            &request.body.unsigned_hex,
            alephium_l2_sdk::alephium::MAX_UNSIGNED_BYTES,
        )?;
        let references =
            unsigned_input_refs(&approved, &raw).map_err(|_| HandoffError::SdkValidation)?;
        let funding = observe_funding(&approved, &references, source)
            .map_err(|_| HandoffError::SdkValidation)?;
        let unsigned = validate_unsigned(&approved, &funding, &raw)
            .map_err(|_| HandoffError::SdkValidation)?;
        match_unsigned(request, &unsigned)?;
        Ok(unsigned)
    }
}

impl FileOutbox {
    /// Import one exact response against the current ledger. A normal head
    /// advance uses a freshly revalidated capability for the SAME unsigned bytes
    /// and policy. The response still echoes the original durable attempt token.
    pub fn import_signature<R: Repository>(
        &self,
        publisher: &mut Publisher<R>,
        expected: Token,
        request_identity: B256,
        response_path: &Path,
        fresh: ValidatedUnsignedAlephium,
        now_ms: u64,
    ) -> Result<(Token, ValidatedSignedAlephium), HandoffError> {
        let snapshot = publisher.snapshot(expected)?;
        let request = self.load_request(request_identity, &snapshot)?;
        if request.document.body.binding.kind != RequestKind::Sign {
            return Err(HandoffError::Binding);
        }
        match_unsigned(&request.document, &fresh)?;
        if fresh.operation().spec().funding.head_hash != snapshot.canonical_head {
            return Err(HandoffError::Binding);
        }
        let response: ResponseDocument = repository::read_document(response_path)?;
        response.validate(&request.document)?;
        let signature = match &response.body.outcome {
            ResponseOutcome::Signed { signature_hex } => decode_hex(signature_hex, 64)?,
            ResponseOutcome::Cancelled => return Err(HandoffError::Cancelled),
            ResponseOutcome::SubmissionAcknowledged => return Err(HandoffError::Binding),
        };
        let signed = validate_detached_signature(fresh, &signature)
            .map_err(|_| HandoffError::SdkValidation)?;
        let token = publisher.record_signed(expected, &signed, now_ms)?;
        Ok((token, signed))
    }

    /// An external submission acknowledgement is an audit fact only. It cannot
    /// set Submitted/Included/Confirmed, release inputs, or permit another submit.
    /// The existing ambiguous record is resolved only by CanonicalSource checks.
    pub fn inspect_submission_response<R: Repository>(
        &self,
        publisher: &mut Publisher<R>,
        expected: Token,
        request_identity: B256,
        response_path: &Path,
    ) -> Result<SubmissionAcknowledgement, HandoffError> {
        let snapshot = publisher.snapshot(expected)?;
        let request = self.load_request(request_identity, &snapshot)?;
        if request.document.body.binding.kind != RequestKind::Submit {
            return Err(HandoffError::Binding);
        }
        let response: ResponseDocument = repository::read_document(response_path)?;
        response.validate(&request.document)?;
        match response.body.outcome {
            ResponseOutcome::SubmissionAcknowledged => Ok(SubmissionAcknowledgement {
                request_identity,
                tx_id: request.document.body.binding.tx_id,
            }),
            ResponseOutcome::Cancelled => Err(HandoffError::Cancelled),
            ResponseOutcome::Signed { .. } => Err(HandoffError::Binding),
        }
    }
}

fn match_unsigned(
    request: &RequestDocument,
    unsigned: &ValidatedUnsignedAlephium,
) -> Result<(), HandoffError> {
    let binding = &request.body.binding;
    if unsigned.intent_id() != binding.intent_id
        || unsigned.operation_id() != binding.operation_id
        || unsigned.publication_scope() != binding.scope_id
        || unsigned.tx_id() != binding.tx_id
        || sha(unsigned.unsigned_bytes()) != binding.unsigned_sha256
        || hex::encode(unsigned.unsigned_bytes()) != request.body.unsigned_hex
        || operation_policy_hash(unsigned.operation()) != binding.operation_policy_sha256
        || hex::encode(unsigned.operation().spec().caller_public_key) != binding.authority_key_hex
    {
        return Err(HandoffError::Binding);
    }
    Ok(())
}
