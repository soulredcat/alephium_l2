//! Persist-before-effect detached signing and one-shot submission.
use super::{
    service::{ExternalSigner, ExternalSubmitter, Publisher, row_mut},
    types::*,
};
use alephium_l2_sdk::alephium::{
    ValidatedSignedAlephium, ValidatedUnsignedAlephium, validate_detached_signature,
};

impl<R: Repository> Publisher<R> {
    pub fn sign(
        &mut self,
        expected: Token,
        unsigned: ValidatedUnsignedAlephium,
        signer: &mut impl ExternalSigner,
        now_ms: u64,
    ) -> Result<(Token, ValidatedSignedAlephium), PublisherError> {
        let mut next = self.state(expected, true)?;
        self.match_unsigned(&next, &unsigned)?;
        let id = unsigned.intent_id();
        let record = row_mut(&mut next, id)?;
        if record.phase != Phase::Intent || record.sign_attempts != 0 {
            return Err(PublisherError::InvalidTransition);
        }
        if !signer.enabled() {
            return Err(PublisherError::Disabled);
        }
        record.phase = Phase::SignAttempted;
        record.sign_attempts = 1;
        let attempted = self.persist(expected, next, AuditKind::SignAttempt, Some(id), now_ms)?;
        let response = signer.sign(attempted, &unsigned);
        let signed = match response {
            Ok(signature) => validate_detached_signature(unsigned, &signature)
                .map_err(|_| PublisherError::InvalidSignature),
            Err(_) => Err(PublisherError::Ambiguous),
        };
        match signed {
            Ok(signed) => {
                let token = self.record_signed(attempted, &signed, now_ms)?;
                Ok((token, signed))
            }
            Err(error) => {
                let mut next = self.state(attempted, true)?;
                row_mut(&mut next, id)?.phase = Phase::SignAmbiguous;
                self.persist(attempted, next, AuditKind::SignAmbiguous, Some(id), now_ms)?;
                Err(error)
            }
        }
    }

    /// Explicitly reconcile a recovered signer response without another call.
    pub fn record_signed(
        &mut self,
        expected: Token,
        signed: &ValidatedSignedAlephium,
        now_ms: u64,
    ) -> Result<Token, PublisherError> {
        let mut next = self.state(expected, true)?;
        self.match_unsigned(&next, signed.unsigned())?;
        let record = row_mut(&mut next, signed.intent_id())?;
        if !matches!(record.phase, Phase::SignAttempted | Phase::SignAmbiguous) {
            return Err(PublisherError::InvalidTransition);
        }
        record.signature = Some(signed.signature().to_vec());
        record.phase = Phase::Signed;
        self.persist(
            expected,
            next,
            AuditKind::Signed,
            Some(signed.intent_id()),
            now_ms,
        )
    }

    pub fn submit(
        &mut self,
        expected: Token,
        signed: &ValidatedSignedAlephium,
        submitter: &mut impl ExternalSubmitter,
        now_ms: u64,
    ) -> Result<Token, PublisherError> {
        let mut next = self.state(expected, true)?;
        self.match_unsigned(&next, signed.unsigned())?;
        let record = row_mut(&mut next, signed.intent_id())?;
        if record.phase != Phase::Signed
            || record.submit_attempts != 0
            || record.signature.as_deref() != Some(signed.signature().as_slice())
        {
            return Err(PublisherError::InvalidTransition);
        }
        if !submitter.enabled() {
            return Err(PublisherError::Disabled);
        }
        record.phase = Phase::SubmitAttempted;
        record.submit_attempts = 1;
        let attempted = self.persist(
            expected,
            next,
            AuditKind::SubmitAttempt,
            Some(signed.intent_id()),
            now_ms,
        )?;
        let acknowledged = submitter
            .submit(attempted, signed)
            .is_ok_and(|id| id == signed.tx_id());
        let mut next = self.state(attempted, true)?;
        row_mut(&mut next, signed.intent_id())?.phase = if acknowledged {
            Phase::Submitted
        } else {
            Phase::SubmitAmbiguous
        };
        let kind = if acknowledged {
            AuditKind::Submitted
        } else {
            AuditKind::SubmitAmbiguous
        };
        let token = self.persist(attempted, next, kind, Some(signed.intent_id()), now_ms)?;
        if acknowledged {
            Ok(token)
        } else {
            Err(PublisherError::Ambiguous)
        }
    }
}
