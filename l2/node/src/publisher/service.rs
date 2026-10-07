//! Memory-first orchestration; durable attempt markers always precede callbacks.
use super::{codec, types::*};
use alephium_l2_sdk::alephium::{ValidatedSignedAlephium, ValidatedUnsignedAlephium};
use alloy_primitives::B256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalFailure {
    Disabled,
    Timeout,
    Rejected,
    Unavailable,
}

/// Detached signing only. An implementation must not broadcast. Its audit must
/// retain the intent/operation/tx identity so an uncertain response is recoverable.
pub trait ExternalSigner {
    /// Availability only; this never replaces approved unsigned/signature checks.
    fn enabled(&self) -> bool {
        false
    }
    fn sign(
        &mut self,
        attempt: Token,
        intent: &ValidatedUnsignedAlephium,
    ) -> Result<Vec<u8>, ExternalFailure>;
}
/// Submit this exact validated signed transaction once. A returned hash is only
/// acknowledgement, never inclusion, execution success or finality authority.
pub trait ExternalSubmitter {
    fn enabled(&self) -> bool {
        false
    }
    fn submit(
        &mut self,
        attempt: Token,
        signed: &ValidatedSignedAlephium,
    ) -> Result<B256, ExternalFailure>;
}
pub struct DisabledExternal;
impl ExternalSigner for DisabledExternal {
    fn sign(
        &mut self,
        _: Token,
        _: &ValidatedUnsignedAlephium,
    ) -> Result<Vec<u8>, ExternalFailure> {
        Err(ExternalFailure::Disabled)
    }
}
impl ExternalSubmitter for DisabledExternal {
    fn submit(&mut self, _: Token, _: &ValidatedSignedAlephium) -> Result<B256, ExternalFailure> {
        Err(ExternalFailure::Disabled)
    }
}

pub struct Plan {
    pub parent: Option<B256>,
    pub expected_effect: B256,
    pub review_after_ms: u64,
    pub confirmations: u64,
}

pub struct Publisher<R: Repository> {
    pub(super) repository: R,
    pub(super) scope: Scope,
    pub(super) cache: Option<PublisherSnapshot>,
    pub(super) lease: Option<u64>,
}

impl<R: Repository> Publisher<R> {
    pub fn open(repository: R, scope: Scope) -> Result<Self, PublisherError> {
        codec::scope_id(&scope)?;
        let snapshot = repository
            .publisher_load(&scope)?
            .unwrap_or_else(|| PublisherSnapshot::empty(scope.clone()));
        codec::validate_snapshot(&snapshot)?;
        Ok(Self {
            repository,
            scope,
            cache: Some(snapshot),
            lease: None,
        })
    }
    pub fn token(&self) -> Result<Token, PublisherError> {
        Ok(self.cache.as_ref().ok_or(PublisherError::Storage)?.token())
    }
    pub fn snapshot(&mut self, expected: Token) -> Result<PublisherSnapshot, PublisherError> {
        self.state(expected, false)
    }
    pub fn into_repository(self) -> R {
        self.repository
    }

    /// Explicit ownership change. Existing attempted operations remain attempted;
    /// taking a fence never authorizes signing/submission again after restart.
    pub fn acquire(&mut self, expected: Token, now_ms: u64) -> Result<Token, PublisherError> {
        let mut next = self.state(expected, false)?;
        next.fencing_epoch = next
            .fencing_epoch
            .checked_add(1)
            .ok_or(PublisherError::ResourceLimit)?;
        let token = self.persist(expected, next, AuditKind::Fence, None, now_ms)?;
        self.lease = Some(token.fencing_epoch);
        Ok(token)
    }

    pub fn register(
        &mut self,
        expected: Token,
        unsigned: &ValidatedUnsignedAlephium,
        plan: Plan,
        now_ms: u64,
    ) -> Result<Token, PublisherError> {
        let mut next = self.state(expected, true)?;
        self.context_matches(unsigned, next.canonical_head)?;
        if next.records.len() == MAX_PUBLICATIONS
            || plan.expected_effect == B256::ZERO
            || plan.confirmations == 0
            || plan.review_after_ms <= now_ms
        {
            return Err(PublisherError::InvalidInput);
        }
        if let Some(parent) = plan.parent
            && row(&next, parent)?.phase != Phase::Confirmed
        {
            return Err(PublisherError::InvalidTransition);
        }
        let spec = unsigned.operation().spec();
        if now_ms < spec.funding.timestamp_ms {
            return Err(PublisherError::InvalidInput);
        }
        let script_hash = spec
            .script_blake2b256
            .filter(|value| *value != B256::ZERO)
            .ok_or(PublisherError::InvalidInput)?;
        let intent = Intent {
            id: unsigned.intent_id(),
            operation_id: unsigned.operation_id(),
            parent: plan.parent,
            tx_id: unsigned.tx_id(),
            unsigned: unsigned.unsigned_bytes().to_vec(),
            inputs: unsigned
                .input_refs()
                .iter()
                .map(|input| ReservedInput {
                    hint: input.hint,
                    key: input.key,
                })
                .collect(),
            network: self.scope.l1_network,
            l1_genesis: self.scope.l1_genesis,
            canonical_source: self.scope.canonical_source,
            artifact_hash: spec.source_artifact_sha256,
            script_hash,
            expected_effect: plan.expected_effect,
            authority_key: spec.caller_public_key.to_vec(),
            created_at_ms: now_ms,
            review_after_ms: plan.review_after_ms,
            confirmations: plan.confirmations,
        };
        let id = intent.id;
        next.records.push(Publication {
            intent,
            phase: Phase::Intent,
            sign_attempts: 0,
            submit_attempts: 0,
            signature: None,
            inclusion: None,
            reservations_retained: true,
        });
        self.persist(expected, next, AuditKind::Intent, Some(id), now_ms)
    }

    pub(super) fn state(
        &mut self,
        expected: Token,
        leased: bool,
    ) -> Result<PublisherSnapshot, PublisherError> {
        // A caller asks for an exact revision/head view. A write still uses the
        // repository's fresh CAS before any external effect can be dispatched.
        if self
            .cache
            .as_ref()
            .is_none_or(|value| value.token() != expected)
        {
            self.cache = self.repository.publisher_load(&self.scope)?;
        }
        let snapshot = self.cache.as_ref().ok_or(PublisherError::Conflict)?;
        if snapshot.token() != expected {
            return Err(PublisherError::Conflict);
        }
        if leased && self.lease != Some(snapshot.fencing_epoch) {
            return Err(PublisherError::StaleFence);
        }
        Ok(snapshot.clone())
    }
    pub(super) fn persist(
        &mut self,
        expected: Token,
        mut next: PublisherSnapshot,
        kind: AuditKind,
        id: Option<B256>,
        now_ms: u64,
    ) -> Result<Token, PublisherError> {
        if next.history.len() >= MAX_HISTORY {
            return Err(PublisherError::ResourceLimit);
        }
        next.revision = expected
            .revision
            .checked_add(1)
            .ok_or(PublisherError::ResourceLimit)?;
        let inclusion = if kind == AuditKind::CanonicalObservation {
            row(&next, id.ok_or(PublisherError::InvalidTransition)?)?
                .inclusion
                .clone()
        } else {
            None
        };
        next.history.push(AuditEntry {
            revision: next.revision,
            fencing_epoch: next.fencing_epoch,
            intent_id: id,
            kind,
            at_ms: now_ms,
            canonical_head: next.canonical_head,
            inclusion,
        });
        let previous = self.cache.as_ref().filter(|value| value.revision != 0);
        codec::validate_transition(previous, &next)?;
        match self
            .repository
            .publisher_cas(expected.revision, expected.fencing_epoch, &next)
        {
            Ok(stored) => {
                let token = stored.token();
                self.cache = Some(stored);
                Ok(token)
            }
            Err(error) => {
                self.cache = None;
                self.lease = None;
                Err(error)
            }
        }
    }
    fn context_matches(
        &self,
        unsigned: &ValidatedUnsignedAlephium,
        head: B256,
    ) -> Result<(), PublisherError> {
        let spec = unsigned.operation().spec();
        if spec.publication_scope != codec::scope_id(&self.scope)?
            || head == B256::ZERO
            || spec.funding.head_hash != head
            || spec.funding.source_id != self.scope.canonical_source
            || spec.funding.network_id != self.scope.l1_network
            || spec.funding.network_genesis_id != self.scope.l1_genesis
            || spec.caller_public_key.as_slice() != self.scope.publisher_key
        {
            return Err(PublisherError::InvalidInput);
        }
        Ok(())
    }
    pub(super) fn match_unsigned(
        &self,
        snapshot: &PublisherSnapshot,
        unsigned: &ValidatedUnsignedAlephium,
    ) -> Result<(), PublisherError> {
        self.context_matches(unsigned, snapshot.canonical_head)?;
        let record = row(snapshot, unsigned.intent_id())?;
        let spec = unsigned.operation().spec();
        if record.intent.operation_id != unsigned.operation_id()
            || record.intent.tx_id != unsigned.tx_id()
            || record.intent.unsigned != unsigned.unsigned_bytes()
            || record.intent.artifact_hash != spec.source_artifact_sha256
            || Some(record.intent.script_hash) != spec.script_blake2b256
            || record.intent.inputs.len() != unsigned.input_refs().len()
            || record
                .intent
                .inputs
                .iter()
                .zip(unsigned.input_refs())
                .any(|(a, b)| a.hint != b.hint || a.key != b.key)
        {
            return Err(PublisherError::InvalidInput);
        }
        Ok(())
    }
}

pub(super) fn row(snapshot: &PublisherSnapshot, id: B256) -> Result<&Publication, PublisherError> {
    snapshot
        .records
        .iter()
        .find(|row| row.intent.id == id)
        .ok_or(PublisherError::InvalidInput)
}
pub(super) fn row_mut(
    snapshot: &mut PublisherSnapshot,
    id: B256,
) -> Result<&mut Publication, PublisherError> {
    snapshot
        .records
        .iter_mut()
        .find(|row| row.intent.id == id)
        .ok_or(PublisherError::InvalidInput)
}
