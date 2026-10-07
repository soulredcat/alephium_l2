//! Explicit durable publication lifecycle; no live signer, wallet or network client.
pub(crate) mod codec;
mod dispatch;
mod history;
mod observation;
mod reconciliation;
mod service;
pub(crate) mod types;

pub use observation::{CanonicalSource, ChainHead, ExecutionOutcome, ObservedReceipt};
pub use service::{
    DisabledExternal, ExternalFailure, ExternalSigner, ExternalSubmitter, Plan, Publisher,
};
pub use types::{
    AuditEntry, AuditKind, Inclusion, Intent, Phase, Publication, PublisherError,
    PublisherSnapshot, Repository, ReservedInput, Scope, Token,
};
