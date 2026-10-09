//! Explicit durable publication lifecycle; no live signer, wallet or network client.
#[cfg(test)]
#[path = "../../../../test/publisher/adapters_qualification.rs"]
mod adapters_qualification;
pub(crate) mod codec;
#[path = "../../../../tool/publisher/configured_signer.rs"]
pub mod configured_signer;
mod dispatch;
pub mod handoff;
mod history;
#[path = "../../../../tool/publisher/http_submitter.rs"]
pub mod http_submitter;
mod observation;
mod reconciliation;
mod service;
#[path = "../../../../tool/publisher/serial_dispatch.rs"]
pub mod serial_dispatch;
pub(crate) mod types;

pub use observation::{CanonicalSource, ChainHead, ExecutionOutcome, ObservedReceipt};
pub use service::{
    DisabledExternal, ExternalFailure, ExternalSigner, ExternalSubmitter, Plan, Publisher,
};
pub use types::{
    AuditEntry, AuditKind, Inclusion, Intent, Phase, Publication, PublisherError,
    PublisherSnapshot, Repository, ReservedInput, Scope, Token,
};
