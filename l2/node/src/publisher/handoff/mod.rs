//! Version-one private file exchange over the durable publisher. No keys,
//! network client, signing implementation or broadcasting is provided.
//!
//! The operator owns the Store exclusively after the runtime is closed. Open an
//! existing dedicated private E-drive directory, then pass FileOutbox only to
//! Publisher::sign/submit. Those methods persist their attempt before callback.
//! Every export uses create_new and file+directory durability barriers. Export
//! always returns external Unavailable: queued bytes are NOT a signed response
//! or a network acknowledgement. Unknown/partial writes remain preserved and
//! cannot be automatically recreated after a crash or a cancellation.
//!
//! Restart reads data DTOs, never serialized SDK capabilities. Revalidation uses
//! independently configured LocalScriptApproval and CanonicalFundingSource;
//! import binds the original attempt and all immutable fields to the current
//! ledger, verifies the exact detached signature, then records it once.
//! Submission response files remain audit-only; canonical observation remains
//! the sole inclusion/effect/confirmation authority.
//!
//! Unix files request mode0600. Directory privacy/Windows ACL provisioning is
//! the operator's responsibility; access_report records observable limitations.
//! Windows directory flushing is attempted through a directory handle. If the
//! filesystem/OS cannot confirm it, FileSynced plus the explicit durability
//! error is retained, never DirectorySynced or a successful external operation.
mod adapter;
mod binding;
mod document;
mod import;
mod operation;
mod repository;
mod types;

pub use adapter::FileOutbox;
pub use binding::BoundRequest;
pub use operation::operation_policy_hash;
pub use repository::AccessReport;
pub use types::{
    Binding, ExportProgress, ExportStage, FORMAT_VERSION, FundingRecord, HandoffError,
    MAX_DOCUMENT_BYTES, OperationRecord, RequestBody, RequestDocument, RequestKind, ResponseBody,
    ResponseDocument, ResponseOutcome, SpendRecord, SubmissionAcknowledgement,
};
