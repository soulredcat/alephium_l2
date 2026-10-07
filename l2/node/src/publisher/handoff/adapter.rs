//! File exchange only: enabled means local export, never wallet/network availability.
use super::{
    binding::{self, BoundRequest},
    repository::{AccessReport, Directory},
    types::*,
};
use crate::publisher::{
    ExternalFailure, ExternalSigner, ExternalSubmitter, PublisherSnapshot, Scope, Token,
};
use alephium_l2_sdk::alephium::{ValidatedSignedAlephium, ValidatedUnsignedAlephium};
use alloy_primitives::B256;
use std::path::{Path, PathBuf};

pub struct FileOutbox {
    pub(super) directory: Directory,
    scope: Scope,
    last_progress: Option<ExportProgress>,
    last_error: Option<HandoffError>,
}
impl FileOutbox {
    /// The operator must provision this existing dedicated directory's private
    /// permissions/ACL. Paths and exports remain on E: (or WSL /mnt/e).
    pub fn open_existing(path: &Path, scope: Scope) -> Result<Self, HandoffError> {
        scope.identity()?;
        Ok(Self {
            directory: Directory::open(path)?,
            scope,
            last_progress: None,
            last_error: None,
        })
    }
    pub fn access_report(&self) -> Result<AccessReport, HandoffError> {
        self.directory.access_report()
    }
    pub fn last_progress(&self) -> Option<ExportProgress> {
        self.last_progress
    }
    pub fn last_error(&self) -> Option<HandoffError> {
        self.last_error
    }
    pub fn request_path(&self, identity: B256) -> PathBuf {
        self.directory.request_path(identity)
    }
    pub fn load_request(
        &self,
        identity: B256,
        snapshot: &PublisherSnapshot,
    ) -> Result<BoundRequest, HandoffError> {
        let document = self.directory.read_request(identity)?;
        if document.request_identity != identity || document.body.scope != self.scope {
            return Err(HandoffError::Binding);
        }
        binding::bind(document, snapshot)
    }
    fn export(&mut self, document: Result<RequestDocument, HandoffError>) {
        self.last_progress = None;
        self.last_error = None;
        let document = match document {
            Ok(value) => value,
            Err(error) => {
                self.last_error = Some(error);
                return;
            }
        };
        let identity = document.request_identity;
        let mut stage = ExportStage::Prepared;
        let result = document
            .encode()
            .and_then(|bytes| self.directory.write_request(identity, &bytes, &mut stage));
        self.last_progress = Some(ExportProgress {
            request_identity: identity,
            stage,
        });
        self.last_error = result.err();
    }
}
impl ExternalSigner for FileOutbox {
    fn enabled(&self) -> bool {
        true
    }
    fn sign(
        &mut self,
        attempt: Token,
        unsigned: &ValidatedUnsignedAlephium,
    ) -> Result<Vec<u8>, ExternalFailure> {
        self.export(RequestDocument::capture(
            &self.scope,
            attempt,
            unsigned,
            None,
        ));
        // Even a directory-synced request has no signature response yet. All
        // failures/unknown durability remain ambiguous; nothing is re-exported.
        Err(ExternalFailure::Unavailable)
    }
}
impl ExternalSubmitter for FileOutbox {
    fn enabled(&self) -> bool {
        true
    }
    fn submit(
        &mut self,
        attempt: Token,
        signed: &ValidatedSignedAlephium,
    ) -> Result<B256, ExternalFailure> {
        self.export(RequestDocument::capture(
            &self.scope,
            attempt,
            signed.unsigned(),
            Some(signed.signature()),
        ));
        Err(ExternalFailure::Unavailable)
    }
}
