//! Simulated adapters produce only public-development detached signatures.
use super::dev_signer;
use alephium_l2_node::publisher::*;
use alephium_l2_sdk::alephium::{ValidatedSignedAlephium, ValidatedUnsignedAlephium};
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
pub enum Mode {
    Success,
    Timeout,
    Invalid,
}
pub struct Signer {
    pub mode: Mode,
    pub calls: Rc<Cell<u32>>,
    pub recovered: Rc<RefCell<Option<Vec<u8>>>>,
    pub durable: Rc<RefCell<Option<PublisherSnapshot>>>,
}
impl ExternalSigner for Signer {
    fn enabled(&self) -> bool {
        true
    }
    fn sign(
        &mut self,
        attempt: Token,
        unsigned: &ValidatedUnsignedAlephium,
    ) -> Result<Vec<u8>, ExternalFailure> {
        let state = self.durable.borrow();
        assert!(state.as_ref().unwrap().token() == attempt);
        let row = state
            .as_ref()
            .unwrap()
            .records
            .iter()
            .find(|row| row.intent.id == unsigned.intent_id())
            .unwrap();
        assert!(
            row.phase == Phase::SignAttempted && row.sign_attempts == 1 && row.signature.is_none()
        );
        self.calls.set(self.calls.get() + 1);
        let signature = dev_signer().sign_hash_sync(&unsigned.tx_id()).unwrap();
        let mut bytes = signature.r().to_be_bytes::<32>().to_vec();
        bytes.extend(signature.s().to_be_bytes::<32>());
        *self.recovered.borrow_mut() = Some(bytes.clone());
        match self.mode {
            Mode::Success => Ok(bytes),
            Mode::Timeout => Err(ExternalFailure::Timeout),
            Mode::Invalid => Ok(vec![0; 64]),
        }
    }
}
pub struct Submitter {
    pub mode: Mode,
    pub calls: Rc<Cell<u32>>,
    pub durable: Rc<RefCell<Option<PublisherSnapshot>>>,
}
impl ExternalSubmitter for Submitter {
    fn enabled(&self) -> bool {
        true
    }
    fn submit(
        &mut self,
        attempt: Token,
        signed: &ValidatedSignedAlephium,
    ) -> Result<B256, ExternalFailure> {
        let state = self.durable.borrow();
        assert!(state.as_ref().unwrap().token() == attempt);
        let row = state
            .as_ref()
            .unwrap()
            .records
            .iter()
            .find(|row| row.intent.id == signed.intent_id())
            .unwrap();
        assert!(
            row.phase == Phase::SubmitAttempted
                && row.submit_attempts == 1
                && row.signature.is_some()
        );
        self.calls.set(self.calls.get() + 1);
        match self.mode {
            Mode::Success => Ok(signed.tx_id()),
            Mode::Timeout => Err(ExternalFailure::Timeout),
            Mode::Invalid => Ok(B256::ZERO),
        }
    }
}
