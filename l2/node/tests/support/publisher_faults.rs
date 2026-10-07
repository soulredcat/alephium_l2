//! Inject repository-return gaps around the real Store SyncAll implementation.
use alephium_l2_node::{publisher::*, storage::Store};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Default)]
pub struct Control {
    pub calls: Cell<u64>,
    pub loads: Cell<u64>,
    pub before: Cell<Option<u64>>,
    pub after: Cell<Option<u64>>,
    pub durable: Rc<RefCell<Option<PublisherSnapshot>>>,
    pub steal_fence: Cell<Option<u64>>,
}
pub struct FaultRepository {
    pub store: Store,
    pub control: Rc<Control>,
}
impl Repository for FaultRepository {
    fn publisher_load(&self, scope: &Scope) -> Result<Option<PublisherSnapshot>, PublisherError> {
        self.control.loads.set(self.control.loads.get() + 1);
        let value = self.store.publisher_load(scope)?;
        *self.control.durable.borrow_mut() = value.clone();
        Ok(value)
    }
    fn publisher_cas(
        &mut self,
        revision: u64,
        fence: u64,
        next: &PublisherSnapshot,
    ) -> Result<PublisherSnapshot, PublisherError> {
        let call = self.control.calls.get() + 1;
        self.control.calls.set(call);
        if self.control.before.get() == Some(call) {
            return Err(PublisherError::Storage);
        }
        if self.control.steal_fence.get() == Some(call) {
            let mut fenced = self
                .store
                .publisher_load(&next.scope)?
                .ok_or(PublisherError::CorruptState)?;
            let old = fenced.token();
            fenced.revision += 1;
            fenced.fencing_epoch += 1;
            fenced.history.push(AuditEntry {
                revision: fenced.revision,
                fencing_epoch: fenced.fencing_epoch,
                intent_id: None,
                kind: AuditKind::Fence,
                at_ms: 10_001,
                canonical_head: fenced.canonical_head,
                inclusion: None,
            });
            let fenced = self
                .store
                .publisher_cas(old.revision, old.fencing_epoch, &fenced)?;
            *self.control.durable.borrow_mut() = Some(fenced);
        }
        let stored = self.store.publisher_cas(revision, fence, next)?;
        *self.control.durable.borrow_mut() = Some(stored.clone());
        if self.control.after.get() == Some(call) {
            Err(PublisherError::Storage)
        } else {
            Ok(stored)
        }
    }
}
