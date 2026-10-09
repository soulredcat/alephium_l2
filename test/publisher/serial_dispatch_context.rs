use crate::fixture::{self, *};
use alephium_l2_node::{
    development,
    publisher::{serial_dispatch::*, *},
    storage::Store,
};
use alephium_l2_sdk::alephium::ValidatedUnsignedAlephium;
use std::{
    cell::{Cell, RefCell},
    path::{Path, PathBuf},
    rc::Rc,
};

pub type Service = Publisher<FaultRepository>;

pub struct Context {
    pub path: PathBuf,
    pub scope: Scope,
    pub source: Source,
    pub script: Script,
    pub control: Rc<Control>,
    pub plan: SerialBootstrapPlan,
    pub signer: Signer,
    pub submitter: Submitter,
}

impl Context {
    pub fn open(path: &Path) -> (Service, Self) {
        let (mut service, scope, mut source, script, control) = fixture::open(path);
        let token = service.acquire(service.token().unwrap(), 10_000).unwrap();
        service.refresh_head(token, &mut source).unwrap();
        let operations = std::array::from_fn(|index| {
            let tx = unsigned(
                &scope,
                &script,
                index as u64 + 1,
                index as u64 + 1001,
                100_000,
                source.head,
            );
            SerialOperation::from_approved(
                tx.operation(),
                tx.unsigned_bytes(),
                id(index as u64 + 500),
                2,
            )
            .unwrap()
        });
        let plan = SerialBootstrapPlan::new(operations).unwrap();
        let signer = Signer {
            mode: Mode::Success,
            calls: Rc::new(Cell::new(0)),
            recovered: Rc::new(RefCell::new(None)),
            durable: control.durable.clone(),
        };
        let submitter = Submitter {
            mode: Mode::Success,
            calls: Rc::new(Cell::new(0)),
            durable: control.durable.clone(),
        };
        (
            service,
            Self {
                path: path.to_path_buf(),
                scope,
                source,
                script,
                control,
                plan,
                signer,
                submitter,
            },
        )
    }

    pub fn unsigned(&self, index: usize) -> ValidatedUnsignedAlephium {
        unsigned(
            &self.scope,
            &self.script,
            index as u64 + 1,
            index as u64 + 1001,
            100_000,
            self.source.head,
        )
    }

    pub fn dispatch(
        &mut self,
        service: &mut Service,
        index: usize,
    ) -> Result<Token, PublisherError> {
        let unsigned = self.unsigned(index);
        let token = service.token().unwrap();
        let now = self.source.head.timestamp_ms;
        self.plan.dispatch(
            service,
            token,
            index,
            unsigned,
            &mut self.source,
            &mut self.signer,
            &mut self.submitter,
            now,
        )
    }

    pub fn observe(
        &mut self,
        service: &mut Service,
        index: usize,
    ) -> Result<Token, PublisherError> {
        let token = service.token().unwrap();
        self.plan
            .observe_confirmed(service, token, index, &mut self.source)
    }

    pub fn reopen(&mut self, service: Service) -> Service {
        drop(service);
        let store = Store::open_existing(&self.path, &development::genesis()).unwrap();
        let control = Rc::new(Control::default());
        let mut service = Publisher::open(
            FaultRepository {
                store,
                control: control.clone(),
            },
            self.scope.clone(),
        )
        .unwrap();
        service
            .acquire(service.token().unwrap(), self.source.head.timestamp_ms)
            .unwrap();
        self.signer.durable = control.durable.clone();
        self.submitter.durable = control.durable.clone();
        self.control = control;
        service
    }

    pub fn counts(&self) -> (u32, u32) {
        (self.signer.calls.get(), self.submitter.calls.get())
    }
}

pub fn snapshot(service: &mut Service) -> PublisherSnapshot {
    service.snapshot(service.token().unwrap()).unwrap()
}

pub fn check(ok: bool, count: &mut usize) {
    assert!(
        ok,
        "Serial dispatch aggregate failed; private values suppressed"
    );
    *count += 1;
}
