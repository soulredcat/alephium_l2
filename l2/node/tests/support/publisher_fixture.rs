//! Public development key and a pinned compiler-produced script for one bulk job.
//! Funding/effect observations below are simulated, never public-L1 evidence.
use alephium_l2_node::{publisher::*, storage::Store};
use alephium_l2_sdk::alephium::*;
use alloy_primitives::{B256, U256};
use alloy_signer_local::PrivateKeySigner;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
    rc::Rc,
};

#[path = "publisher_faults.rs"]
mod faults;
pub use faults::{Control, FaultRepository};
#[path = "publisher_callbacks.rs"]
mod callbacks;
pub use callbacks::{Mode, Signer, Submitter};

pub fn dev_signer() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::from(U256::from(1).to_be_bytes::<32>()))
        .expect("public development scalar")
}
pub fn public_key() -> Vec<u8> {
    dev_signer()
        .credential()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}
pub fn id(value: u64) -> B256 {
    B256::from(U256::from(value).to_be_bytes::<32>())
}

#[derive(Clone)]
pub struct Script {
    bytes: Vec<u8>,
    artifact: B256,
    scope: B256,
}
impl Script {
    pub fn load(scope: &Scope) -> Self {
        let path = PathBuf::from(
            std::env::var_os("L2_PUBLISHER_SCRIPT_FILE").expect("set the compiled script file"),
        );
        assert!(
            on_project_drive(&path),
            "publisher script fixture must stay on E: or /mnt/e"
        );
        let pin = std::env::var("L2_PUBLISHER_SCRIPT_SHA256")
            .expect("set the independent compiled-script pin");
        let bytes = fs::read(path).expect("read bounded compiler-produced fixture script");
        assert!(!bytes.is_empty() && bytes.len() <= 65_536);
        let artifact = B256::from_slice(&Sha256::digest(&bytes));
        assert!(
            hex::encode(artifact) == pin,
            "compiled script artifact pin differs"
        );
        Self {
            bytes,
            artifact,
            scope: scope.identity().unwrap(),
        }
    }
    pub fn for_scope(&self, scope: &Scope) -> Self {
        Self {
            bytes: self.bytes.clone(),
            artifact: self.artifact,
            scope: scope.identity().unwrap(),
        }
    }
}

pub fn on_project_drive(path: &Path) -> bool {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return false;
    }
    let resolved = if path.exists() {
        fs::canonicalize(path).ok()
    } else {
        path.parent()
            .and_then(|parent| fs::canonicalize(parent).ok())
    };
    let Some(resolved) = resolved else {
        return false;
    };
    #[cfg(windows)]
    {
        use std::path::Prefix;
        matches!(resolved.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) if letter.eq_ignore_ascii_case(&b'E')))
    }
    #[cfg(not(windows))]
    {
        resolved.starts_with("/mnt/e")
    }
}
impl LocalScriptApproval for Script {
    fn approved_script(
        &self,
        spec: &OperationSpec,
    ) -> Result<Option<Vec<u8>>, AlephiumValidationError> {
        if spec.source_artifact_sha256 != self.artifact || spec.publication_scope != self.scope {
            return Err(AlephiumValidationError::InvalidApproval);
        }
        Ok(Some(self.bytes.clone()))
    }
}

pub struct Funding {
    pin: FundingPin,
    output: PreviousOutput,
}
impl CanonicalFundingSource for Funding {
    fn source_id(&self) -> B256 {
        self.pin.source_id
    }
    fn unspent_outputs(
        &self,
        pin: &FundingPin,
        references: &[OutputRef],
    ) -> Result<Vec<PreviousOutput>, AlephiumValidationError> {
        if pin != &self.pin || references != [self.output.reference] {
            return Err(AlephiumValidationError::FundingUnavailable);
        }
        Ok(vec![self.output.clone()])
    }
}

pub fn unsigned(
    scope: &Scope,
    script: &Script,
    intent_id: u64,
    input_id: u64,
    gas: u32,
    head: ChainHead,
) -> ValidatedUnsignedAlephium {
    let key: [u8; 33] = public_key().try_into().unwrap();
    let owner = alephium_hash(&key);
    let hint = owner.as_slice().iter().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(*byte as u32)
    }) | 1;
    let group = ((hint ^ (hint >> 8) ^ (hint >> 16) ^ (hint >> 24)) as u8) % 4;
    let reference = OutputRef {
        hint,
        key: id(input_id),
    };
    let price = U256::from(100_000_000_000u64);
    let amount = U256::from(1_000_000_000_000_000_000u64) + U256::from(200_000) * price;
    let funding = FundingPin {
        model: FundingModel::ExactHeadSnapshotV1,
        source_id: scope.canonical_source,
        network_id: scope.l1_network,
        network_genesis_id: scope.l1_genesis,
        group,
        group_count: 4,
        head_hash: head.hash,
        head_height: head.height,
        timestamp_ms: head.timestamp_ms,
    };
    let spec = OperationSpec {
        intent_id: id(intent_id),
        operation_id: id(intent_id + 10_000),
        publication_scope: scope.identity().unwrap(),
        source_artifact_sha256: script.artifact,
        script_blake2b256: Some(alephium_hash(&script.bytes)),
        caller_public_key: key,
        funding: funding.clone(),
        limits: SpendLimits {
            min_gas_amount: 20_000,
            max_gas_amount: 200_000,
            max_gas_price: price,
            max_fee: U256::from(200_000) * price,
            contract_deposit: U256::ZERO,
            max_total_debit: U256::from(200_000) * price,
            minimum_change: U256::from(1_000_000_000_000_000u64),
        },
    };
    let approved = approve_operation(spec, script).unwrap();
    let mut locking = vec![0];
    locking.extend(owner.as_slice());
    let source = Funding {
        pin: funding,
        output: PreviousOutput {
            reference,
            amount,
            locking_script: locking,
            lock_time_ms: 0,
            tokens: vec![],
            additional_data: vec![],
        },
    };
    let observed = observe_funding(&approved, &[reference], &source).unwrap();
    // Source-derived v0 wire; SDK independently re-encodes and checks every field.
    let mut raw = vec![0, scope.l1_network, 1];
    raw.extend(&script.bytes);
    put_int(&mut raw, gas);
    put_amount(&mut raw, price);
    put_int(&mut raw, 1);
    raw.extend(hint.to_be_bytes());
    raw.extend(reference.key.as_slice());
    raw.push(0);
    raw.extend(key);
    put_int(&mut raw, 1);
    put_amount(&mut raw, amount - U256::from(gas) * price);
    raw.push(0);
    raw.extend(owner.as_slice());
    raw.extend(0_u64.to_be_bytes());
    raw.extend([0, 0]);
    validate_unsigned(&approved, &observed, &raw).unwrap()
}

fn put_int(out: &mut Vec<u8>, value: u32) {
    let bytes = value.to_be_bytes();
    if value < 32 {
        out.push(value as u8);
    } else if value < 8192 {
        out.extend([bytes[2] | 0x40, bytes[3]]);
    } else {
        out.extend([bytes[0] | 0x80, bytes[1], bytes[2], bytes[3]]);
    }
}
fn put_amount(out: &mut Vec<u8>, value: U256) {
    let bytes = value.to_be_bytes::<32>();
    if value < U256::from(64) {
        out.push(bytes[31]);
    } else if value < U256::from(16384) {
        out.extend([bytes[30] | 0x40, bytes[31]]);
    } else if value < U256::from(1u64 << 30) {
        out.extend([bytes[28] | 0x80, bytes[29], bytes[30], bytes[31]]);
    } else {
        let start = bytes.iter().position(|byte| *byte != 0).unwrap();
        out.push(0xc0 + (28 - start) as u8);
        out.extend(&bytes[start..]);
    }
}

pub struct Source {
    pub head: ChainHead,
    pub hashes: BTreeMap<u64, B256>,
    pub receipts: BTreeMap<B256, ObservedReceipt>,
    pub source_id: B256,
}
impl Source {
    pub fn new(scope: &Scope) -> Self {
        let mut hashes = BTreeMap::new();
        hashes.insert(0, scope.l1_genesis);
        for height in 1..=7 {
            hashes.insert(height, id(height + 100));
        }
        Self {
            head: ChainHead {
                network: scope.l1_network,
                genesis: scope.l1_genesis,
                hash: hashes[&7],
                parent: hashes[&6],
                height: 7,
                timestamp_ms: 10_000,
            },
            hashes,
            receipts: BTreeMap::new(),
            source_id: scope.canonical_source,
        }
    }
    pub fn advance(&mut self) {
        let old = self.head.hash;
        self.head.height += 1;
        self.head.hash = id(self.head.height + 100);
        self.head.parent = old;
        self.head.timestamp_ms += 1000;
        self.hashes.insert(self.head.height, self.head.hash);
    }
    pub fn include(&mut self, scope: &Scope, unsigned: &ValidatedUnsignedAlephium, effect: B256) {
        self.receipts.insert(
            unsigned.tx_id(),
            ObservedReceipt {
                tx_id: unsigned.tx_id(),
                block: self.head.hash,
                height: self.head.height,
                factory: scope.factory,
                script_hash: unsigned.operation().spec().script_blake2b256.unwrap(),
                effect_digest: effect,
                execution: ExecutionOutcome::Succeeded,
            },
        );
    }
}
impl CanonicalSource for Source {
    fn source_id(&self) -> B256 {
        self.source_id
    }
    fn head(&mut self, _: &Scope) -> Result<ChainHead, PublisherError> {
        Ok(self.head)
    }
    fn canonical_hash(
        &mut self,
        _: &Scope,
        head: &ChainHead,
        height: u64,
    ) -> Result<Option<B256>, PublisherError> {
        if *head != self.head {
            return Err(PublisherError::InvalidObservation);
        }
        Ok(self.hashes.get(&height).copied())
    }
    fn receipt(
        &mut self,
        _: &Scope,
        head: &ChainHead,
        tx_id: B256,
    ) -> Result<Option<ObservedReceipt>, PublisherError> {
        if *head != self.head {
            return Err(PublisherError::InvalidObservation);
        }
        Ok(self.receipts.get(&tx_id).copied())
    }
}

pub fn scope(store: &Store) -> Scope {
    let view = store.view().unwrap();
    Scope {
        l1_network: 1,
        l1_genesis: id(900),
        l2_chain_id: view.chain_id(),
        l2_genesis: view.head.genesis_id,
        factory: id(901),
        execution_profile: id(902),
        publisher_key: public_key(),
        canonical_source: id(903),
    }
}
pub fn open(
    path: &Path,
) -> (
    Publisher<FaultRepository>,
    Scope,
    Source,
    Script,
    Rc<Control>,
) {
    let store = Store::open(path, &alephium_l2_node::development::genesis()).unwrap();
    let scope = scope(&store);
    let control = Rc::new(Control::default());
    let repo = FaultRepository {
        store,
        control: control.clone(),
    };
    let publisher = Publisher::open(repo, scope.clone()).unwrap();
    let source = Source::new(&scope);
    let script = Script::load(&scope);
    (publisher, scope, source, script, control)
}
pub fn plan(parent: Option<B256>, effect: B256) -> Plan {
    Plan {
        parent,
        expected_effect: effect,
        review_after_ms: 11_000,
        confirmations: 2,
    }
}
