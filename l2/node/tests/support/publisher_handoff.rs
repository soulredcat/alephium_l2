//! Offline file handoff in the one publisher bundle. All authorities are simulated.
use crate::{fixture::*, initialized};
use alephium_l2_node::{
    development,
    publisher::{handoff::*, *},
    storage::Store,
};
use alephium_l2_sdk::alephium::*;
use alloy_primitives::{B256, U256};
use alloy_signer::SignerSync;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    rc::Rc,
};

pub fn exercise(path: &Path) -> u64 {
    fs::create_dir(path).unwrap();
    let store_path = path.join("store");
    let (mut service, scope, mut source, script, _) = initialized(&store_path);
    let directory = path.join("outbox");
    fs::create_dir(&directory).unwrap();
    let mut outbox = FileOutbox::open_existing(&directory, scope.clone()).unwrap();
    let original = unsigned(&scope, &script, 1, 1001, 100_000, source.head);
    let mut changed_spec = original.operation().spec().clone();
    changed_spec.limits.minimum_change += U256::from(1);
    let changed_policy = operation_policy_hash(&approve_operation(changed_spec, &script).unwrap());
    let raw = original.unsigned_bytes().to_vec();
    assert!(matches!(
        service.sign(service.token().unwrap(), original, &mut outbox, 10_000),
        Err(PublisherError::Ambiguous)
    ));
    let request_id = checked_export(&outbox, path, "sign-durability.json");
    let token = service.token().unwrap();
    let state = service.snapshot(token).unwrap();
    assert!(state.records[0].phase == Phase::SignAmbiguous && state.records[0].sign_attempts == 1);
    let bound = outbox.load_request(request_id, &state).unwrap();
    let request = bound.document().clone();
    let original_file = fs::read(outbox.request_path(request_id)).unwrap();
    let mut cases = 1;

    // Direct callback misuse still cannot overwrite an existing request.
    let fresh = unsigned(&scope, &script, 1, 1001, 100_000, source.head);
    assert!(ExternalSigner::sign(&mut outbox, request.body.binding.attempt, &fresh).is_err());
    assert!(outbox.last_error() == Some(HandoffError::AlreadyExists));
    assert!(fs::read(outbox.request_path(request_id)).unwrap() == original_file);
    cases += 1;
    for variant in 0..4 {
        let mut changed = request.clone();
        let bytes = match variant {
            0 => b"{\"version\":".to_vec(),
            1 => {
                changed.checksum_sha256 = id(999);
                serde_json::to_vec(&changed).unwrap()
            }
            2 => {
                changed.version += 1;
                serde_json::to_vec(&changed).unwrap()
            }
            _ => {
                changed.body.operation.limits.minimum_change += U256::from(1);
                changed.body.binding.operation_policy_sha256 = changed_policy;
                reseal_request(&mut changed);
                changed.encode().unwrap()
            }
        };
        let copy = path.join(format!("request-negative-{variant}"));
        fs::create_dir(&copy).unwrap();
        let copied = FileOutbox::open_existing(&copy, scope.clone()).unwrap();
        write_new(&copied.request_path(changed.request_identity), &bytes);
        assert!(
            copied
                .load_request(changed.request_identity, &state)
                .is_err()
        );
        cases += 1;
    }

    let signature = dev_signer()
        .sign_hash_sync(&request.body.binding.tx_id)
        .unwrap();
    let mut signature_bytes = signature.r().to_be_bytes::<32>().to_vec();
    signature_bytes.extend(signature.s().to_be_bytes::<32>());
    let response = ResponseDocument::for_request(
        &request,
        ResponseOutcome::Signed {
            signature_hex: hex::encode(&signature_bytes),
        },
    )
    .unwrap();
    let response_path = path.join("response.json");
    write_new(&response_path, &response.encode(&request).unwrap());
    for variant in 0..10 {
        let mut changed = response.clone();
        match variant {
            0 => {}
            1 => changed.checksum_sha256 = id(990),
            2 => changed.version += 1,
            3 => changed.body.request_identity = id(991),
            4 => changed.body.binding.attempt.fencing_epoch += 1,
            5 => changed.body.binding.scope_id = id(992),
            6 => changed.body.binding.unsigned_sha256 = id(993),
            7 => changed.body.binding.authority_key_hex = "00".repeat(33),
            8 => {
                changed.body.outcome = ResponseOutcome::Signed {
                    signature_hex: "00".repeat(64),
                }
            }
            _ => changed.body.outcome = ResponseOutcome::Cancelled,
        }
        if variant >= 3 {
            changed.checksum_sha256 = hash(&serde_json::to_vec(&changed.body).unwrap());
        }
        let bytes = if variant == 0 {
            b"{\"version\":".to_vec()
        } else {
            serde_json::to_vec(&changed).unwrap()
        };
        let bad_path = path.join(format!("response-negative-{variant}.json"));
        write_new(&bad_path, &bytes);
        let result = outbox.import_signature(
            &mut service,
            token,
            request_id,
            &bad_path,
            unsigned(&scope, &script, 1, 1001, 100_000, source.head),
            10_000,
        );
        assert!(result.is_err() && service.token().unwrap() == token);
        assert!(service.snapshot(token).unwrap().records[0].reservations_retained);
        cases += 1;
    }

    drop(service);
    let store = Store::open_existing(&store_path, &development::genesis()).unwrap();
    let repo = FaultRepository {
        store,
        control: Rc::new(Control::default()),
    };
    let mut service = Publisher::open(repo, scope.clone()).unwrap();
    let token = service.acquire(service.token().unwrap(), 10_001).unwrap();
    source.advance();
    let token = service.refresh_head(token, &mut source).unwrap();
    assert!(
        outbox
            .import_signature(
                &mut service,
                token,
                request_id,
                &response_path,
                unsigned(&scope, &script, 1, 1001, 100_000, Source::new(&scope).head),
                11_000
            )
            .is_err()
    );
    assert!(service.token().unwrap() == token);
    cases += 1;
    let funding = TestFunding::at(&scope, source.head);
    let bound = outbox
        .load_request(request_id, &service.snapshot(token).unwrap())
        .unwrap();
    let mut changed_model = funding.pin.clone();
    changed_model.model = FundingModel::CanonicalFixedCurrentV1;
    assert!(matches!(
        bound.revalidate_unsigned(changed_model, &script, &funding),
        Err(HandoffError::Binding)
    ));
    cases += 1;
    let fresh = bound
        .revalidate_unsigned(funding.pin.clone(), &script, &funding)
        .unwrap();
    assert!(fresh.unsigned_bytes() == raw);
    let (token, signed) = outbox
        .import_signature(
            &mut service,
            token,
            request_id,
            &response_path,
            fresh,
            11_000,
        )
        .unwrap();
    assert!(signed.signature().as_slice() == signature_bytes && signed.unsigned_bytes() == raw);
    assert!(service.snapshot(token).unwrap().records[0].sign_attempts == 1);
    let fresh = bound
        .revalidate_unsigned(funding.pin.clone(), &script, &funding)
        .unwrap();
    assert!(
        outbox
            .import_signature(
                &mut service,
                token,
                request_id,
                &response_path,
                fresh,
                11_000
            )
            .is_err()
    );
    assert!(service.token().unwrap() == token);
    cases += 2;

    assert!(matches!(
        service.submit(token, &signed, &mut outbox, 11_000),
        Err(PublisherError::Ambiguous)
    ));
    let submit_id = checked_export(&outbox, path, "submit-durability.json");
    let token = service.token().unwrap();
    let submitted = service.snapshot(token).unwrap();
    let submit_request = outbox.load_request(submit_id, &submitted).unwrap();
    let ack = ResponseDocument::for_request(
        submit_request.document(),
        ResponseOutcome::SubmissionAcknowledged,
    )
    .unwrap();
    let ack_path = path.join("submission-ack.json");
    write_new(&ack_path, &ack.encode(submit_request.document()).unwrap());
    let observed = outbox
        .inspect_submission_response(&mut service, token, submit_id, &ack_path)
        .unwrap();
    assert!(observed.tx_id == signed.tx_id() && observed.request_identity == submit_id);
    assert!(service.token().unwrap() == token && service.snapshot(token).unwrap() == submitted);
    assert!(
        submitted.records[0].phase == Phase::SubmitAmbiguous
            && submitted.records[0].reservations_retained
    );
    assert!(submitted.records[0].submit_attempts == 1);
    assert!(matches!(
        service.submit(token, &signed, &mut outbox, 11_000),
        Err(PublisherError::InvalidTransition)
    ));
    assert!(fs::read_dir(&directory).unwrap().count() == 2);
    cases += 2;
    drop(service);
    let mut service = Publisher::open(
        Store::open_existing(&store_path, &development::genesis()).unwrap(),
        scope.clone(),
    )
    .unwrap();
    let token = service.acquire(service.token().unwrap(), 11_001).unwrap();
    assert!(matches!(
        service.submit(token, &signed, &mut outbox, 11_001),
        Err(PublisherError::InvalidTransition)
    ));
    assert!(service.snapshot(token).unwrap().records[0].phase == Phase::SubmitAmbiguous);
    assert!(fs::read_dir(&directory).unwrap().count() == 2);
    drop(service);
    cases += 1;
    refuse_old_frame(&path.join("old-frame"));
    cases + 1
}

fn checked_export(outbox: &FileOutbox, root: &Path, name: &str) -> B256 {
    let progress = outbox.last_progress().unwrap();
    let confirmed = progress.stage == ExportStage::DirectorySynced;
    assert!(
        confirmed && outbox.last_error().is_none()
            || progress.stage == ExportStage::FileSynced
                && outbox.last_error() == Some(HandoffError::DirectoryDurabilityUnconfirmed)
    );
    let access = outbox.access_report().unwrap();
    let report = serde_json::json!({"fileSynced": true, "directorySyncConfirmed": confirmed,
        "directoryDurability": if confirmed { "OS flush returned success" } else { "unconfirmed; no replay" },
        "windowsAclInspected": access.windows_acl_inspected, "unixDirectoryMode": access.unix_directory_mode,
        "externalSuccess": false, "powerLossQualified": false});
    write_new(
        &root.join(name),
        &serde_json::to_vec_pretty(&report).unwrap(),
    );
    progress.request_identity
}
fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn hash(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}
fn reseal_request(request: &mut RequestDocument) {
    let bytes = serde_json::to_vec(&request.body).unwrap();
    request.checksum_sha256 = hash(&bytes);
    let mut digest = Sha256::new();
    digest.update(b"ALPH/L2/publisher-handoff-request/v1");
    digest.update(bytes);
    request.request_identity = B256::from_slice(&digest.finalize());
}

// Configured known fixture funding. No request-file claim is used as an oracle.
struct TestFunding {
    pin: FundingPin,
    output: PreviousOutput,
}
impl TestFunding {
    fn at(scope: &Scope, head: ChainHead) -> Self {
        let owner = alephium_hash(&public_key());
        let hint = owner.as_slice().iter().fold(5381u32, |hash, byte| {
            hash.wrapping_mul(33).wrapping_add(*byte as u32)
        }) | 1;
        let group = ((hint ^ (hint >> 8) ^ (hint >> 16) ^ (hint >> 24)) as u8) % 4;
        let mut locking_script = vec![0];
        locking_script.extend(owner.as_slice());
        Self {
            pin: FundingPin {
                model: FundingModel::ExactHeadSnapshotV1,
                source_id: scope.canonical_source,
                network_id: scope.l1_network,
                network_genesis_id: scope.l1_genesis,
                group,
                group_count: 4,
                head_hash: head.hash,
                head_height: head.height,
                timestamp_ms: head.timestamp_ms,
            },
            output: PreviousOutput {
                reference: OutputRef {
                    hint,
                    key: id(1001),
                },
                amount: U256::from(1_000_000_000_000_000_000u64)
                    + U256::from(200_000) * U256::from(100_000_000_000u64),
                locking_script,
                lock_time_ms: 0,
                tokens: vec![],
                additional_data: vec![],
            },
        }
    }
}
impl CanonicalFundingSource for TestFunding {
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

fn refuse_old_frame(path: &Path) {
    let (service, _, _, _, _) = initialized(path);
    drop(service);
    // Fresh v2 test data only: isolate the envelope version guard. This is not a
    // migration claim and does not alter retained schema-one evidence.
    let database = fjall::Database::builder(path).open().unwrap();
    let items = database
        .keyspace("l2-publisher-v1", fjall::KeyspaceCreateOptions::default)
        .unwrap();
    let mut header = items.get([1]).unwrap().unwrap().to_vec();
    let offset = b"ALPH/L2/publisher-storage/v2".len();
    header[offset..offset + 4].copy_from_slice(&1_u32.to_be_bytes());
    items.insert([1], header).unwrap();
    database.persist(fjall::PersistMode::SyncAll).unwrap();
    drop(items);
    drop(database);
    assert!(Store::open_existing(path, &development::genesis()).is_err());
}
