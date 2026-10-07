//! Private SDK receipt ingestion; independent pairing precedes target execution.
use crate::{
    actual_factory_service, compiler::Compiled, factory_service, ordinary_miller, receipt_cases,
    receipt_fixture, residue_witness, staged_cases, transport::ReadOnlyNode,
};
use ark_bn254::{Bn254, Fq12, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, pairing::Pairing};
use ark_ff::{BigInteger, Field, PrimeField};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, Metadata, OpenOptions},
    io::Read,
    path::{Component, Path, PathBuf},
};

const MAX_INPUT_BYTES: u64 = 1_048_576;
const SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];
pub(crate) const MAX_REQUESTS: usize = 69;

/// These pins are selected from the independently reviewed ProgramBinary and replayed
/// canonical transition. The private receipt report cannot choose either pin.
pub(crate) struct Input {
    directory: PathBuf,
    image: [u8; 32],
    journal: [u8; 32],
}

impl Input {
    pub(crate) fn new(directory: &OsStr, image: &OsStr, journal: &OsStr) -> Result<Self, String> {
        let digest = |value: &OsStr| -> Result<[u8; 32], String> {
            let text = value
                .to_str()
                .ok_or("Expected receipt pin must be UTF-8 hex")?;
            if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("Expected receipt pin must be exactly 64 hex characters".into());
            }
            receipt_fixture::bytes32(
                &hex::decode(text).map_err(|_| "Invalid expected receipt pin")?,
            )
        };
        Ok(Self {
            directory: directory.into(),
            image: digest(image)?,
            journal: digest(journal)?,
        })
    }
}

pub(crate) struct Prepared {
    pub(crate) fixture: staged_cases::Fixture,
    pub(crate) changed_proof: staged_cases::Fixture,
    pub(crate) evidence: Value,
    // Keep the exact bytes verified above; settlement adapters never reopen them.
    pub(crate) journal: Vec<u8>,
}

pub(crate) fn prepare(input: &Input) -> Result<Prepared, String> {
    load(input, &factory_service::canonical_child_id()?)
}

pub(crate) fn prepare_for_child(input: &Input, child_id: &[u8; 32]) -> Result<Prepared, String> {
    load(input, child_id)
}

/// The caller separately approves the compiled guest and its input provenance.
/// Host report assertions never authorize the pairing or target acceptance.
pub(crate) fn execute_actual(
    node: &ReadOnlyNode,
    factory: &Compiled,
    child: &Compiled,
    report: &mut Value,
    prepared: Prepared,
) -> Result<(), String> {
    report["actualReceipt"] = prepared.evidence;
    actual_factory_service::execute(
        node,
        factory,
        child,
        report,
        &prepared.fixture,
        &prepared.changed_proof,
    )?;
    if report["executedCases"].as_u64() != Some(MAX_REQUESTS as u64) {
        return Err("Actual receipt flow differs from its fixed request inventory".into());
    }
    report["actualReceipt"]["canonicalTargetAccepted"] = json!(true);
    report["actualReceipt"]["wrongJournalTargetRejected"] = json!(true);
    report["actualReceipt"]["wrongImageTargetRejected"] = json!(true);
    report["actualReceipt"]["changedProofTargetRejected"] = json!(true);
    Ok(())
}

fn load(input: &Input, child_id: &[u8; 32]) -> Result<Prepared, String> {
    let root = checked_directory(&input.directory)?;
    let seal = read_regular(&root, "seal.bin", 260)?;
    let image = receipt_fixture::bytes32(&read_regular(&root, "imageid.bin", 32)?)?;
    let journal = read_regular(&root, "journal.bin", MAX_INPUT_BYTES)?;
    let journal_digest = receipt_fixture::bytes32(&read_regular(&root, "journal_digest.bin", 32)?)?;
    let host_report = read_regular(&root, "report.json", MAX_INPUT_BYTES)?;
    serde_json::from_slice::<Value>(&host_report)
        .map_err(|_| "Private receipt host report is not bounded valid JSON")?;
    if seal.len() != 260 || seal[..4] != SELECTOR || hash(&journal) != journal_digest {
        return Err("Actual receipt seal/selector or journal digest binding differs".into());
    }
    if image != input.image || journal_digest != input.journal {
        return Err(
            "Actual receipt differs from the independently selected image or journal pin".into(),
        );
    }
    // Control parameters and the verification key come from hash-pinned sources.
    // No private-directory metadata can replace them.
    let (pinned, words) = receipt_fixture::load()?;
    let receipt = receipt_fixture::Fixture {
        seal,
        image,
        journal: journal_digest,
        control: pinned.control,
        control_id: pinned.control_id,
    };
    let pairs = receipt_cases::pair_inputs_for(&receipt, &words, image, journal_digest)?;
    let identity = Bn254::multi_pairing(pairs.map(|pair| pair.0), pairs.map(|pair| pair.1)).0;
    if identity != Fq12::ONE {
        return Err("Actual SDK receipt fails independent full BN254 pairing".into());
    }
    let mut wrong_image = image;
    wrong_image[0] ^= 1;
    let mut wrong_journal = journal_digest;
    wrong_journal[0] ^= 1;
    for (changed_image, changed_journal) in [(wrong_image, journal_digest), (image, wrong_journal)]
    {
        let changed =
            receipt_cases::pair_inputs_for(&receipt, &words, changed_image, changed_journal)?;
        if Bn254::multi_pairing(changed.map(|pair| pair.0), changed.map(|pair| pair.1)).0
            == Fq12::ONE
        {
            return Err("Altered actual receipt claim satisfies independent pairing".into());
        }
    }
    let product = ordinary_miller::miller_product(&pairs)?;
    ordinary_miller::certify_normalized_product(&pairs, product)?;
    let auxiliary = residue_witness::generate(product)?;
    let encoded = vec![
        hex::encode(&receipt.seal),
        hex::encode(image),
        hex::encode(journal_digest),
        hex::encode(auxiliary),
    ];
    let fixture = staged_cases::Fixture::from_encoded(child_id, &encoded)?;
    // C + G1 is different even when C is infinity. Keep valid curve/subgroup
    // admission, and retain the original auxiliary for final equation rejection.
    let changed_c = (pairs[3].0.into_group() + G1Projective::generator()).into_affine();
    let mut changed_receipt = receipt_fixture::Fixture {
        seal: receipt.seal.clone(),
        image,
        journal: journal_digest,
        control: receipt.control,
        control_id: receipt.control_id,
    };
    for (index, value) in [changed_c.x, changed_c.y].into_iter().enumerate() {
        let encoded = value.into_bigint().to_bytes_be();
        let word = &mut changed_receipt.seal[196 + 32 * index..228 + 32 * index];
        word.fill(0);
        word[32 - encoded.len()..].copy_from_slice(&encoded);
    }
    let changed_pairs =
        receipt_cases::pair_inputs_for(&changed_receipt, &words, image, journal_digest)?;
    if Bn254::multi_pairing(
        changed_pairs.map(|pair| pair.0),
        changed_pairs.map(|pair| pair.1),
    )
    .0 == Fq12::ONE
    {
        return Err("Changed actual proof unexpectedly satisfies independent pairing".into());
    }
    let mut changed_encoded = encoded.clone();
    changed_encoded[0] = hex::encode(&changed_receipt.seal);
    let changed_proof = staged_cases::Fixture::from_encoded(child_id, &changed_encoded)?;
    let mut evidence = json!({
        "scope": "actual SDK Groth16 receipt; pinned-key independent oracle and synthetic target",
        "sealBytes": receipt.seal.len(), "sealSha256": hex::encode(hash(&receipt.seal)),
        "imageIdBytes": 32, "imageIdSha256": hex::encode(hash(&image)),
        "journalBytes": journal.len(), "journalSha256": hex::encode(journal_digest),
        "journalDigestBytes": 32, "journalDigestSha256": hex::encode(hash(&journal_digest)),
        "hostReportBytes": host_report.len(), "hostReportSha256": hex::encode(hash(&host_report)),
        "hostReportUsedAsCryptographicAuthority": false,
        "independentlySelectedImageId": hex::encode(input.image),
        "independentlySelectedJournalSha256": hex::encode(input.journal),
        "externalPinsMatchedBeforeVm": true, "pinsAreOnchainPolicy": false,
        "sourceAndKey": "existing receipt_fixture hash-pinned v3.0.0 sources and parameters",
        "parameterSelector": hex::encode(SELECTOR), "publicSignalCount": 5,
        "claimProfile": "zero input; unconditional halted-zero claim; image and journal bound",
        "independentFullPairingIdentity": true, "rawMillerNormalizationCertified": true,
        "wrongImageIndependentlyFalse": true, "wrongJournalIndependentlyFalse": true,
        "changedProofIndependentlyFalse": true, "changedProofMutation": "G1 C + generator; original auxiliary",
        "auxiliaryBytes": auxiliary.len(), "auxiliarySha256": hex::encode(hash(&auxiliary)),
        "statementSha256": fixture.statement_id, "statementPreimageBytes": 188,
        "canonicalChildId": hex::encode(child_id), "maximumRequests": MAX_REQUESTS,
        "canonicalTargetAccepted": false, "wrongJournalTargetRejected": false,
        "wrongImageTargetRejected": false, "changedProofTargetRejected": false,
        "approvedGuestSemanticsEstablishedByPairing": false,
        "realDeploymentProven": false, "persistentChainContinuityProven": false,
        "settlementAccepted": false
    });
    // Keep the existing flat report schema without expanding one json! object
    // beyond the macro's recursion budget as boundary evidence grows.
    evidence["syntheticFactoryImmutablePolicyPinsPayload"] = json!(true);
    evidence["expectedPayloadReadFromHostReport"] = json!(false);
    evidence["expectedPayloadId"] = json!(fixture.payload_id);
    evidence["payloadDomain"] = json!("ALPH/L2/stagedpayload/v1");
    evidence["payloadPreimageBytes"] = json!(156);
    evidence["payloadDerivedFromPinnedClaimAndIndependentlyVerifiedSeal"] = json!(true);
    Ok(Prepared {
        fixture,
        changed_proof,
        evidence,
        journal,
    })
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn checked_directory(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "Cannot resolve private receipt directory")?
            .join(path)
    };
    reject_redirects(&absolute)?;
    if !fs::metadata(&absolute)
        .map_err(|_| "Missing private receipt directory")?
        .is_dir()
    {
        return Err("Private receipt input is not a directory".into());
    }
    fs::canonicalize(absolute).map_err(|_| "Cannot canonicalize private receipt directory".into())
}

fn reject_redirects(path: &Path) -> Result<(), String> {
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err("Private receipt paths cannot traverse parent directories".into());
        }
        ancestor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::CurDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&ancestor)
            .map_err(|_| "Cannot inspect private receipt path ancestry")?;
        if redirected(&metadata) {
            return Err("Private receipt paths cannot contain symlinks or reparse points".into());
        }
    }
    Ok(())
}

fn redirected(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

fn read_regular(root: &Path, name: &str, maximum: u64) -> Result<Vec<u8>, String> {
    let path = root.join(name);
    reject_redirects(&path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the leaf itself rather than follow a reparse point introduced
        // between ancestry inspection and open.
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(&path)
        .map_err(|_| "Missing private receipt component")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect private receipt component")?;
    if redirected(&metadata) || !metadata.is_file() || metadata.len() > maximum {
        return Err("Private receipt component is redirected, non-regular or oversized".into());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read bounded private receipt component")?;
    let after = file
        .metadata()
        .map_err(|_| "Cannot recheck private receipt component")?;
    reject_redirects(&path)?;
    if bytes.len() as u64 > maximum
        || bytes.len() as u64 != metadata.len()
        || after.len() != metadata.len()
        || after.modified().ok() != metadata.modified().ok()
        || fs::canonicalize(&path).map_err(|_| "Cannot recheck private receipt location")? != path
    {
        return Err("Private receipt component changed or escaped its bounded directory".into());
    }
    Ok(bytes)
}
