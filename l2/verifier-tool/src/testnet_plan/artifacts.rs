//! Freeze reviewed compiler outputs against independent pins and current sources.
//! Metadata flags never substitute for byte, source-closure or exact ABI checks.
use crate::{
    compiler::{Compiled, JAR_SHA256},
    input::{Source, Suite},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type Hash = [u8; 32];
const ZERO: Hash = [0; 32];
const MAX_EXECUTABLE_BYTES: usize = 32_768;
const SOURCE_CLOSURE_DOMAIN: &[u8] = b"ALPH/L2/testnet-artifact-source-closure/v1";

pub(crate) struct ArtifactPins {
    pub(crate) artifact_sha256: Hash,
    pub(crate) executable_sha256: Hash,
    pub(crate) code_hash: Hash,
    pub(crate) source_closure_sha256: Hash,
}

pub(crate) struct FrozenArtifact {
    pub(super) class: &'static str,
    pub(super) bytecode: Vec<u8>,
    pub(super) code_hash: Hash,
    pub(super) artifact_sha256: Hash,
    pub(super) executable_sha256: Hash,
    pub(super) source_closure_sha256: Hash,
    pub(super) public_methods: BTreeMap<String, usize>,
}

pub(crate) struct FrozenArtifacts {
    pub(super) proof: FrozenArtifact,
    pub(super) data: FrozenArtifact,
    pub(super) factory: FrozenArtifact,
}

/// Pins are ordered proof, data, factory and must already be independently reviewed.
pub(crate) fn freeze(
    proof: &Compiled,
    data: &Compiled,
    factory: &Compiled,
    pins: &[ArtifactPins; 3],
) -> Result<FrozenArtifacts, String> {
    Ok(FrozenArtifacts {
        proof: freeze_one(proof, Suite::StagedReceipt, &pins[0])?,
        data: freeze_one(data, Suite::SettlementData, &pins[1])?,
        factory: freeze_one(factory, Suite::SettlementFactoryCompile, &pins[2])?,
    })
}

fn sha(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

fn hash_field(value: &Value) -> Result<Hash, String> {
    let text = value.as_str().ok_or("Missing artifact hash pin")?;
    if text.len() != 64 {
        return Err("Artifact hash must be exactly 32 canonical hex bytes".into());
    }
    hex::decode(text)
        .map_err(|_| "Artifact hash is not hexadecimal".to_owned())?
        .try_into()
        .map_err(|_| "Artifact hash has the wrong width".into())
}

fn freeze_one(
    compiled: &Compiled,
    suite: Suite,
    pins: &ArtifactPins,
) -> Result<FrozenArtifact, String> {
    if [
        pins.artifact_sha256,
        pins.executable_sha256,
        pins.code_hash,
        pins.source_closure_sha256,
    ]
    .contains(&ZERO)
    {
        return Err("Offline artifact pins must be independently selected and nonzero".into());
    }
    let evidence = &compiled.evidence;
    if evidence["compilerReportedVersion"] != "v4.7.0"
        || hash_field(&evidence["jarSha256"])? != hash_field(&json!(JAR_SHA256))?
        || evidence["artifact"] != format!("artifacts/{}", suite.artifact())
    {
        return Err("Offline artifact compiler or selected class differs".into());
    }
    if compiled.bytecode.is_empty() || compiled.bytecode.len() > MAX_EXECUTABLE_BYTES * 2 {
        return Err("Offline artifact executable exceeds the selected bound".into());
    }
    let bytecode = hex::decode(&compiled.bytecode)
        .map_err(|_| "Offline artifact production bytecode is not hexadecimal")?;
    let executable_sha256 = sha(&bytecode);
    let artifact_sha256 = hash_field(&evidence["artifactSha256"])?;
    let code_hash = hash_field(&evidence["productionCodeHash"])?;
    // Compiled does not retain raw artifact JSON. Its artifact hash and VM code
    // hash are matched to external pins; only executable SHA is recomputed here.
    if bytecode.is_empty()
        || bytecode.len() > MAX_EXECUTABLE_BYTES
        || evidence["executableBytes"].as_u64() != Some(bytecode.len() as u64)
        || executable_sha256 != pins.executable_sha256
        || hash_field(&evidence["executableSha256"])? != executable_sha256
        || artifact_sha256 != pins.artifact_sha256
        || code_hash != pins.code_hash
    {
        return Err("Offline artifact bytes or independent hash pins differ".into());
    }
    let source_closure_sha256 = source_closure(suite, Some(&evidence["sources"]))?;
    if source_closure_sha256 != pins.source_closure_sha256 {
        return Err("Current ordered source closure differs from its independent pin".into());
    }
    check_fields(evidence, suite)?;
    check_methods(compiled, suite)?;
    Ok(FrozenArtifact {
        class: suite.probe(),
        bytecode,
        code_hash,
        artifact_sha256,
        executable_sha256,
        source_closure_sha256,
        public_methods: compiled.public_methods.clone(),
    })
}

/// Review-pin preparation only: computing this fingerprint grants no approval.
/// SHA256(domain || repeated u32BE path-length || UTF-8 origin path ||
/// SHA256(source bytes) || u64BE source-byte-length), in Suite::sources order.
pub(crate) fn source_closure_fingerprint(suite: Suite) -> Result<Hash, String> {
    source_closure(suite, None)
}

fn source_closure(suite: Suite, supplied: Option<&Value>) -> Result<Hash, String> {
    let sources = suite.sources();
    if sources.is_empty() {
        return Err("Offline artifact has no selected source closure".into());
    }
    let records = supplied
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| "Missing ordered artifact source records".to_owned())
        })
        .transpose()?;
    if records.is_some_and(|rows| rows.len() != sources.len()) {
        return Err("Artifact source inventory omits or adds selected sources".into());
    }
    let mut paths = BTreeSet::new();
    let mut digest = Sha256::new();
    digest.update(SOURCE_CLOSURE_DOMAIN);
    for (index, source) in sources.iter().enumerate() {
        if source.origin.is_empty()
            || source.filename.is_empty()
            || !paths.insert(source.origin)
            || source.bytes.is_empty()
            || source.bytes.len() > 131_072
        {
            return Err("Invalid selected source identity or size".into());
        }
        let source_hash = sha(source.bytes);
        if let Some(rows) = records {
            check_source(&rows[index], source, source_hash)?;
        }
        let path = source.origin.as_bytes();
        let path_length = u32::try_from(path.len()).map_err(|_| "Source path exceeds u32")?;
        let byte_length =
            u64::try_from(source.bytes.len()).map_err(|_| "Source size exceeds u64")?;
        digest.update(path_length.to_be_bytes());
        digest.update(path);
        digest.update(source_hash);
        digest.update(byte_length.to_be_bytes());
    }
    Ok(digest.finalize().into())
}

fn check_source(record: &Value, source: &Source, expected_hash: Hash) -> Result<(), String> {
    if record["path"].as_str() != Some(source.origin)
        || record["bytes"].as_u64() != Some(source.bytes.len() as u64)
        || hash_field(&record["sha256"])? != expected_hash
    {
        return Err("Artifact source path, bytes or hash differs from current source".into());
    }
    Ok(())
}

fn check_fields(evidence: &Value, suite: Suite) -> Result<(), String> {
    let (names, types, mutable, counts) = match suite {
        Suite::StagedReceipt => (
            json!([
                "fpModulus",
                "expectedPayloadId",
                "stateStatus",
                "stateCursor",
                "statePairs",
                "statePoints",
                "stateRootInverse",
                "stateRoot",
                "stateAccumulator",
                "stateCorrection",
                "stateStatementId"
            ]),
            json!([
                "U256",
                "ByteVec",
                "U256",
                "U256",
                "[U256;18]",
                "[U256;18]",
                "[U256;12]",
                "[U256;12]",
                "[U256;12]",
                "[U256;6]",
                "ByteVec"
            ]),
            json!([
                false, false, true, true, true, true, true, true, true, true, true
            ]),
            (2, 81),
        ),
        Suite::SettlementData => (json!(["data"]), json!(["ByteVec"]), json!([false]), (1, 0)),
        Suite::SettlementFactoryCompile => (
            json!([
                "proofTemplateId",
                "proofTemplateCodeHash",
                "dataTemplateId",
                "dataTemplateCodeHash",
                "approvedImageId",
                "l1Network",
                "l1GenesisId",
                "l2ChainId",
                "l2GenesisId",
                "executionProfile",
                "genesisCheckpointSha256",
                "genesisHead",
                "transportLimits",
                "maxFutureSeconds",
                "initialized",
                "acceptedHead",
                "acceptedRoot"
            ]),
            json!([
                "ByteVec", "ByteVec", "ByteVec", "ByteVec", "ByteVec", "ByteVec", "ByteVec",
                "U256", "ByteVec", "ByteVec", "ByteVec", "ByteVec", "ByteVec", "U256", "U256",
                "ByteVec", "ByteVec"
            ]),
            json!([
                false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, true, true, true
            ]),
            (14, 3),
        ),
        _ => return Err("Unsupported offline artifact field class".into()),
    };
    if evidence["fieldsSignature"] != json!({"names":names, "types":types, "isMutable":mutable})
        || evidence["immutableFieldCount"].as_u64() != Some(counts.0)
        || evidence["mutableFieldCount"].as_u64() != Some(counts.1)
    {
        return Err("Offline artifact constructor fields differ from the exact ABI".into());
    }
    Ok(())
}

fn check_methods(compiled: &Compiled, suite: Suite) -> Result<(), String> {
    let names: &[&str] = match suite {
        Suite::StagedReceipt => &["begin", "advance", "finish", "getAcceptance", "getBinding"],
        Suite::SettlementData => &["getHash", "getLength", "getData"],
        Suite::SettlementFactoryCompile => &[
            "initializeGenesis",
            "createCandidate",
            "finalize",
            "getAnchor",
        ],
        _ => return Err("Unsupported offline artifact method class".into()),
    };
    let reported = compiled.evidence["publicMethodIndices"]
        .as_object()
        .ok_or("Missing reported public method inventory")?;
    if compiled.public_methods.len() != names.len() || reported.len() != names.len() {
        return Err("Offline artifact omits or adds public methods".into());
    }
    let mut indices = BTreeSet::new();
    for name in names {
        let index = *compiled
            .public_methods
            .get(*name)
            .ok_or("Missing required public method")?;
        let reported_index = reported
            .get(*name)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        if reported_index != Some(index) || !indices.insert(index) {
            return Err("Reported public method index differs or is duplicated".into());
        }
    }
    if compiled.public_methods.get(suite.entry()).copied() != Some(compiled.method_index) {
        return Err("Offline artifact selected entry index differs".into());
    }
    Ok(())
}
