//! Pinned historical receipt ingestion and canonical Solidity hash binding.
use ark_bn254::{Fq, Fr};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Read, path::Path};
const MAX_INPUT_BYTES: u64 = 1_048_576;
const ARTIFACT_SHA256: &str = "474672cdba6abd067038e784d85e96c06638b2602f1b8675804dd40042b35be3";
const MANIFEST_SHA256: &str = "fd08bbba8c93b169275199bc6b002635ceff2038bbf72bd9f568b52290cf6c90";
const REVISION: &str = "365e7b2db4f620fa256580c27558d2623362b9ae";
const GROTH16: &str = "vendor/contracts/src/groth16/Groth16Verifier.sol";
const CONTROL: &str = "vendor/contracts/src/groth16/ControlID.sol";
const CLAIM: &str = "vendor/contracts/src/IRiscZeroVerifier.sol";
const RECEIPT: &str = "vendor/contracts/test/TestReceiptV3_0.sol";

pub(crate) struct Fixture {
    pub(crate) seal: Vec<u8>,
    pub(crate) image: [u8; 32],
    pub(crate) journal: [u8; 32],
    pub(crate) control: [u8; 32],
    pub(crate) control_id: [u8; 32],
}

pub(crate) struct KeyWords {
    pub(crate) alpha: Vec<[u8; 32]>,
    pub(crate) beta: Vec<[u8; 32]>,
    pub(crate) gamma: Vec<[u8; 32]>,
    pub(crate) delta: Vec<[u8; 32]>,
    pub(crate) ic: Vec<Vec<[u8; 32]>>,
    selector: [u8; 4],
}

pub(crate) fn load() -> Result<(Fixture, KeyWords), String> {
    let (fixture, sources) = load_inputs()?;
    let words = key_words(&sources[GROTH16], &fixture)?;
    if fixture.seal[..4] != words.selector {
        return Err(
            "Pinned receipt selector does not match independently hashed parameters".into(),
        );
    }
    Ok((fixture, words))
}
/// Safe inventory only: never return seals, proof cells, signatures or VM arguments.
pub(crate) fn evidence(case_count: usize) -> Result<Value, String> {
    let (fixture, _) = load_inputs()?;
    Ok(json!({
        "artifact_sha256": ARTIFACT_SHA256, "source_manifest_sha256": MANIFEST_SHA256,
        "risc0_revision": REVISION, "source_files": 12, "seal_bytes": fixture.seal.len(),
        "seal_sha256": hex::encode(hash(&fixture.seal)), "image_id_bytes": 32,
        "journal_bytes": 21, "journal_digest_bytes": 32, "case_count": case_count,
        "oracle": "Arkworks 0.6 Bn254 multi_pairing over independently derived five signals"
    }))
}

fn load_inputs() -> Result<(Fixture, BTreeMap<String, String>), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../node/fixtures/risc0-groth16");
    let artifact = pinned(&root.join("artifact.json"), ARTIFACT_SHA256)?;
    let manifest = pinned(&root.join("sources.json"), MANIFEST_SHA256)?;
    let manifest: Value =
        serde_json::from_slice(&manifest).map_err(|_| "Invalid pinned receipt source inventory")?;
    let entries = manifest["files"]
        .as_array()
        .ok_or("Missing receipt source inventory")?;
    if manifest["schema"] != 1 || manifest["risc0_revision"] != REVISION || entries.len() != 12 {
        return Err("Pinned receipt source inventory identity differs".into());
    }
    let mut sources = BTreeMap::new();
    for entry in entries {
        let path = text(entry, "path")?;
        let bytes = pinned(&root.join(path), text(entry, "sha256")?)?;
        if entry["bytes"].as_u64() != Some(bytes.len() as u64) {
            return Err("Pinned receipt source length differs".into());
        }
        sources.insert(
            path.into(),
            String::from_utf8(bytes).map_err(|_| "Invalid source UTF-8")?,
        );
    }
    let artifact: Value =
        serde_json::from_slice(&artifact).map_err(|_| "Invalid pinned receipt artifact")?;
    if artifact["schema"] != 1 {
        return Err("Pinned receipt artifact schema differs".into());
    }
    let value = &artifact["fixture"];
    let seal = decode(text(value, "seal")?)?;
    let image = bytes32(&decode(text(value, "image_id")?)?)?;
    let journal_bytes = decode(text(value, "journal")?)?;
    let journal = bytes32(&decode(text(value, "journal_digest")?)?)?;
    let control = bytes32(&decode(text(value, "control_root")?)?)?;
    let control_id = bytes32(&decode(text(value, "bn254_control_id")?)?)?;
    if seal.len() != 260
        || journal_bytes.len() != 21
        || hash(&journal_bytes) != journal
        || constant_hex(&sources[CONTROL], "CONTROL_ROOT")? != control
        || constant_hex(&sources[CONTROL], "BN254_CONTROL_ID")? != control_id
        || constant_hex(&sources[RECEIPT], "SEAL")? != seal
        || constant_hex(&sources[RECEIPT], "IMAGE_ID")? != image
        || constant_hex(&sources[RECEIPT], "JOURNAL")? != journal_bytes
    {
        return Err("Pinned receipt fixture/source/control or journal digest mismatch".into());
    }
    let zero_state = tagged("risc0.SystemState", &[[0; 32]], &[0; 4]);
    if constant_hex(&sources[CLAIM], "SYSTEM_STATE_ZERO_DIGEST")? != zero_state {
        return Err("Independent zero SystemState digest differs from pinned claim source".into());
    }
    Ok((
        Fixture {
            seal,
            image,
            journal,
            control,
            control_id,
        },
        sources,
    ))
}

fn key_words(source: &str, fixture: &Fixture) -> Result<KeyWords, String> {
    if constant_decimal(source, "q")? != Fq::MODULUS.to_string()
        || constant_decimal(source, "r")? != Fr::MODULUS.to_string()
    {
        return Err("Pinned Solidity BN254 moduli differ from independent Arkworks fields".into());
    }
    let coordinates = |names: &[String]| -> Result<Vec<[u8; 32]>, String> {
        names
            .iter()
            .map(|name| {
                let value = BigUint::parse_bytes(constant_decimal(source, name)?.as_bytes(), 10)
                    .ok_or("Invalid pinned verification-key integer")?;
                bytes32_padded(&value.to_bytes_be())
            })
            .collect()
    };
    let alpha = coordinates(&["alphax".into(), "alphay".into()])?;
    let group2 = |prefix| {
        coordinates(&[
            format!("{prefix}x1"),
            format!("{prefix}x2"),
            format!("{prefix}y1"),
            format!("{prefix}y2"),
        ])
    };
    let (beta, gamma, delta) = (group2("beta")?, group2("gamma")?, group2("delta")?);
    let mut ic = Vec::new();
    let mut ic_list = [0; 32];
    for index in (0..6).rev() {
        let words = coordinates(&[format!("IC{index}x"), format!("IC{index}y")])?;
        let digest = hash_words(&words);
        ic.push(words);
        ic_list = tagged("risc0_groth16.VerifyingKey.IC", &[digest, ic_list], &[]);
    }
    ic.reverse();
    let vk_digest = tagged(
        "risc0_groth16.VerifyingKey",
        &[
            hash_words(&alpha),
            hash_words(&beta),
            hash_words(&gamma),
            hash_words(&delta),
            ic_list,
        ],
        &[],
    );
    let mut reversed_control = fixture.control_id;
    reversed_control.reverse();
    let params = tagged(
        "risc0.Groth16ReceiptVerifierParameters",
        &[fixture.control, reversed_control, vk_digest],
        &[],
    );
    Ok(KeyWords {
        alpha,
        beta,
        gamma,
        delta,
        ic,
        selector: params[..4]
            .try_into()
            .map_err(|_| "Invalid derived selector length")?,
    })
}

fn constant_decimal(source: &str, name: &str) -> Result<String, String> {
    Ok(constant(source, name)?.trim().to_owned())
}

fn constant_hex(source: &str, name: &str) -> Result<Vec<u8>, String> {
    let value = constant(source, name)?.trim();
    decode(
        value
            .strip_prefix("hex\"")
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(value),
    )
}

fn constant<'a>(source: &'a str, name: &str) -> Result<&'a str, String> {
    source
        .split_once(&format!("constant {name} ="))
        .and_then(|(_, value)| value.split_once(';'))
        .map(|(value, _)| value)
        .ok_or_else(|| format!("Missing pinned Solidity constant {name}"))
}

fn pinned(path: &Path, expected: &str) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|_| "Missing pinned receipt fixture/source")?;
    if file
        .metadata()
        .map_err(|_| "Cannot inspect pinned receipt input")?
        .len()
        > MAX_INPUT_BYTES
    {
        return Err("Pinned receipt input exceeds its fixed byte bound".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read bounded receipt input")?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("Pinned receipt input grew beyond its fixed byte bound".into());
    }
    if hex::encode(hash(&bytes)) != expected {
        return Err("Pinned receipt fixture/source integrity mismatch".into());
    }
    Ok(bytes)
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value[name]
        .as_str()
        .ok_or_else(|| format!("Missing pinned receipt metadata field {name}"))
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| "Invalid pinned receipt hex".into())
}

pub(crate) fn bytes32(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "Invalid pinned receipt bytes32 length".into())
}

fn bytes32_padded(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() > 32 {
        return Err("Pinned integer exceeds 256 bits".into());
    }
    let mut word = [0; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(word)
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hash_words(words: &[[u8; 32]]) -> [u8; 32] {
    hash(&words.concat())
}

pub(crate) fn tagged(tag: &str, children: &[[u8; 32]], data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(Sha256::digest(tag.as_bytes()));
    for child in children {
        hash.update(child);
    }
    hash.update(data);
    hash.update((children.len() as u16).to_le_bytes());
    hash.finalize().into()
}
