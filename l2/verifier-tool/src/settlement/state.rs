//! Exact synthetic VM state, independently derived child IDs and bounded requests.
use super::journal::sha;
use crate::{
    compiler::Compiled,
    factory_state, staged_cases,
    staged_state::asset,
    transport::{ProbeError, ReadOnlyNode},
};
use blake2::{
    Blake2b,
    digest::{Digest, consts::U32},
};
use num_bigint::BigUint;
use serde_json::{Value, json};

pub(super) const MAX_REQUESTS: usize = 96;

pub(super) struct Ids {
    pub key: [u8; 32],
    pub proof: [u8; 32],
    pub data: [u8; 32],
}

pub(super) fn ids(
    factory: &[u8; 32],
    image: &[u8; 32],
    journal: &[u8; 32],
    seal: &[u8; 32],
    auxiliary: &[u8; 32],
) -> Ids {
    let mut preimage = b"ALPH/L2/batch-session/v1".to_vec();
    for value in [factory, image, journal, seal, auxiliary] {
        preimage.extend(value);
    }
    let key = sha(&preimage);
    let path = |prefix: &[u8]| {
        let mut path = prefix.to_vec();
        path.extend(key);
        path
    };
    Ids {
        key,
        proof: child_id(factory, &path(b"p5v1/proof/")),
        data: child_id(factory, &path(b"p5v1/data/")),
    }
}

pub(super) fn child_id(factory: &[u8; 32], path: &[u8]) -> [u8; 32] {
    let mut preimage = factory.to_vec();
    preimage.extend(path);
    let first = Blake2b::<U32>::digest(&preimage);
    let mut child: [u8; 32] = Blake2b::<U32>::digest(first).into();
    // Matches subContractId!/copyCreateSubContract! under the declared group0 VM.
    child[31] = 0;
    child
}

pub(super) fn bytes(value: &[u8]) -> Value {
    staged_cases::bytes(&hex::encode(value))
}
pub(super) fn word(value: u64) -> Value {
    crate::cases::word(&value.to_string())
}

pub(super) fn contract(
    compiled: &Compiled,
    id: &[u8; 32],
    imm: Vec<Value>,
    mutable: Vec<Value>,
) -> Result<Value, String> {
    validate_code(compiled)?;
    let fields = field_bytes(&imm)?
        .checked_add(field_bytes(&mutable)?)
        .ok_or("Field byte overflow")?;
    if fields >= 3072 {
        return Err("Settlement contract fields violate strict three-KiB bound".into());
    }
    Ok(
        json!({"address": staged_cases::contract_address(id), "bytecode": compiled.bytecode,
        "codeHash": compiled.evidence["productionCodeHash"], "immFields": imm,
        "mutFields": mutable, "asset": asset()}),
    )
}

pub(super) fn field_bytes(fields: &[Value]) -> Result<usize, String> {
    fields.iter().try_fold(0_usize, |total, field| {
        let text = field["value"]
            .as_str()
            .ok_or("Missing exact VM field value")?;
        let size = match field["type"].as_str() {
            Some("ByteVec") => {
                if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err("Noncanonical ByteVec field".into());
                }
                text.len() / 2
            }
            Some("U256") => {
                let integer =
                    BigUint::parse_bytes(text.as_bytes(), 10).ok_or("Invalid U256 field")?;
                if integer.bits() > 256 || text != integer.to_string() {
                    return Err("Noncanonical U256 field".into());
                }
                32
            }
            _ => return Err("Unsupported settlement field type".into()),
        };
        total
            .checked_add(size)
            .ok_or("VM field size overflow".into())
    })
}

pub(super) fn validate_code(compiled: &Compiled) -> Result<(), String> {
    let bytes = hex::decode(&compiled.bytecode).map_err(|_| "Invalid compiled executable")?;
    if bytes.is_empty() || bytes.len() > 32768 {
        return Err("Settlement executable exceeds target limit".into());
    }
    let hash = compiled.evidence["productionCodeHash"]
        .as_str()
        .ok_or("Missing executable identity")?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Malformed compiled executable identity".into());
    }
    Ok(())
}

pub(super) struct Run<'a> {
    pub node: &'a ReadOnlyNode,
    pub compiled: &'a Compiled,
    pub root: Value,
    pub records: Vec<Value>,
    pub timestamp_ms: u64,
}

impl<'a> Run<'a> {
    pub fn method(&self, name: &str) -> Result<usize, String> {
        self.compiled
            .public_methods
            .get(name)
            .copied()
            .ok_or_else(|| format!("Missing settlement method {name}"))
    }
    pub fn request(
        &self,
        name: &str,
        args: Vec<Value>,
        existing: &[Value],
        funded: bool,
    ) -> Result<Value, String> {
        let input_assets = if funded {
            json!([{"address": format!("{}5L", "1".repeat(32)),
            "asset": {"attoAlphAmount": "1000000000000000000", "tokens": []}}])
        } else {
            json!([])
        };
        Ok(
            json!({"group": 0, "address": self.root["address"], "bytecode": self.compiled.bytecode,
            "initialImmFields": self.root["immFields"], "initialMutFields": self.root["mutFields"],
            "initialAsset": asset(), "methodIndex": self.method(name)?, "args": args,
            "existingContracts": existing, "inputAssets": input_assets,
            "dustAmount": "1000000000000000", "blockTimeStamp": self.timestamp_ms}),
        )
    }
    pub fn reject(&mut self, name: &str, request: Value, code: u64) -> Result<(), String> {
        let (passed, actual, outcome) = match self.send(&request) {
            Err(ProbeError::VmAssertion(actual)) => (actual == code, Some(actual), "vm-assertion"),
            Err(ProbeError::VmGasExhausted) => (false, None, "vm-gas-exhausted"),
            Err(ProbeError::Deadline) => (false, None, "request-bound"),
            Err(ProbeError::Transport) => (false, None, "transport-or-response-error"),
            Ok(_) => (false, None, "unexpected-vm-success"),
        };
        self.record(json!({"name": name, "passed": passed, "outcome": outcome,
            "expectedAssertionCode": code, "assertionCode": actual,
            "carriedStateUnchanged": true, "onchainRollbackEstablished": false}))
    }
    pub fn success(
        &mut self,
        name: &str,
        request: Value,
        expected: &[Value],
        returns: Vec<Value>,
        creation_ids: &[[u8; 32]],
    ) -> Result<Vec<Value>, String> {
        let response = self.send(&request).map_err(|error| match error {
            ProbeError::VmAssertion(_) => "Settlement positive VM assertion; payload suppressed",
            ProbeError::VmGasExhausted => "Settlement positive VM gas exhausted",
            ProbeError::Deadline => "Settlement request inventory exceeded",
            ProbeError::Transport => "Settlement transport/response error; payload suppressed",
        })?;
        let expected_refs: Vec<_> = expected.iter().collect();
        let states = factory_state::checked_states(&response, &expected_refs);
        let events_match = creation_events(&response, &self.root, creation_ids);
        let passed = factory_state::envelope(&response, &self.root)
            && states.is_ok()
            && response["returns"] == json!(returns)
            && events_match;
        self.record(json!({"name": name, "passed": passed, "outcome": "vm-success",
            "gasUsed": response["gasUsed"], "exactStateMatched": states.is_ok(),
            "exactReturnsMatched": response["returns"] == json!(returns), "creationEventsMatched": events_match}))?;
        let states = states?;
        self.root = states
            .iter()
            .find(|state| state["address"] == self.root["address"])
            .cloned()
            .ok_or("Missing updated settlement state")?;
        Ok(states)
    }
    fn send(&self, request: &Value) -> Result<Value, ProbeError> {
        if self.records.len() >= MAX_REQUESTS {
            return Err(ProbeError::Deadline);
        }
        self.node.test(request)
    }
    fn record(&mut self, record: Value) -> Result<(), String> {
        let passed = record["passed"] == true;
        let name = record["name"].as_str().unwrap_or("unknown").to_owned();
        self.records.push(record);
        if passed {
            Ok(())
        } else {
            Err(format!(
                "Settlement case {name} failed; response suppressed"
            ))
        }
    }
}

fn creation_events(response: &Value, root: &Value, ids: &[[u8; 32]]) -> bool {
    let Some(events) = response["events"].as_array() else {
        return false;
    };
    if events.len() != ids.len() {
        return false;
    }
    let mut system = [0; 32];
    system[30] = 0xff;
    events.iter().zip(ids).all(|(event, id)| {
        event["eventIndex"] == -1
            && event["contractAddress"] == staged_cases::contract_address(&system)
            && event["fields"]
                == json!([{"type": "Address", "value": staged_cases::contract_address(id)},
            {"type": "Address", "value": root["address"]}, staged_cases::bytes("")])
    })
}
