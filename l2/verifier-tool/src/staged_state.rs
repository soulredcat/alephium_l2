//! Trust boundary for VM-produced staged checkpoints and immutable regions.
use crate::{
    cases::{FP_MODULUS, word},
    compiler::Compiled,
    staged_cases::{Fixture, MAX_REQUESTS, MUTABLE_WORDS, bytes},
    transport::{ProbeError, ReadOnlyNode},
};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[allow(clippy::too_many_arguments)]
pub fn checked_fields(
    result: &Value,
    compiled: &Compiled,
    fixture: &Fixture,
    previous: &[Value],
    method: usize,
    phase: u64,
    cursor: u64,
    id: &str,
) -> Result<Vec<Value>, String> {
    let code_hash = &compiled.evidence["productionCodeHash"];
    if result["address"] != fixture.address
        || result["codeHash"] != *code_hash
        || result["events"] != json!([])
        || result["debugMessages"] != json!([])
    {
        return Err("Staged response target, executable or side effects differ".into());
    }
    let contracts = result["contracts"]
        .as_array()
        .ok_or("Missing VM contract states")?;
    if contracts.len() != 1 || contracts[0]["address"] != fixture.address {
        return Err("VM result does not contain exactly the owned isolated contract".into());
    }
    let state = &contracts[0];
    if state["bytecode"] != compiled.bytecode
        || state["codeHash"] != *code_hash
        || state["immFields"] != json!(fixture.immutable_fields())
        || state["asset"] != asset()
    {
        return Err("VM returned executable, immutable fields or virtual asset differ".into());
    }
    let fields = state["mutFields"]
        .as_array()
        .ok_or("Missing mutable VM state")?;
    if fields.len() != MUTABLE_WORDS + 1
        || previous.len() != MUTABLE_WORDS + 1
        || fields[0] != word(&phase.to_string())
        || fields[1] != word(&cursor.to_string())
        || fields[MUTABLE_WORDS] != bytes(id)
    {
        return Err("VM state phase, cursor, identity or exact layout differ".into());
    }
    let modulus = BigUint::parse_bytes(FP_MODULUS.as_bytes(), 10).ok_or("Invalid pinned Fp")?;
    for (index, field) in fields[..MUTABLE_WORDS].iter().enumerate() {
        let value = field["value"]
            .as_str()
            .ok_or("VM field is not decimal text")?;
        if field.as_object().is_none_or(|object| object.len() != 2)
            || field["type"] != "U256"
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err("VM field is not an exact canonical U256 value".into());
        }
        let integer = BigUint::parse_bytes(value.as_bytes(), 10).ok_or("Invalid VM integer")?;
        if integer.bits() > 256 || (index >= 2 && integer >= modulus) {
            return Err("VM arithmetic checkpoint coefficient is noncanonical".into());
        }
    }
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Expected independent identity has the wrong wire width".into());
    }
    if Some(&method) == compiled.public_methods.get("advance")
        && (fields[2..20] != previous[2..20]
            || fields[38..62] != previous[38..62]
            || fields[74..80] != previous[74..80])
    {
        return Err("Advance altered immutable arithmetic regions".into());
    }
    if Some(&method) == compiled.public_methods.get("finish") && fields[1..] != previous[1..] {
        return Err("Finish altered fields outside its accepted status".into());
    }
    if (Some(&method) == compiled.public_methods.get("getAcceptance")
        || Some(&method) == compiled.public_methods.get("getBinding"))
        && fields != previous
    {
        return Err("Read-only acceptance method changed state".into());
    }
    Ok(fields.clone())
}

pub fn asset() -> Value {
    json!({"attoAlphAmount": "100000000000000000", "tokens": []})
}

pub fn fingerprint(fields: &[Value]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ALPH/L2/staged-checkpoint/v1");
    for field in fields {
        digest.update(field["type"].as_str().unwrap_or("").as_bytes());
        digest.update([0]);
        digest.update(field["value"].as_str().unwrap_or("").as_bytes());
        digest.update([0]);
    }
    hex::encode(digest.finalize())
}

pub(crate) struct Run<'a> {
    node: &'a ReadOnlyNode,
    compiled: &'a Compiled,
    fixture: &'a Fixture,
    pub(crate) report: &'a mut Value,
    pub(crate) records: Vec<Value>,
    last_state: Option<Value>,
}

impl<'a> Run<'a> {
    pub(crate) fn new(
        node: &'a ReadOnlyNode,
        compiled: &'a Compiled,
        fixture: &'a Fixture,
        report: &'a mut Value,
    ) -> Self {
        Self {
            node,
            compiled,
            fixture,
            report,
            records: Vec::new(),
            last_state: None,
        }
    }

    pub(crate) fn last_contract_state(&self) -> Result<Value, String> {
        self.last_state
            .clone()
            .ok_or_else(|| "No checked VM contract state exists".into())
    }

    pub(crate) fn request(&self, method: usize, args: Vec<Value>, fields: &[Value]) -> Value {
        json!({
            "group": 0, "address": self.fixture.address, "bytecode": self.compiled.bytecode,
            "initialImmFields": self.fixture.immutable_fields(), "initialMutFields": fields,
            "initialAsset": asset(), "methodIndex": method, "args": args,
            "existingContracts": [], "inputAssets": []
        })
    }

    fn send(&mut self, request: &Value) -> Result<Value, ProbeError> {
        if self.records.len() >= MAX_REQUESTS {
            return Err(ProbeError::Deadline);
        }
        self.report["stagedLifecycle"]["requests"] = json!(self.records.len() + 1);
        self.node.test(request)
    }

    fn record(&mut self, result: Value) -> Result<(), String> {
        let passed = result["passed"] == true;
        let name = result["name"].as_str().unwrap_or("unknown").to_owned();
        self.records.push(result);
        self.report["results"] = json!(self.records);
        if passed {
            Ok(())
        } else {
            Err(format!(
                "Staged transition {name} failed; response payload suppressed"
            ))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn success(
        &mut self,
        name: &str,
        method: usize,
        args: Vec<Value>,
        fields: &[Value],
        phase: u64,
        cursor: u64,
        id: &str,
        returns: Vec<Value>,
    ) -> Result<Vec<Value>, String> {
        let request = self.request(method, args, fields);
        match self.send(&request) {
            Ok(response) => {
                let gas = response["gasUsed"].as_u64();
                let output = checked_fields(
                    &response,
                    self.compiled,
                    self.fixture,
                    fields,
                    method,
                    phase,
                    cursor,
                    id,
                );
                let passed = output.is_ok()
                    && gas.is_some_and(|amount| amount > 0 && amount <= 5_000_000)
                    && response["returns"] == json!(returns);
                self.record(json!({"name": name, "passed": passed,
                    "outcome": "vm-success", "gasUsed": gas, "status": phase, "cursor": cursor,
                    "ownedStateAndIdentityMatched": output.is_ok(),
                    "exactReturnMatched": response["returns"] == json!(returns),
                    "stateValidationError": output.as_ref().err(),
                    "checkpointSha256": output.as_ref().ok().map(|state| fingerprint(state))}))?;
                self.last_state = Some(response["contracts"][0].clone());
                output
            }
            Err(error) => {
                self.record(
                    json!({"name": name, "passed": false, "outcome": outcome(&error),
                    "assertionCode": assertion(&error)}),
                )?;
                Err("Unexpected failed staged transition".into())
            }
        }
    }

    pub(crate) fn view(
        &mut self,
        name: &str,
        method: usize,
        fields: &[Value],
        phase: u64,
        cursor: u64,
        id: &str,
    ) -> Result<(), String> {
        let next = self.success(
            name,
            method,
            Vec::new(),
            fields,
            phase,
            cursor,
            id,
            vec![word(&phase.to_string()), bytes(id)],
        )?;
        if next != fields {
            return Err("Read-only acceptance view changed carried state".into());
        }
        Ok(())
    }

    pub(crate) fn reject(
        &mut self,
        name: &str,
        method: usize,
        args: Vec<Value>,
        fields: &[Value],
        expected: u64,
    ) -> Result<(), String> {
        let request = self.request(method, args, fields);
        self.reject_request(name, request, fields, expected)
    }

    pub(crate) fn reject_request(
        &mut self,
        name: &str,
        request: Value,
        fields: &[Value],
        expected: u64,
    ) -> Result<(), String> {
        let before = fingerprint(fields);
        let response = self.send(&request);
        let (passed, label, code) = match response {
            Err(error) => (
                assertion(&error) == Some(expected),
                outcome(&error),
                assertion(&error),
            ),
            Ok(_) => (false, "unexpected-vm-success", None),
        };
        self.record(json!({"name": name, "passed": passed, "outcome": label,
            "expectedAssertionCode": expected, "assertionCode": code,
            "rejectionGasAvailable": false, "carryforwardUnchanged": before == fingerprint(fields),
            "checkpointSha256": before, "realOnChainRollbackProven": false}))
    }
}

pub fn canonical_child_fields(
    state: &Value,
    compiled: &Compiled,
    fixture: &Fixture,
) -> Result<Vec<Value>, String> {
    let zero = crate::staged_cases::initial_fields();
    if state["address"] != fixture.address
        || state["bytecode"] != compiled.bytecode
        || state["codeHash"] != compiled.evidence["productionCodeHash"]
        || state["immFields"] != json!(fixture.immutable_fields())
        || state["asset"] != asset()
        || state["mutFields"] != json!(zero)
    {
        return Err("VM-created child does not have the exact canonical zero origin".into());
    }
    let initial_hash = state["initialStateHash"]
        .as_str()
        .ok_or("Missing VM child initial-state hash")?;
    if initial_hash.len() != 64 || !initial_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("VM child initial-state hash is malformed".into());
    }
    // Clone the actual VM field array, never construct its arithmetic checkpoint.
    state["mutFields"]
        .as_array()
        .cloned()
        .ok_or_else(|| "Missing VM child fields".into())
}

fn assertion(error: &ProbeError) -> Option<u64> {
    if let ProbeError::VmAssertion(code) = error {
        Some(*code)
    } else {
        None
    }
}

fn outcome(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::VmAssertion(_) => "vm-assertion",
        ProbeError::VmGasExhausted => "vm-gas-exhausted",
        ProbeError::Transport => "transport-or-response-error",
        ProbeError::Deadline => "deadline-or-request-bound",
    }
}
