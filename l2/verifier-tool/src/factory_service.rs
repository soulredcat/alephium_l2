//! Synthetic factory creation and canonical-child acceptance; never live deployment.
use crate::{
    cases::{FP_MODULUS, word},
    compiler::Compiled,
    factory_state::{checked_states, child_state, envelope, fixture_id, state_at},
    staged_cases::{self, Fixture, bytes},
    staged_service,
    staged_state::{asset, fingerprint},
    transport::{ProbeError, ReadOnlyNode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_FACTORY_REQUESTS: usize = 20;
// Independently computed with Python hashlib.blake2b(digest_size=32) twice over
// parent || 7631, replacing byte 31 with group 0, per v4.7.0 ContractId.scala.
// This fixed fixture pin avoids adding a runtime cryptographic dependency.
const CHILD_ID: &str = "4230bd56756cae099c977897889a1641fddbafff080a97fdbdc762f0de9b2c00";

pub fn execute(
    node: &ReadOnlyNode,
    factory: &Compiled,
    child: &Compiled,
    report: &mut Value,
) -> Result<(), String> {
    let create = *factory
        .public_methods
        .get("create")
        .ok_or("Missing factory create")?;
    let accepted = *factory
        .public_methods
        .get("accepted")
        .ok_or("Missing factory accepted")?;
    if factory.public_methods.len() != 2 {
        return Err("Unexpected public factory entry point".into());
    }
    let factory_id = fixture_id(b"ALPH/L2/stagedfactory/development-fixture/v1");
    let child_id = canonical_child_id()?;
    let fixture = Fixture::at_id(&child_id)?;
    let template_id = fixture_id(b"ALPH/L2/stagedfactory/template-fixture/v1");
    let template = child_state(child, &template_id, staged_cases::initial_fields());
    let immutable = json!([
        bytes(&hex::encode(template_id)),
        child.evidence["productionCodeHash"]
            .as_str()
            .map(bytes)
            .ok_or("Missing native template code hash")?,
        word(FP_MODULUS)
    ]);
    let root_state = json!({"address": staged_cases::contract_address(&factory_id),
        "bytecode": factory.bytecode, "codeHash": factory.evidence["productionCodeHash"],
        "immFields": immutable, "mutFields": [], "asset": asset()});
    report["factoryLifecycle"] = json!({
        "scope": "mainnet-pinned synthetic read-only VM factory creation and gate",
        "fixtureFactoryId": hex::encode(factory_id), "childPath": "7631",
        "independentlyDerivedChildId": CHILD_ID,
        "childDerivation": "Blake2b256(Blake2b256(factoryId || path)), final byte = group 0",
        "derivationSource": "https://github.com/alephium/alephium/blob/v4.7.0/protocol/src/main/scala/org/alephium/protocol/model/ContractId.scala",
        "inputAssetSchemaSource": "https://github.com/alephium/alephium/blob/v4.7.0/api/src/main/scala/org/alephium/api/model/TestInputAsset.scala",
        "factoryImmutableConfigurationPinned": true, "maximumFactoryRequests": MAX_FACTORY_REQUESTS,
        "maximumCanonicalChildRequests": 12, "virtualCallerAttoAlph": "1000000000000000000",
        "virtualChildDepositAttoAlph": "100000000000000000", "signed": false,
        "templateTrust": "synthetically supplied pinned production code, not prover authority",
        "canonicalStateSource": "VM copyCreateSubContract result then checked canonical child transitions",
        "syntheticCreationProven": false, "realCanonicalDeploymentProven": false,
        "realOnChainContinuityProven": false, "durableStateProven": false,
        "settlementAccepted": false, "forgedCanonicalOriginUsed": false
    });
    let mut run = Run {
        node,
        factory,
        root_state,
        report,
        records: Vec::new(),
    };
    let statement = &fixture.statement_id;
    run.reject(
        "acceptance-before-create",
        accepted,
        vec![bytes(statement)],
        &[],
        1513,
    )?;
    let mut invalid_modulus = run.request(create, Vec::new(), std::slice::from_ref(&template));
    invalid_modulus["initialImmFields"][2] = word("0");
    run.reject_request("factory-wrong-modulus", invalid_modulus, 1510)?;
    let wrong_template = state_at(&run.root_state, &template_id);
    run.reject(
        "factory-wrong-template-code",
        create,
        Vec::new(),
        &[wrong_template],
        1511,
    )?;

    let created = run.create(create, child, &template, &child_id)?;
    run.reject(
        "duplicate-create",
        create,
        Vec::new(),
        &[template.clone(), created.clone()],
        1512,
    )?;
    run.reject(
        "acceptance-before-finish",
        accepted,
        vec![bytes(statement)],
        std::slice::from_ref(&created),
        1514,
    )?;

    // Attack fixture only: an arbitrary same-code clone is deliberately injected
    // at a different ID with forged final status. It never becomes the origin.
    let clone_id = fixture_id(b"ALPH/L2/stagedfactory/forged-clone-fixture/v1");
    let mut forged = staged_cases::initial_fields();
    forged[0] = word("3");
    forged[staged_cases::MUTABLE_WORDS] = bytes(statement);
    let clone = child_state(child, &clone_id, forged);
    run.clone_view(child, &clone, statement)?;
    run.reject(
        "forged-clone-without-canonical-child",
        accepted,
        vec![bytes(statement)],
        std::slice::from_ref(&clone),
        1513,
    )?;
    run.reject(
        "forged-clone-canonical-still-pending",
        accepted,
        vec![bytes(statement)],
        &[created.clone(), clone],
        1514,
    )?;
    let substituted = state_at(&run.root_state, &child_id);
    run.reject(
        "canonical-address-wrong-executable",
        accepted,
        vec![bytes(statement)],
        &[substituted],
        1511,
    )?;

    let mut child_report = json!({"results": [], "passed": false});
    let final_state =
        staged_service::execute_canonical(node, child, &mut child_report, &child_id, &created);
    run.report["canonicalChildLifecycle"] = child_report;
    let final_state = final_state?;
    if final_state["mutFields"][staged_cases::MUTABLE_WORDS] != bytes(statement) {
        return Err(
            "Completed canonical child has a different independent statement identity".into(),
        );
    }
    let wrong = staged_cases::different_id(statement)?;
    run.reject(
        "accepted-wrong-statement",
        accepted,
        vec![bytes(&wrong)],
        std::slice::from_ref(&final_state),
        1515,
    )?;
    run.reject(
        "accepted-malformed-statement",
        accepted,
        vec![bytes("00")],
        std::slice::from_ref(&final_state),
        1515,
    )?;
    run.accepted(accepted, statement, &final_state)?;
    run.report["factoryLifecycle"]["syntheticCreationProven"] = json!(true);
    run.report["factoryLifecycle"]["canonicalGenesisFieldsMatched"] = json!(true);
    run.report["factoryLifecycle"]["nativeTemplateCodeHashMatched"] = json!(true);
    run.report["factoryLifecycle"]["forgedCloneCannotSubstituteForCanonicalChild"] = json!(true);
    run.report["factoryLifecycle"]["canonicalCompleteFlowAndGatePassed"] = json!(true);
    run.report["factoryLifecycle"]["finalCheckpointSha256"] = json!(fingerprint(
        final_state["mutFields"]
            .as_array()
            .ok_or("Missing final fields")?
    ));
    let child_count = run.report["canonicalChildLifecycle"]["executedCases"]
        .as_u64()
        .ok_or("Missing canonical child request count")?;
    run.report["executedCases"] = json!(run.records.len() as u64 + child_count);
    run.report["passed"] = json!(true);
    Ok(())
}

pub(crate) fn canonical_child_id() -> Result<[u8; 32], String> {
    hex::decode(CHILD_ID)
        .map_err(|_| "Invalid pinned child ID")?
        .try_into()
        .map_err(|_| "Invalid child width".into())
}

pub(crate) struct Run<'a> {
    node: &'a ReadOnlyNode,
    factory: &'a Compiled,
    root_state: Value,
    pub(crate) report: &'a mut Value,
    pub(crate) records: Vec<Value>,
}

impl<'a> Run<'a> {
    pub(crate) fn new(
        node: &'a ReadOnlyNode,
        factory: &'a Compiled,
        root_state: Value,
        report: &'a mut Value,
    ) -> Self {
        Self {
            node,
            factory,
            root_state,
            report,
            records: Vec::new(),
        }
    }

    fn request(&self, method: usize, args: Vec<Value>, existing: &[Value]) -> Value {
        let funding = if Some(&method) == self.factory.public_methods.get("create") {
            // P2PKH 00 || 31 zero bytes || fb has group 0 under v4.7.0
            // DjbHash/ScriptHint. No public key or private key is generated.
            json!([{"address": format!("{}5L", "1".repeat(32)),
                "asset": {"attoAlphAmount": "1000000000000000000", "tokens": []}}])
        } else {
            json!([])
        };
        json!({"group": 0, "address": self.root_state["address"],
            "bytecode": self.factory.bytecode, "initialImmFields": self.root_state["immFields"],
            "initialMutFields": [], "initialAsset": asset(), "methodIndex": method, "args": args,
            "existingContracts": existing, "inputAssets": funding,
            "dustAmount": "1000000000000000"})
    }

    fn send(&mut self, request: &Value) -> Result<Value, ProbeError> {
        if self.records.len() >= MAX_FACTORY_REQUESTS {
            return Err(ProbeError::Deadline);
        }
        self.report["factoryLifecycle"]["factoryRequests"] = json!(self.records.len() + 1);
        self.node.test(request)
    }

    fn record(&mut self, entry: Value) -> Result<(), String> {
        let passed = entry["passed"] == true;
        let name = entry["name"].as_str().unwrap_or("unknown").to_owned();
        self.records.push(entry);
        self.report["results"] = json!(self.records);
        if passed {
            Ok(())
        } else {
            Err(format!(
                "Factory case {name} failed; response payload suppressed"
            ))
        }
    }

    pub(crate) fn reject(
        &mut self,
        name: &str,
        method: usize,
        args: Vec<Value>,
        existing: &[Value],
        code: u64,
    ) -> Result<(), String> {
        self.reject_request(name, self.request(method, args, existing), code)
    }

    fn reject_request(&mut self, name: &str, request: Value, code: u64) -> Result<(), String> {
        let (passed, actual, outcome) = match self.send(&request) {
            Err(ProbeError::VmAssertion(actual)) => (actual == code, Some(actual), "vm-assertion"),
            Err(ProbeError::VmGasExhausted) => (false, None, "vm-gas-exhausted"),
            Err(ProbeError::Deadline) => (false, None, "deadline-or-request-bound"),
            Err(ProbeError::Transport) => (false, None, "transport-or-response-error"),
            Ok(_) => (false, None, "unexpected-vm-success"),
        };
        self.record(json!({"name": name, "passed": passed, "outcome": outcome,
            "expectedAssertionCode": code, "assertionCode": actual,
            "carriedCanonicalStateUnchanged": true, "realOnChainRollbackProven": false}))
    }

    fn success(&mut self, name: &str, request: &Value) -> Result<Value, String> {
        match self.send(request) {
            Ok(response) => Ok(response),
            Err(error) => {
                let label = match error {
                    ProbeError::VmAssertion(_) => "vm-assertion",
                    ProbeError::VmGasExhausted => "vm-gas-exhausted",
                    ProbeError::Transport => "transport-or-response-error",
                    ProbeError::Deadline => "deadline-or-request-bound",
                };
                self.record(json!({"name": name, "passed": false, "outcome": label}))?;
                Err("Factory execution failed".into())
            }
        }
    }

    pub(crate) fn create(
        &mut self,
        method: usize,
        child: &Compiled,
        template: &Value,
        id: &[u8; 32],
    ) -> Result<Value, String> {
        let request = self.request(method, Vec::new(), std::slice::from_ref(template));
        let response = self.success("canonical-factory-create", &request)?;
        let expected = child_state(child, id, staged_cases::initial_fields());
        let owned = checked_states(&response, &[&self.root_state, template, &expected]);
        let events = response["events"].as_array();
        let mut system_id = [0_u8; 32];
        system_id[30] = 0xff;
        let event_matched = events.is_some_and(|events| {
            events.len() == 1
                && events[0]["eventIndex"] == -1
                && events[0]["contractAddress"] == staged_cases::contract_address(&system_id)
                && events[0]["fields"]
                    == json!([
                        {"type": "Address", "value": expected["address"]},
                        {"type": "Address", "value": self.root_state["address"]}, bytes("")
                    ])
        });
        let passed = envelope(&response, &self.root_state)
            && owned.is_ok()
            && response["returns"] == json!([bytes(CHILD_ID)])
            && event_matched;
        self.record(json!({"name": "canonical-factory-create", "passed": passed,
            "outcome": "vm-success", "gasUsed": response["gasUsed"],
            "derivedChildIdMatched": response["returns"] == json!([bytes(CHILD_ID)]),
            "factoryTemplateAndChildStateMatched": owned.is_ok(), "stateValidationError": owned.as_ref().err(),
            "systemCreationEventMatched": event_matched, "newMutableWords": 80,
            "newMutableByteVecBytes": 32, "createdCheckpointSha256": fingerprint(&staged_cases::initial_fields())}))?;
        let states = owned?;
        states
            .into_iter()
            .find(|state| state["address"] == expected["address"])
            .ok_or("Missing VM-created canonical child".into())
    }

    fn clone_view(
        &mut self,
        child: &Compiled,
        clone: &Value,
        statement: &str,
    ) -> Result<(), String> {
        let view = child
            .public_methods
            .get("getAcceptance")
            .ok_or("Missing child acceptance view")?;
        let request = json!({"group": 0, "address": clone["address"], "bytecode": child.bytecode,
            "initialImmFields": clone["immFields"], "initialMutFields": clone["mutFields"],
            "initialAsset": asset(), "methodIndex": view, "args": [], "existingContracts": [], "inputAssets": []});
        let response = self.success("forged-clone-claims-final-view", &request)?;
        let checked = checked_states(&response, &[clone]);
        self.record(json!({"name": "forged-clone-claims-final-view",
            "passed": envelope(&response, clone) && checked.is_ok() && response["events"] == json!([])
                && response["returns"] == json!([word("3"), bytes(statement)]),
            "outcome": "vm-success", "gasUsed": response["gasUsed"], "syntheticallyForgedAttackState": true,
            "canonicalOriginEvidence": false, "stateValidationError": checked.as_ref().err()}))
    }

    pub(crate) fn accepted(
        &mut self,
        method: usize,
        statement: &str,
        final_state: &Value,
    ) -> Result<(), String> {
        let request = self.request(
            method,
            vec![bytes(statement)],
            std::slice::from_ref(final_state),
        );
        let response = self.success("canonical-factory-accepted", &request)?;
        let checked = checked_states(&response, &[&self.root_state, final_state]);
        self.record(json!({"name": "canonical-factory-accepted",
            "passed": envelope(&response, &self.root_state) && checked.is_ok()
                && response["returns"] == json!([bytes(statement)]) && response["events"] == json!([]),
            "outcome": "vm-success", "gasUsed": response["gasUsed"],
            "canonicalChildAndFactoryUnchanged": checked.is_ok(), "stateValidationError": checked.as_ref().err(),
            "statementIdentityHexSha256": hex::encode(Sha256::digest(statement.as_bytes()))}))
    }
}
