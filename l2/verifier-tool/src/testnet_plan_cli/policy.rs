//! Explicit private policy schema; no inferred live identity or funding.
use super::io;
use crate::testnet_plan::{
    Actor, ArtifactPins, DeploymentVector, OperationLimit, Policy, TotalLimit,
};
use num_bigint::BigUint;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub(super) struct ArtifactInput {
    pub artifact: PathBuf,
    pub evidence: PathBuf,
    pub evidence_sha256: [u8; 32],
    pub pins: ArtifactPins,
}

pub(super) struct Inputs {
    pub actor: Actor,
    pub policy: Policy,
    pub limits: [OperationLimit; 2],
    pub total: TotalLimit,
    pub artifacts: [ArtifactInput; 3],
    pub vector: Option<DeploymentVector>,
    pub policy_sha256: [u8; 32],
    pub vector_sha256: Option<[u8; 32]>,
}

pub(super) fn load(path: &Path, key: &str, l1_genesis: &str) -> Result<Inputs, String> {
    let bytes = io::read(path, 65536)?;
    let value = io::json(&bytes)?;
    io::object(
        &value,
        &[
            "schema",
            "canonicalSource",
            "l2ChainId",
            "l2Genesis",
            "executionProfile",
            "approvedImage",
            "programSha256",
            "genesisCheckpointPath",
            "genesisCheckpointSha256",
            "genesisHead",
            "capacity",
            "transportLimits",
            "maxFutureSeconds",
            "confirmations",
            "minimumContractDepositAtto",
            "templateLimits",
            "totalLimits",
            "artifacts",
            "simulation",
        ],
    )?;
    if value["schema"] != 1 {
        return Err("Unsupported offline policy schema".into());
    }
    let actor = Actor {
        public_key: io::hex_bytes(key)?,
        canonical_source: io::hash(&value, "canonicalSource")?,
    };
    let capacity = &value["capacity"];
    io::object(capacity, &["blockGas", "blockBytes", "maxPending"])?;
    let checkpoint = io::read(Path::new(io::text(&value, "genesisCheckpointPath")?), 3000)?;
    let policy = Policy {
        l1_genesis: io::hex_bytes(l1_genesis)?,
        l2_chain_id: io::number(&value, "l2ChainId")?,
        l2_genesis: io::hash(&value, "l2Genesis")?,
        execution_profile: io::hash(&value, "executionProfile")?,
        approved_image: io::hash(&value, "approvedImage")?,
        program_sha256: io::hash(&value, "programSha256")?,
        genesis_checkpoint: checkpoint,
        genesis_checkpoint_sha256: io::hash(&value, "genesisCheckpointSha256")?,
        genesis_head: io::hex_bytes(io::text(&value, "genesisHead")?)?,
        capacity: [
            io::number(capacity, "blockGas")?,
            io::number(capacity, "blockBytes")?,
            io::number(capacity, "maxPending")?,
        ],
        transport_limits: io::hash(&value, "transportLimits")?,
        max_future_seconds: io::number(&value, "maxFutureSeconds")?,
        confirmations: io::number(&value, "confirmations")?,
        minimum_contract_deposit: amount(&value, "minimumContractDepositAtto")?,
    };
    policy.validate(&actor)?;
    let rows = value["templateLimits"]
        .as_array()
        .ok_or("Template limits must be an array")?;
    if rows.len() != 2 {
        return Err("Exactly two template operation limits are required".into());
    }
    let limits = [operation(&rows[0])?, operation(&rows[1])?];
    for limit in &limits {
        limit.validate(&policy.minimum_contract_deposit)?;
    }
    let total_value = &value["totalLimits"];
    io::object(
        total_value,
        &["feeMaxAtto", "depositMaxAtto", "totalDebitMaxAtto"],
    )?;
    let total = TotalLimit {
        fee_max: amount(total_value, "feeMaxAtto")?,
        deposit_max: amount(total_value, "depositMaxAtto")?,
        debit_max: amount(total_value, "totalDebitMaxAtto")?,
    };
    let fee = &limits[0].fee_max + &limits[1].fee_max;
    let deposit = &limits[0].deposit + &limits[1].deposit;
    if total.fee_max < fee
        || total.deposit_max < deposit
        || total.debit_max < &total.fee_max + &total.deposit_max
    {
        return Err("Total limits cannot cover the supplied two-template budget".into());
    }
    let artifacts = &value["artifacts"];
    io::object(artifacts, &["proof", "data", "factory"])?;
    let artifacts = [
        artifact(&artifacts["proof"])?,
        artifact(&artifacts["data"])?,
        artifact(&artifacts["factory"])?,
    ];
    let (vector, vector_sha256) = if value["simulation"].is_null() {
        (None, None)
    } else {
        let simulation = &value["simulation"];
        io::object(
            simulation,
            &[
                "deploymentVectorPath",
                "deploymentVectorSha256",
                "fundingIsSimulated",
                "vectorIsIndependentSourceDerived",
            ],
        )?;
        if simulation["fundingIsSimulated"] != true
            || simulation["vectorIsIndependentSourceDerived"] != true
        {
            return Err("Offline aggregate requires explicit simulated-funding and independent-vector acknowledgements".into());
        }
        let vector_sha256 = io::hash(simulation, "deploymentVectorSha256")?;
        let vector = io::pinned_json(
            Path::new(io::text(simulation, "deploymentVectorPath")?),
            vector_sha256,
        )?;
        io::object(
            &vector,
            &[
                "schema",
                "actor_reference",
                "actor_group",
                "deployment_vector",
                "provenance",
                "signing_or_proof",
            ],
        )?;
        if vector["schema"] != 1
            || vector["actor_group"] != 0
            || vector["signing_or_proof"] != false
            || io::text(&vector, "actor_reference")?.is_empty()
            || io::text(&vector, "provenance")?.is_empty()
        {
            return Err("Independent source-derived fixture metadata differs".into());
        }
        let raw_vector = &vector["deployment_vector"];
        io::object(
            raw_vector,
            &["tx_id", "output_index", "expected_contract_id"],
        )?;
        let vector = DeploymentVector {
            tx_id: io::hash(raw_vector, "tx_id")?,
            output_index: u32::try_from(io::number(raw_vector, "output_index")?)
                .map_err(|_| "Vector output index exceeds u32")?,
            expected_contract_id: io::hash(raw_vector, "expected_contract_id")?,
        };
        (Some(vector), Some(vector_sha256))
    };
    Ok(Inputs {
        actor,
        policy,
        limits,
        total,
        artifacts,
        vector,
        policy_sha256: io::sha(&bytes),
        vector_sha256,
    })
}

fn artifact(value: &Value) -> Result<ArtifactInput, String> {
    io::object(
        value,
        &[
            "artifactPath",
            "evidencePath",
            "evidenceSha256",
            "artifactSha256",
            "executableSha256",
            "codeHash",
            "sourceClosureSha256",
        ],
    )?;
    Ok(ArtifactInput {
        artifact: io::existing(Path::new(io::text(value, "artifactPath")?))?,
        evidence: io::existing(Path::new(io::text(value, "evidencePath")?))?,
        evidence_sha256: io::hash(value, "evidenceSha256")?,
        pins: ArtifactPins {
            artifact_sha256: io::hash(value, "artifactSha256")?,
            executable_sha256: io::hash(value, "executableSha256")?,
            code_hash: io::hash(value, "codeHash")?,
            source_closure_sha256: io::hash(value, "sourceClosureSha256")?,
        },
    })
}

fn amount(value: &Value, key: &str) -> Result<BigUint, String> {
    let text = io::text(value, key)?;
    if text.is_empty()
        || text.len() > 78
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("Amounts require bounded canonical decimal strings".into());
    }
    let amount = BigUint::parse_bytes(text.as_bytes(), 10).ok_or("Invalid decimal amount")?;
    if amount.bits() > 256 {
        return Err("Policy amount exceeds U256".into());
    }
    Ok(amount)
}

fn operation(value: &Value) -> Result<OperationLimit, String> {
    io::object(
        value,
        &[
            "gasAmountMax",
            "gasPriceMaxAtto",
            "feeMaxAtto",
            "depositAtto",
            "totalDebitMaxAtto",
            "requestBytesMax",
            "responseBytesMax",
            "connectTimeoutMs",
            "requestTimeoutMs",
        ],
    )?;
    Ok(OperationLimit {
        gas_amount_max: u32::try_from(io::number(value, "gasAmountMax")?)
            .map_err(|_| "Gas ceiling exceeds u32")?,
        gas_price_max: amount(value, "gasPriceMaxAtto")?,
        fee_max: amount(value, "feeMaxAtto")?,
        deposit: amount(value, "depositAtto")?,
        debit_max: amount(value, "totalDebitMaxAtto")?,
        request_bytes_max: usize::try_from(io::number(value, "requestBytesMax")?)
            .map_err(|_| "Request bound exceeds usize")?,
        response_bytes_max: usize::try_from(io::number(value, "responseBytesMax")?)
            .map_err(|_| "Response bound exceeds usize")?,
        connect_timeout_ms: io::number(value, "connectTimeoutMs")?,
        request_timeout_ms: io::number(value, "requestTimeoutMs")?,
    })
}

pub(super) fn limits_report(inputs: &Inputs) -> Value {
    json!({"templateLimits": inputs.limits.iter().map(OperationLimit::value).collect::<Vec<_>>(),
        "suppliedTotalLimits": {"feeMaxAtto": inputs.total.fee_max.to_string(), "depositMaxAtto": inputs.total.deposit_max.to_string(),
            "totalDebitMaxAtto": inputs.total.debit_max.to_string()}, "qualification": "only covers two draft templates; thirty-operation live budget remains pending"})
}
