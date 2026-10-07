//! Predictions from exact approved unsigned deployments; no asserted identities.
use super::{literal, types::*};
use alephium_l2_sdk::alephium::ValidatedUnsignedAlephium;

impl Deployment {
    pub fn from_unsigned(
        draft: &ScriptDraft,
        script: &CompiledScript,
        unsigned: &ValidatedUnsignedAlephium,
        actor: &Actor,
        policy: &Policy,
    ) -> Result<Self, String> {
        if !matches!(
            draft.kind,
            "deploy-proof-template" | "deploy-data-template" | "deploy-factory"
        ) || literal::sha(draft.source.as_bytes()) != draft.source_sha256
            || script.source_sha256 != draft.source_sha256
            || literal::sha(&script.bytes) != script.script_sha256
            || literal::blake(&script.bytes) != script.script_blake2b256
        {
            return Err("Reviewed exact deployment script required".into());
        }
        policy.validate(actor)?;
        let request_floor = unsigned
            .unsigned_bytes()
            .len()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or("Deployment request bound overflow")?;
        if request_floor > draft.limits.request_bytes_max {
            return Err("Actual deployment unsigned request exceeds approved byte bound".into());
        }
        let operation = unsigned.operation();
        let spec = operation.spec();
        if operation.script_bytes() != Some(script.bytes.as_slice())
            || spec.source_artifact_sha256.as_slice() != script.artifact_sha256
            || spec.script_blake2b256.map(|hash| hash.0) != Some(script.script_blake2b256)
            || spec.caller_public_key != actor.public_key
            || spec.funding.group != 0
            || spec.funding.group_count != 4
            || spec.funding.network_id != 1
            || spec.funding.network_genesis_id.as_slice() != policy.l1_genesis
            || spec.funding.source_id.as_slice() != actor.canonical_source
            || spec.limits.max_gas_amount > draft.limits.gas_amount_max
            || spec
                .limits
                .max_gas_price
                .to_string()
                .parse::<num_bigint::BigUint>()
                .map_err(|_| "Invalid approved gas price")?
                > draft.limits.gas_price_max
            || spec.limits.contract_deposit.to_string() != draft.limits.deposit.to_string()
            || unsigned
                .fee()
                .to_string()
                .parse::<num_bigint::BigUint>()
                .map_err(|_| "Invalid validated fee")?
                > draft.limits.fee_max
        {
            return Err("Deployment funding/script/authority differs from frozen operation".into());
        }
        // Our closed deployment script creates exactly one contract. Existing
        // fixed outputs precede it; do not guess zero or embed this ID in source.
        let index = unsigned.fixed_output_count();
        let tx_id: [u8; 32] = unsigned.tx_id().0;
        let expected_code_hash = hex::decode(
            draft.expected_effect["expectedCodeHash"]
                .as_str()
                .ok_or("Deployment effect lacks exact code hash")?,
        )
        .map_err(|_| "Deployment code hash invalid")?
        .try_into()
        .map_err(|_| "Deployment code hash width invalid")?;
        let id = derive_contract_id(&tx_id, index)?;
        Ok(Self {
            kind: draft.kind,
            expected_code_hash,
            contract_id: id,
            tx_id,
            unsigned_sha256: literal::sha(unsigned.unsigned_bytes()),
            script_sha256: script.script_sha256,
            creation_output_index: index,
            group: 0,
            artifact_sha256: script.artifact_sha256,
            caller_public_key_sha256: literal::sha(&actor.public_key),
            funding_head: spec.funding.head_hash.0,
            funding_source: spec.funding.source_id.0,
            publication_scope: spec.publication_scope.0,
            reserved_input_keys: unsigned
                .input_refs()
                .iter()
                .map(|input| input.key.0)
                .collect(),
        })
    }
}

pub(super) fn derive_contract_id(tx_id: &[u8; 32], index: u32) -> Result<[u8; 32], String> {
    let index_signed = i32::try_from(index).map_err(|_| "Creation index exceeds signed Int32")?;
    let mut preimage = tx_id.to_vec();
    preimage.extend(index_signed.to_be_bytes());
    let mut id = literal::blake(&preimage);
    id[31] = 0;
    Ok(id)
}
