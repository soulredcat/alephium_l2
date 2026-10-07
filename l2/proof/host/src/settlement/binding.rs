//! Exact staged claim encoding and the frozen native P5 candidate/path grammar.
use super::types::{
    PreparedInlineData, SessionBinding, SessionCandidate, SessionCandidateMetadata, StagedClaim,
    StagedClaimBinding,
};
use crate::HostResult;
use sha2::{Digest, Sha256};

pub const STAGED_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];
const PAYLOAD_DOMAIN: &[u8] = b"ALPH/L2/stagedpayload/v1";
const STATEMENT_DOMAIN: &[u8] = b"ALPH/L2/stagedreceipt/v1";
const CANDIDATE_DOMAIN: &[u8] = b"ALPH/L2/batch-session/v1";
const PROOF_PATH: &[u8] = b"p5v1/proof/";
const DATA_PATH: &[u8] = b"p5v1/data/";

/// Validate only the certified fixed wire layout, then hash the exact bytes.
/// The seal's coordinates, auxiliary arithmetic and pairing are not evaluated.
pub fn staged_claim_binding(claim: &StagedClaim<'_>) -> HostResult<StagedClaimBinding> {
    if claim.seal.len() != 260 || claim.auxiliary.len() != 577 {
        return Err("Staged claim seal/auxiliary widths differ from the fixed layout.");
    }
    if claim.seal[..4] != STAGED_SELECTOR || claim.auxiliary[0] != 1 {
        return Err("Staged claim selector or auxiliary version differs from the pinned layout.");
    }
    let mut binding = StagedClaimBinding {
        image_id: width32(claim.image_id)?,
        journal_sha256: width32(claim.journal_sha256)?,
        seal_sha256: Sha256::digest(claim.seal).into(),
        auxiliary_sha256: Sha256::digest(claim.auxiliary).into(),
        payload_id: [0; 32],
    };
    let mut hash = Sha256::new();
    hash.update(PAYLOAD_DOMAIN);
    update_claim(&mut hash, &binding);
    binding.payload_id = hash.finalize().into();
    Ok(binding)
}

/// Journal binding is drawn from the opaque checked DA preparation; image and
/// factory are independently selected pins. On target the factory uses selfID.
pub fn prepare_session_candidate(
    data: &PreparedInlineData,
    factory_id: &[u8],
    approved_image_id: [u8; 32],
    claim: &StagedClaim<'_>,
) -> HostResult<SessionCandidate> {
    let factory_id = group_zero_id(factory_id)?;
    let claim = staged_claim_binding(claim)?;
    if factory_id.as_slice() != data.metadata().domain.settlement_contract_id.as_slice() {
        return Err("Session factory differs from the independently checked settlement domain.");
    }
    if claim.image_id != approved_image_id || approved_image_id == [0; 32] {
        return Err("Session image differs from its independent approved-image pin.");
    }
    if claim.journal_sha256 != data.metadata().journal_sha256 {
        return Err("Session claim journal differs from the checked inline data statement.");
    }
    let mut hash = Sha256::new();
    hash.update(CANDIDATE_DOMAIN);
    hash.update(factory_id);
    hash.update(claim.image_id);
    hash.update(claim.journal_sha256);
    hash.update(claim.seal_sha256);
    hash.update(claim.auxiliary_sha256);
    let candidate_key: [u8; 32] = hash.finalize().into();
    let path = |prefix: &[u8]| {
        let mut bytes = Vec::with_capacity(prefix.len() + candidate_key.len());
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&candidate_key);
        bytes
    };
    Ok(SessionCandidate {
        metadata: SessionCandidateMetadata {
            factory_id,
            candidate_key,
            proof_path: path(PROOF_PATH),
            data_path: path(DATA_PATH),
            claim,
        },
    })
}

/// Bind IDs derived by the caller from these exact paths. This does not derive
/// Alephium IDs or certify origin; the target must authenticate creation.
pub fn bind_derived_children(
    candidate: &SessionCandidate,
    proof_path: &[u8],
    data_path: &[u8],
    proof_child_id: &[u8],
    data_child_id: &[u8],
) -> HostResult<SessionBinding> {
    let metadata = candidate.metadata();
    if proof_path != metadata.proof_path || data_path != metadata.data_path {
        return Err("Session child derivation paths differ from the frozen candidate paths.");
    }
    let proof_child_id = group_zero_id(proof_child_id)?;
    let data_child_id = group_zero_id(data_child_id)?;
    if proof_child_id == data_child_id
        || proof_child_id == metadata.factory_id
        || data_child_id == metadata.factory_id
    {
        return Err("Session factory/proof/data identities must be distinct.");
    }
    Ok(SessionBinding {
        candidate: metadata.clone(),
        proof_child_id,
        data_child_id,
        statement_id: staged_statement_id(&metadata.claim, &proof_child_id)?,
    })
}

/// Existing 188-byte staged statement, including the concrete proof child ID.
pub fn staged_statement_id(
    claim: &StagedClaimBinding,
    proof_child_id: &[u8],
) -> HostResult<[u8; 32]> {
    let child = width32(proof_child_id)?;
    if child[31] != 0 {
        return Err("Staged proof child must use exact group zero.");
    }
    let mut hash = Sha256::new();
    hash.update(STATEMENT_DOMAIN);
    hash.update(child);
    update_claim(&mut hash, claim);
    Ok(hash.finalize().into())
}

fn update_claim(hash: &mut Sha256, claim: &StagedClaimBinding) {
    hash.update(STAGED_SELECTOR);
    hash.update(claim.image_id);
    hash.update(claim.journal_sha256);
    hash.update(claim.seal_sha256);
    hash.update(claim.auxiliary_sha256);
}

fn width32(bytes: &[u8]) -> HostResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| "Session identity/digest requires exactly 32 bytes.")
}

fn group_zero_id(bytes: &[u8]) -> HostResult<[u8; 32]> {
    let id = width32(bytes)?;
    if id == [0; 32] || id[31] != 0 {
        return Err("Session identity must be nonzero and use exact group zero.");
    }
    Ok(id)
}
