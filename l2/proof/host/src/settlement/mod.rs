//! Bounded native inline-data and staged-session preparation, without authority.
mod binding;
mod data;
mod types;

pub use binding::{
    STAGED_SELECTOR, bind_derived_children, prepare_session_candidate, staged_claim_binding,
    staged_statement_id,
};
pub use data::{extract_original_parent_checkpoint, prepare_inline_data, prepare_inline_data_file};
pub use types::{
    INLINE_DATA_VERSION, InlineDataMetadata, MAX_INLINE_DATA_BYTES, OriginalParentCheckpoint,
    ParentCheckpointMetadata, PreparedInlineData, SessionBinding, SessionCandidate,
    SessionCandidateMetadata, StagedClaim, StagedClaimBinding,
};

#[cfg(test)]
mod tests {
    use super::data::test_data::{encode_da, fixture, prepared, sha};
    use super::*;
    use alephium_l2_transition_core::{
        RawEnvelope, da::ExpectedDa, encode_large_checkpoint_transition,
    };

    #[test]
    fn bulk_native_inline_data_and_session_binding() {
        record_original_fixture_checkpoint();
        let (mut bundle, mut journal, policy, anchor) = fixture();
        let capacity = bundle.checkpoint.capacity;
        let bytes = encode_da(&bundle, &mut journal);
        let output = prepared(&bytes, &journal, capacity, &policy, &anchor);
        assert!(output.private_data_bytes() == bytes);
        assert!(output.metadata().data_sha256 == sha(&bytes));
        let original = bundle.checkpoint.encode().unwrap();
        assert!(output.private_parent_checkpoint_bytes() == original);
        assert!(output.metadata().parent_checkpoint_sha256 == sha(&original));
        // Existing independent .NET vectors ensure the payload/statement
        // encoding was preserved rather than merely mirrored by this test.
        let mut seal = [0; 260];
        seal[..4].copy_from_slice(&STAGED_SELECTOR);
        let mut auxiliary = [0; 577];
        auxiliary[0] = 1;
        let image = [1; 32];
        let old_digest = [2; 32];
        let mut claim = StagedClaim {
            image_id: &image,
            journal_sha256: &old_digest,
            seal: &seal,
            auxiliary: &auxiliary,
        };
        let old = staged_claim_binding(&claim).unwrap();
        assert!(
            hex::encode(old.payload_id)
                == "91d90dcfb22517173b92b53271a5c6b92c08871970313cb55c160df4f79d87b2"
        );
        assert!(
            hex::encode(staged_statement_id(&old, &[0; 32]).unwrap())
                == "e7e3505ca8b30e467512ab084f5743c884e3939fbd6dc764e154050fe9c85023"
        );
        let factory: [u8; 32] = journal.domain.settlement_contract_id.into();
        assert!(prepare_session_candidate(&output, &factory, image, &claim).is_err());
        claim.journal_sha256 = &output.metadata().journal_sha256;
        let candidate = prepare_session_candidate(&output, &factory, image, &claim).unwrap();
        let metadata = candidate.metadata();
        assert!(metadata.proof_path.starts_with(b"p5v1/proof/"));
        assert!(metadata.data_path.starts_with(b"p5v1/data/"));
        assert!(metadata.proof_path[b"p5v1/proof/".len()..] == metadata.candidate_key);
        assert!(metadata.data_path[b"p5v1/data/".len()..] == metadata.candidate_key);
        let mut proof_id = [21; 32];
        proof_id[31] = 0;
        let mut data_id = [22; 32];
        data_id[31] = 0;
        let bind = |proof_path: &[u8], data_path: &[u8], proof: &[u8], data: &[u8]| {
            bind_derived_children(&candidate, proof_path, data_path, proof, data)
        };
        let bound = bind(
            &metadata.proof_path,
            &metadata.data_path,
            &proof_id,
            &data_id,
        )
        .unwrap();
        assert!(bound.statement_id != old.payload_id);
        let mut other_proof = proof_id;
        other_proof[0] ^= 1;
        let other = bind(
            &metadata.proof_path,
            &metadata.data_path,
            &other_proof,
            &data_id,
        )
        .unwrap();
        assert!(other.candidate.claim.payload_id == bound.candidate.claim.payload_id);
        assert!(other.statement_id != bound.statement_id);
        assert!(
            bind(
                &metadata.data_path,
                &metadata.proof_path,
                &proof_id,
                &data_id
            )
            .is_err()
        );
        assert!(
            bind(
                &metadata.proof_path,
                &metadata.data_path,
                &proof_id[..31],
                &data_id
            )
            .is_err()
        );
        assert!(
            bind(
                &metadata.proof_path,
                &metadata.data_path,
                &proof_id,
                &proof_id
            )
            .is_err()
        );
        let mut bad_group = proof_id;
        bad_group[31] = 34;
        assert!(
            bind(
                &metadata.proof_path,
                &metadata.data_path,
                &bad_group,
                &data_id
            )
            .is_err()
        );
        assert!(prepare_session_candidate(&output, &factory, [0; 32], &claim).is_err());
        assert!(prepare_session_candidate(&output, &factory, [3; 32], &claim).is_err());
        let mut wrong_factory = factory;
        wrong_factory[0] ^= 1;
        assert!(prepare_session_candidate(&output, &wrong_factory, image, &claim).is_err());
        assert!(prepare_session_candidate(&output, &factory[..31], image, &claim).is_err());
        claim.image_id = &image[..31];
        assert!(staged_claim_binding(&claim).is_err());
        claim.image_id = &image;
        claim.seal = &seal[..259];
        assert!(staged_claim_binding(&claim).is_err());
        let mut bad_seal = seal;
        bad_seal[0] ^= 1;
        claim.seal = &bad_seal;
        assert!(staged_claim_binding(&claim).is_err());
        claim.seal = &seal;
        let mut bad_auxiliary = auxiliary;
        bad_auxiliary[0] = 0;
        claim.auxiliary = &bad_auxiliary;
        assert!(staged_claim_binding(&claim).is_err());
        claim.auxiliary = &auxiliary[..576];
        assert!(staged_claim_binding(&claim).is_err());
        claim.auxiliary = &auxiliary;
        let mut changed_seal = seal;
        changed_seal[259] ^= 1;
        claim.seal = &changed_seal;
        let replaced = prepare_session_candidate(&output, &factory, image, &claim).unwrap();
        assert!(replaced.metadata().candidate_key != metadata.candidate_key);
        assert!(replaced.metadata().claim.payload_id != metadata.claim.payload_id);
        assert!(replaced.metadata().proof_path != metadata.proof_path);
        let expected = ExpectedDa {
            journal: &journal,
            capacity,
        };
        let pin = sha(&journal.encode().unwrap());
        for bad in [
            &[][..],
            &[0; MAX_INLINE_DATA_BYTES + 1][..],
            &bytes[..bytes.len() - 1],
        ] {
            assert!(
                prepare_inline_data(bad, &expected, pin, None, &policy, &anchor, 1_000).is_err()
            );
        }
        assert!(
            prepare_inline_data(&bytes, &expected, [0; 32], None, &policy, &anchor, 1_000).is_err()
        );
        assert!(
            prepare_inline_data(
                &bytes,
                &expected,
                pin,
                Some([0; 32]),
                &policy,
                &anchor,
                1_000
            )
            .is_err()
        );
        let mut wrong_domain = policy.clone();
        wrong_domain.domain.l1_network ^= 1;
        assert!(
            prepare_inline_data(&bytes, &expected, pin, None, &wrong_domain, &anchor, 1_000)
                .is_err()
        );
        let mut wrong_parent = anchor.clone();
        wrong_parent.state_root = [20; 32].into();
        assert!(
            prepare_inline_data(&bytes, &expected, pin, None, &policy, &wrong_parent, 1_000)
                .is_err()
        );
        assert!(prepare_inline_data(&bytes, &expected, pin, None, &policy, &anchor, 999).is_err());
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            prepare_inline_data(&changed, &expected, pin, None, &policy, &anchor, 1_000).is_err()
        );
        let wire = encode_large_checkpoint_transition(&bundle).unwrap();
        let extracted = extract_original_parent_checkpoint(&wire, sha(&wire)).unwrap();
        assert!(extracted.private_checkpoint_bytes() == original);
        assert!(extract_original_parent_checkpoint(&wire, [0; 32]).is_err());
        let growth = MAX_INLINE_DATA_BYTES - bytes.len();
        bundle.blocks[0].transactions[0].raw_envelope_hex =
            RawEnvelope::from_bytes(vec![1; 1 + growth]).unwrap();
        let boundary = encode_da(&bundle, &mut journal);
        assert!(boundary.len() == MAX_INLINE_DATA_BYTES);
        assert!(
            prepared(&boundary, &journal, capacity, &policy, &anchor)
                .metadata()
                .bytes
                == 3_000
        );
    }

    fn record_original_fixture_checkpoint() {
        let Some(input) = std::env::var_os("L2_P5_ORIGINAL_INPUT") else {
            return;
        };
        use std::io::Write;
        let pin = std::env::var("L2_P5_ORIGINAL_INPUT_SHA256").unwrap();
        let pin: [u8; 32] = hex::decode(pin).unwrap().try_into().unwrap();
        let bytes = std::fs::read(input).unwrap();
        let original = extract_original_parent_checkpoint(&bytes, pin).unwrap();
        assert!(original.metadata().head.height == 0);
        let output = std::env::var_os("L2_P5_BOOTSTRAP_METADATA").unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .unwrap();
        let metadata = serde_json::to_vec_pretty(original.metadata()).unwrap();
        file.write_all(&metadata).unwrap();
        file.sync_all().unwrap();
    }
}
