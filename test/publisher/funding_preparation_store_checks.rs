//! One coordinated isolated-Store aggregate. No signer/network is invoked.
use super::*;
use crate::funding_preparation::*;

#[path = "funding_preparation_qualification.rs"]
mod qualification;

/// Root provides three fresh owned TEST Stores, a well-formed DATA plan and
/// a matching test signature. They are never live account/database authority.
pub(crate) fn run_checks(
    normal: &mut Store,
    corrupt: &mut Store,
    uncertain: &mut Store,
    planned: &FundingPreparationRecord,
    test_signature: &[u8],
) -> Result<usize, String> {
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(
            ok,
            "Funding preparation aggregate failed; private records suppressed"
        );
        count += 1;
    };
    let planned = planned.clone();
    validation::transition(None, &planned).map_err(|_| "Test preparation DATA plan rejected")?;
    let purpose = planned.immutable.purpose_id;
    let expected_inputs: Vec<_> = planned
        .immutable
        .input_refs
        .iter()
        .map(|input| input.key)
        .collect();
    check(
        normal
            .load_funding_preparation(purpose)
            .map_err(|_| "Test empty load failed")?
            .is_none(),
    );
    let stored = normal
        .cas_funding_preparation(0, &planned)
        .map_err(|_| "Test planned CAS failed")?;
    check(
        stored == planned
            && normal
                .load_funding_preparation(purpose)
                .map_err(|_| "Test planned load failed")?
                == Some(planned.clone()),
    );
    check(normal.cas_funding_preparation(0, &planned).err() == Some(Error::Conflict));

    for mutation in 0..7 {
        let mut changed = planned.clone();
        changed.revision += 1;
        changed.phase = FundingPreparationPhase::SignAttempted;
        changed.sign_attempts = 1;
        match mutation {
            0 => changed.immutable.purpose_id = B256::repeat_byte(99),
            1 => changed.immutable.operator_source = B256::ZERO,
            2 => changed.immutable.gas_amount += 1,
            3 => changed.immutable.fee += alloy_primitives::U256::from(1),
            4 => changed.immutable.outputs[0].amount += alloy_primitives::U256::from(1),
            5 => changed.immutable.unsigned.push(0),
            _ => changed.immutable.minimum_confirmations = [1; 3],
        }
        check(normal.cas_funding_preparation(1, &changed).is_err());
    }
    let mut duplicate = planned.clone();
    duplicate.immutable.purpose_id = B256::repeat_byte(99);
    check(normal.cas_funding_preparation(0, &duplicate).err() == Some(Error::Conflict));
    check(
        normal
            .funding_preparation_reserved_inputs()
            .map_err(|_| "Test input index load failed")?
            == expected_inputs,
    );

    let mut current = planned.clone();
    current.revision = 2;
    current.phase = FundingPreparationPhase::SignAttempted;
    current.sign_attempts = 1;
    normal
        .cas_funding_preparation(1, &current)
        .map_err(|_| "Test sign marker CAS failed")?;
    check(
        normal
            .load_funding_preparation(purpose)
            .map_err(|_| "Test sign marker reload failed")?
            .is_some_and(|row| {
                row.phase == FundingPreparationPhase::SignAttempted
                    && row.sign_attempts == 1
                    && row.signature.is_none()
            }),
    );
    current.revision = 3;
    current.phase = FundingPreparationPhase::SignAmbiguous;
    normal
        .cas_funding_preparation(2, &current)
        .map_err(|_| "Test ambiguous-sign CAS failed")?;
    let mut retry = current.clone();
    retry.revision += 1;
    retry.phase = FundingPreparationPhase::SignAttempted;
    check(normal.cas_funding_preparation(3, &retry).err() == Some(Error::InvalidTransition));
    current.revision = 4;
    current.phase = FundingPreparationPhase::Signed;
    current.signature = Some(test_signature.to_vec());
    normal
        .cas_funding_preparation(3, &current)
        .map_err(|_| "Test recovered-signature CAS failed")?;
    let mut bad_signature = current.clone();
    bad_signature.revision = 5;
    bad_signature.phase = FundingPreparationPhase::SubmitAttempted;
    bad_signature.submit_attempts = 1;
    bad_signature.signature = Some(vec![0; 64]);
    check(normal.cas_funding_preparation(4, &bad_signature).is_err());
    current.revision = 5;
    current.phase = FundingPreparationPhase::SubmitAttempted;
    current.submit_attempts = 1;
    normal
        .cas_funding_preparation(4, &current)
        .map_err(|_| "Test submit marker CAS failed")?;
    current.revision = 6;
    current.phase = FundingPreparationPhase::SubmitAmbiguous;
    normal
        .cas_funding_preparation(5, &current)
        .map_err(|_| "Test ambiguous-submit CAS failed")?;
    retry = current.clone();
    retry.revision += 1;
    retry.phase = FundingPreparationPhase::SubmitAttempted;
    check(normal.cas_funding_preparation(6, &retry).err() == Some(Error::InvalidTransition));
    current.revision = 7;
    current.phase = FundingPreparationPhase::Confirmed;
    current.inclusion = Some(FundingPreparationInclusion {
        transaction_id: planned.immutable.transaction_id,
        block_hash: B256::repeat_byte(22),
        height: 20,
        canonical_head: B256::repeat_byte(23),
        observed_at_ms: 10000,
        confirmations: planned.immutable.minimum_confirmations,
    });
    normal
        .cas_funding_preparation(6, &current)
        .map_err(|_| "Test late canonical CAS failed")?;
    check(
        normal
            .load_funding_preparation(purpose)
            .map_err(|_| "Test confirmed reload failed")?
            == Some(current.clone()),
    );
    check(
        normal
            .funding_preparation_reserved_inputs()
            .map_err(|_| "Test retained index load failed")?
            == expected_inputs,
    );
    retry = current.clone();
    retry.revision += 1;
    retry.phase = FundingPreparationPhase::Planned;
    retry.sign_attempts = 0;
    retry.submit_attempts = 0;
    retry.signature = None;
    retry.inclusion = None;
    check(normal.cas_funding_preparation(7, &retry).is_err());

    // Corruption and durability uncertainty never become an empty/new intent.
    corrupt
        .cas_funding_preparation(0, &planned)
        .map_err(|_| "Test corrupt Store seed failed")?;
    let mut batch = corrupt
        .batch()
        .map_err(|_| "Test corruption batch failed")?;
    batch.remove(
        &corrupt.funding_items,
        recovery::key(3, planned.immutable.input_refs[0].key),
    );
    corrupt
        .finish(batch)
        .map_err(|_| "Test index corruption write failed")?;
    check(corrupt.load_funding_preparation(purpose).err() == Some(Error::CorruptState));
    check(corrupt.load_funding_preparation(purpose).err() == Some(Error::Storage));
    uncertain.fail_next_commit_for_test();
    check(uncertain.cas_funding_preparation(0, &planned).err() == Some(Error::Storage));
    check(uncertain.load_funding_preparation(purpose).err() == Some(Error::Storage));
    let encoded = codec::encode(&codec::Stored {
        schema: 1,
        node_chain_id: normal.chain_id,
        node_genesis: normal
            .view()
            .map_err(|_| "Test Store context unavailable")?
            .head
            .genesis_id,
        capacity: normal.profile_capacity,
        record: current,
    })
    .map_err(|_| "Test envelope encode failed")?;
    check(codec::decode::<codec::Stored>(&encoded).is_ok());
    let mut damaged = encoded;
    *damaged.last_mut().ok_or("Test envelope is empty")? ^= 1;
    check(codec::decode::<codec::Stored>(&damaged).is_err());
    Ok(count)
}
