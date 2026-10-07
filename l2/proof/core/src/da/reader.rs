//! Bounded native DA parsing; complete matching bytes are not proof/settlement authority.
use super::{
    DaBlock, DaEncodingEvidence, DecodedCheckpointDa, ExpectedDa, NAMESPACE,
    encoding::{context_valid, logical_prefix, raw_length_valid},
};
use crate::{
    EXECUTION_ENGINE, LARGE_CHECKPOINT_SCOPE, MAX_TRANSITION_BLOCKS, RPC_PROFILE, SettlementDomain,
    TransitionContext, checkpoint_profile_v4_with_capacity,
    protocol::{
        checkpoint::ExecutionCheckpoint,
        hash::{Digest, Sha256},
        proof_transport::ProofLimits,
        validate_chain_id,
    },
};
use alloy_primitives::B256;
use std::io::{ErrorKind, Read};

struct Stream<'a, R> {
    source: &'a mut R,
    digest: Sha256,
    used: usize,
    exact: usize,
}

impl<R: Read> Stream<'_, R> {
    fn remaining(&self) -> usize {
        self.exact - self.used
    }

    fn read_into(&mut self, bytes: &mut [u8]) -> Result<(), String> {
        if bytes.len() > self.remaining() {
            return Err("DA field exceeds the declared remaining bytes".into());
        }
        self.source
            .read_exact(bytes)
            .map_err(|_| "DA bytes are truncated or unavailable")?;
        self.digest.update(&*bytes);
        self.used += bytes.len();
        Ok(())
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let mut bytes = [0; N];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn hash(&mut self) -> Result<B256, String> {
        Ok(B256::from(self.fixed::<32>()?))
    }

    fn finish(self) -> Result<DaEncodingEvidence, String> {
        if self.used != self.exact {
            return Err("DA package has trailing declared bytes".into());
        }
        let mut extra = [0];
        loop {
            match self.source.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err("DA source has bytes beyond its declared package".into()),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err("Cannot establish physical DA end of input".into()),
            }
        }
        Ok(DaEncodingEvidence {
            bytes: self.used,
            commitment: B256::from_slice(&self.digest.finalize()),
        })
    }
}

fn expected_profile(
    expected: &ExpectedDa<'_>,
    length: usize,
) -> Result<(B256, ProofLimits), String> {
    let journal = expected.journal;
    let limits = ProofLimits::for_capacity(expected.capacity)?;
    let profile = checkpoint_profile_v4_with_capacity(expected.capacity)?;
    validate_chain_id(journal.chain_id)?;
    journal.domain.validate()?;
    let maximum_transactions = journal
        .blocks
        .checked_mul(expected.capacity.max_pending as u64)
        .ok_or("DA transaction bound overflow")?;
    if length == 0
        || length > limits.input_bytes
        || journal.schema != 4
        || journal.proof_scope != LARGE_CHECKPOINT_SCOPE
        || journal.rpc_profile != RPC_PROFILE
        || journal.execution_engine != EXECUTION_ENGINE
        || journal.execution_profile != profile
        || journal.blocks == 0
        || journal.blocks > MAX_TRANSITION_BLOCKS
        || journal.witness_blocks != journal.blocks
        || journal.executed_transactions == 0
        || journal.executed_transactions > maximum_transactions
        || journal.executed_transactions > (length / 5) as u64
        || journal.batch_start
            != journal
                .parent
                .height
                .checked_add(1)
                .ok_or("DA height overflow")?
        || journal.head.height
            != journal
                .parent
                .height
                .checked_add(journal.blocks)
                .ok_or("DA height overflow")?
        || journal.parent.genesis_id != journal.genesis_id
        || journal.head.genesis_id != journal.genesis_id
        || journal.head.timestamp < journal.parent.timestamp
    {
        return Err("independent DA statement/profile or declared resource bounds differ".into());
    }
    Ok((profile, limits))
}

fn blocks(
    input: &mut Stream<'_, impl Read>,
    expected: &ExpectedDa<'_>,
    limits: ProofLimits,
) -> Result<Vec<DaBlock>, String> {
    let count = usize::try_from(input.u64()?).map_err(|_| "DA block count overflow")?;
    if count == 0
        || count as u64 != expected.journal.blocks
        || count as u64 > MAX_TRANSITION_BLOCKS
        || count > input.remaining() / 33
    {
        return Err("DA block count exceeds statement or remaining bytes".into());
    }
    let body_start = input.used;
    let mut output = Vec::with_capacity(count);
    let mut previous_number = expected.journal.parent.height;
    let mut previous_timestamp = expected.journal.parent.timestamp;
    let mut total_transactions = 0_u64;
    for _ in 0..count {
        let context = TransitionContext {
            number: input.u64()?,
            timestamp: input.u64()?,
            gas_limit: input.u64()?,
        };
        context_valid(
            context.number,
            context.timestamp,
            context.gas_limit,
            previous_number,
            previous_timestamp,
            expected.capacity,
        )?;
        let transactions = input.u32()? as usize;
        total_transactions = total_transactions
            .checked_add(transactions as u64)
            .ok_or("DA transaction count overflow")?;
        if transactions == 0
            || transactions > expected.capacity.max_pending
            || transactions > input.remaining() / 5
            || total_transactions > expected.journal.executed_transactions
            || input.used - body_start > limits.transcript_bytes
        {
            return Err("DA transactions exceed the selected block/body bounds".into());
        }
        let mut logical = logical_prefix();
        let mut envelopes = Vec::with_capacity(transactions);
        for _ in 0..transactions {
            let length = input.u32()? as usize;
            raw_length_valid(length, &mut logical, expected.capacity)?;
            if length > input.remaining()
                || (input.used - body_start)
                    .checked_add(length)
                    .is_none_or(|bytes| bytes > limits.transcript_bytes)
            {
                return Err("DA envelope exceeds remaining body bytes".into());
            }
            let mut raw = vec![0; length];
            input.read_into(&mut raw)?;
            envelopes.push(raw);
        }
        previous_number = context.number;
        previous_timestamp = context.timestamp;
        output.push(DaBlock { context, envelopes });
    }
    if total_transactions != expected.journal.executed_transactions
        || previous_number != expected.journal.head.height
        || previous_timestamp != expected.journal.head.timestamp
    {
        return Err("DA contexts/count do not end at the independent statement boundary".into());
    }
    Ok(output)
}

/// Decode only against caller-pinned candidate semantics. The fetched bytes
/// cannot choose capacity, roots, profile or a proof/availability authority.
pub fn read_checkpoint_da(
    reader: &mut impl Read,
    exact_length: usize,
    expected: &ExpectedDa<'_>,
) -> Result<DecodedCheckpointDa, String> {
    let (profile, limits) = expected_profile(expected, exact_length)?;
    let mut input = Stream {
        source: reader,
        digest: Sha256::new(),
        used: 0,
        exact: exact_length,
    };
    if input.u32()? as usize != NAMESPACE.len() {
        return Err("DA namespace length differs".into());
    }
    let mut namespace = [0; NAMESPACE.len()];
    input.read_into(&mut namespace)?;
    if namespace.as_slice() != NAMESPACE {
        return Err("DA namespace differs".into());
    }
    let domain = SettlementDomain {
        l1_network: input.fixed::<1>()?[0],
        l1_genesis_id: input.hash()?,
        settlement_contract_id: input.hash()?,
    };
    domain.validate()?;
    if domain != expected.journal.domain || input.hash()? != profile {
        return Err("DA domain or capacity-bound execution profile differs".into());
    }
    if input.fixed::<32>()? != limits.binding_bytes()? {
        return Err("DA limits differ from the exact selected capacity".into());
    }
    let checkpoint_bytes = input.u32()? as usize;
    if checkpoint_bytes == 0
        || checkpoint_bytes > limits.checkpoint_bytes
        || checkpoint_bytes > input.remaining()
    {
        return Err("DA checkpoint exceeds its declared capacity bound".into());
    }
    let checkpoint = ExecutionCheckpoint::read_encoded_for_capacity(
        &mut |bytes| input.read_into(bytes),
        checkpoint_bytes,
        expected.capacity,
    )?;
    if checkpoint.chain_id != expected.journal.chain_id
        || checkpoint.genesis_id != expected.journal.genesis_id
        || checkpoint.head != expected.journal.parent
        || checkpoint.root_for_transport(
            profile,
            domain.l1_network,
            domain.l1_genesis_id,
            domain.settlement_contract_id,
            limits,
        )? != expected.journal.old_state_root
    {
        return Err("DA checkpoint does not match the independent prior state/root".into());
    }
    let blocks = blocks(&mut input, expected, limits)?;
    let encoding = input.finish()?;
    if encoding.commitment != expected.journal.da_commitment {
        return Err("Complete DA bytes differ from the independently pinned commitment".into());
    }
    Ok(DecodedCheckpointDa {
        domain,
        profile,
        checkpoint,
        blocks,
        encoding,
    })
}
