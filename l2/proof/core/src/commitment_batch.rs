//! Version-four result and reconstruction commitments over complete execution.
use crate::{
    CheckpointTransitionBundle, TransitionContext,
    commitment_stream::CanonicalHash,
    protocol::{Receipt, proof_transport::ProofLimits},
    records,
};
use alloy_primitives::B256;
use std::collections::BTreeSet;

pub(crate) struct StreamCommitments {
    transactions: CanonicalHash,
    contexts: CanonicalHash,
    receipts: CanonicalHash,
    seen: BTreeSet<B256>,
}

impl StreamCommitments {
    pub(crate) fn new(limits: ProofLimits) -> Result<Self, String> {
        let transcript = |namespace: &[u8]| {
            let mut out = CanonicalHash::new(namespace, limits.transcript_bytes)?;
            out.limits(limits)?;
            Ok::<_, String>(out)
        };
        Ok(Self {
            transactions: transcript(b"alephium-l2/batch-transactions/v4")?,
            contexts: transcript(b"alephium-l2/batch-contexts/v4")?,
            receipts: transcript(b"alephium-l2/batch-receipts/v4")?,
            seen: BTreeSet::new(),
        })
    }

    pub(crate) fn include(
        &mut self,
        context: &TransitionContext,
        receipts: &[Receipt],
    ) -> Result<(), String> {
        let count = u32::try_from(receipts.len()).map_err(|_| "receipt count exceeds u32")?;
        self.contexts.u64(context.number)?;
        self.contexts.u64(context.timestamp)?;
        self.contexts.u64(context.gas_limit)?;
        self.transactions.u64(context.number)?;
        self.transactions.u32(count)?;
        self.receipts.u64(context.number)?;
        self.receipts.u32(count)?;
        for receipt in receipts {
            if !self.seen.insert(receipt.hash) {
                return Err("duplicate transaction in selected batch".into());
            }
            self.transactions.hash(receipt.hash)?;
            // The individual receipt keeps the runtime's existing field bound.
            // Its block hash is the complete block's rederived commit identity.
            self.receipts
                .bytes(&records::encode_receipt(receipt, true)?)?;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(B256, B256, B256, u64), String> {
        let count = u64::try_from(self.seen.len()).map_err(|_| "executed count exceeds u64")?;
        Ok((
            self.transactions.finish(),
            self.contexts.finish(),
            self.receipts.finish(),
            count,
        ))
    }
}

/// Hash complete canonical reconstruction data without retaining its transcript.
/// Output heads/receipts and supplied state-digest oracles are not DA inputs.
pub(crate) fn reconstruction_hash(
    bundle: &CheckpointTransitionBundle,
    profile: B256,
    limits: ProofLimits,
    checkpoint_bytes: usize,
) -> Result<B256, String> {
    let mut out = CanonicalHash::new(
        b"alephium-l2/reconstruction/checkpoint-suffix/v4",
        limits.input_bytes,
    )?;
    out.byte(bundle.domain.l1_network)?;
    out.hash(bundle.domain.l1_genesis_id)?;
    out.hash(bundle.domain.settlement_contract_id)?;
    out.hash(profile)?;
    out.limits(limits)?;
    out.u32(u32::try_from(checkpoint_bytes).map_err(|_| "checkpoint field exceeds u32")?)?;
    bundle
        .checkpoint
        .write_encoded(&mut |bytes| out.raw(bytes))?;
    out.u64(u64::try_from(bundle.blocks.len()).map_err(|_| "block count exceeds u64")?)?;
    for block in &bundle.blocks {
        out.u64(block.context.number)?;
        out.u64(block.context.timestamp)?;
        out.u64(block.context.gas_limit)?;
        out.u32(u32::try_from(block.transactions.len()).map_err(|_| "input count exceeds u32")?)?;
        for input in &block.transactions {
            out.bytes(input.raw_envelope_hex.as_bytes())?;
        }
    }
    Ok(out.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encoding::Encoder, protocol::Capacity};

    #[test]
    fn streamed_results_match_canonical_bytes_and_reject_repeated_identity() {
        let limits = ProofLimits::for_capacity(Capacity::default()).unwrap();
        let context = TransitionContext {
            number: 7,
            timestamp: 31,
            gas_limit: 30_000_000,
        };
        let receipt = Receipt {
            hash: B256::repeat_byte(0x53),
            from: alloy_primitives::Address::repeat_byte(0x21),
            to: None,
            contract: None,
            success: true,
            gas_used: 21_000,
            gas_price: 1,
            logs: vec![],
            block_height: 7,
            block_hash: B256::repeat_byte(0x81),
            transaction_index: 0,
            cumulative_gas: 21_000,
            first_log_index: 0,
        };
        let mut streams = StreamCommitments::new(limits).unwrap();
        streams
            .include(&context, std::slice::from_ref(&receipt))
            .unwrap();
        let (transactions, contexts, receipts, count) = streams.finish().unwrap();
        let encode = |namespace: &[u8]| {
            let mut out = Encoder::default();
            out.bytes(namespace).unwrap();
            for value in [
                limits.checkpoint_bytes,
                limits.transcript_bytes,
                limits.input_bytes,
                limits.frame_bytes,
            ] {
                out.u64(value as u64);
            }
            out
        };
        let mut tx = encode(b"alephium-l2/batch-transactions/v4");
        tx.u64(7);
        tx.u32(1);
        tx.hash(receipt.hash);
        let mut ctx = encode(b"alephium-l2/batch-contexts/v4");
        ctx.u64(7);
        ctx.u64(31);
        ctx.u64(30_000_000);
        let mut logs = encode(b"alephium-l2/batch-receipts/v4");
        logs.u64(7);
        logs.u32(1);
        logs.bytes(&records::encode_receipt(&receipt, true).unwrap())
            .unwrap();
        assert_eq!(
            (transactions, contexts, receipts, count),
            (
                crate::batch_journal::hash(&tx.finish().unwrap()),
                crate::batch_journal::hash(&ctx.finish().unwrap()),
                crate::batch_journal::hash(&logs.finish().unwrap()),
                1,
            )
        );
        let mut streams = StreamCommitments::new(limits).unwrap();
        assert!(
            streams
                .include(&context, &[receipt.clone(), receipt])
                .is_err()
        );
    }

    #[test]
    fn hundred_thousand_receipt_transcript_exceeds_legacy_limit_without_a_buffer() {
        use alloy_primitives::{Address, U256};
        let limits = ProofLimits::for_capacity(Capacity {
            block_gas: 3_000_000_000,
            block_bytes: 32 * 1024 * 1024,
            max_pending: 100_000,
        })
        .unwrap();
        let context = TransitionContext {
            number: 1,
            timestamp: 31,
            gas_limit: 3_000_000_000,
        };
        let receipt = Receipt {
            hash: B256::ZERO,
            from: Address::repeat_byte(0x21),
            to: Some(Address::repeat_byte(0x22)),
            contract: None,
            success: true,
            gas_used: 21_000,
            gas_price: 1,
            logs: vec![],
            block_height: 1,
            block_hash: B256::repeat_byte(0x81),
            transaction_index: 0,
            cumulative_gas: 21_000,
            first_log_index: 0,
        };
        let receipts: Vec<_> = (1..=100_000u64)
            .map(|index| {
                let mut receipt = receipt.clone();
                receipt.hash = B256::from(U256::from(index).to_be_bytes::<32>());
                receipt.transaction_index = index - 1;
                receipt.cumulative_gas = index * 21_000;
                receipt
            })
            .collect();
        assert_eq!(
            records::encode_receipt(&receipts[0], true).unwrap().len(),
            167
        );
        assert!(receipts.len() * (167 + 4) > crate::encoding::MAX_RECORD);
        let mut streams = StreamCommitments::new(limits).unwrap();
        streams.include(&context, &receipts).unwrap();
        assert_eq!(streams.finish().unwrap().3, 100_000);
    }
}
