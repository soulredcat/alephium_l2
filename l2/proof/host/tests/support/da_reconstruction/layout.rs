//! Test-side canonical field locations; no production decoder internals used.
use super::{Capacity, checked};
use std::ops::Range;

const NAMESPACE: &[u8] = b"alephium-l2/reconstruction/checkpoint-suffix/v4";
const CHECKPOINT_NAMESPACE: &[u8] = b"alephium-l2/execution-checkpoint/v1";

pub(super) struct BlockLayout {
    pub range: Range<usize>,
    pub records: Vec<Range<usize>>,
}

pub(super) struct Layout {
    pub domain: usize,
    pub profile: usize,
    pub limits: usize,
    pub checkpoint_length: usize,
    pub checkpoint_start: usize,
    pub accounts_count: usize,
    pub block_count: usize,
    pub blocks: Vec<BlockLayout>,
}

fn u32_at(bytes: &[u8], offset: usize) -> usize {
    u32::from_be_bytes(checked(
        bytes[offset..offset + 4].try_into(),
        "DA u32 width",
    )) as usize
}

pub(super) fn layout(bytes: &[u8], capacity: Capacity) -> Layout {
    assert!(
        u32_at(bytes, 0) == NAMESPACE.len(),
        "DA namespace framing changed"
    );
    let domain = 4 + NAMESPACE.len();
    assert!(&bytes[4..domain] == NAMESPACE, "DA namespace changed");
    let profile = domain + 65;
    let limits = profile + 32;
    let checkpoint_length = limits + 32;
    let checkpoint_start = checkpoint_length + 4;
    let block_count = checkpoint_start + u32_at(bytes, checkpoint_length);
    let capacity_bytes = if capacity.is_default() { 0 } else { 24 };
    let accounts_count =
        checkpoint_start + CHECKPOINT_NAMESPACE.len() + 4 + 8 + capacity_bytes + 32 + 80;
    let count = u64::from_be_bytes(checked(
        bytes[block_count..block_count + 8].try_into(),
        "DA block-count width",
    ));
    let mut cursor = block_count + 8;
    let mut blocks = Vec::new();
    for _ in 0..count {
        let start = cursor;
        let transactions = u32_at(bytes, cursor + 24);
        cursor += 28;
        let mut records = Vec::new();
        for _ in 0..transactions {
            let start = cursor;
            cursor += 4 + u32_at(bytes, cursor);
            assert!(cursor <= bytes.len(), "DA envelope framing exceeded data");
            records.push(start..cursor);
        }
        blocks.push(BlockLayout {
            range: start..cursor,
            records,
        });
    }
    assert!(
        cursor == bytes.len(),
        "DA layout has trailing or missing records"
    );
    Layout {
        domain,
        profile,
        limits,
        checkpoint_length,
        checkpoint_start,
        accounts_count,
        block_count,
        blocks,
    }
}
