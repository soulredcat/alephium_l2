//! Exact current journal boundary. Raw proof/journal values are never logged.
use sha2::{Digest, Sha256};

pub(crate) const JOURNAL_BYTES: usize = 898;
pub(crate) const HEADER_BYTES: usize = 161;
pub(crate) const SCOPE: &[u8] = b"cancun-authenticated-checkpoint-batch/v4";
pub(crate) const RPC: &[u8] = b"development/c5-v1";
pub(crate) const ENGINE: &[u8] = b"REVM 43.0.3/Cancun (same library as producer)";

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Head {
    pub bytes: [u8; 80],
    pub height: u64,
    pub timestamp: u64,
    pub commit: [u8; 32],
    pub genesis: [u8; 32],
}

pub(crate) struct Journal {
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub network: u8,
    pub l1_genesis: [u8; 32],
    pub factory: [u8; 32],
    pub chain_id: u64,
    pub genesis: [u8; 32],
    pub profile: [u8; 32],
    pub batch_start: u64,
    pub parent: Head,
    pub head: Head,
    pub blocks: u64,
    pub transactions: u64,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub inbox: [u8; 32],
    pub outbox: [u8; 32],
    pub data_hash: [u8; 32],
}

impl Journal {
    pub fn decode(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() != JOURNAL_BYTES || &bytes[..HEADER_BYTES] != header().as_slice() {
            return Err(
                "Settlement requires the exact 898-byte canonical schema-four journal".into(),
            );
        }
        let journal = Self {
            digest: sha(&bytes),
            network: bytes[161],
            l1_genesis: array(&bytes, 162)?,
            factory: array(&bytes, 194)?,
            chain_id: u64_at(&bytes, 226)?,
            genesis: array(&bytes, 234)?,
            profile: array(&bytes, 266)?,
            batch_start: u64_at(&bytes, 298)?,
            parent: Head::decode(&bytes[306..386])?,
            head: Head::decode(&bytes[386..466])?,
            blocks: u64_at(&bytes, 466)?,
            transactions: u64_at(&bytes, 474)?,
            old_root: array(&bytes, 490)?,
            new_root: array(&bytes, 522)?,
            inbox: array(&bytes, 786)?,
            outbox: array(&bytes, 826)?,
            data_hash: array(&bytes, 866)?,
            bytes,
        };
        if journal.chain_id == 0
            || journal.l1_genesis == [0; 32]
            || journal.factory == [0; 32]
            || journal.genesis == [0; 32]
            || journal.profile == [0; 32]
            || journal.parent.genesis != journal.genesis
            || journal.head.genesis != journal.genesis
            || !(1..=256).contains(&journal.blocks)
            || journal.transactions < journal.blocks
            || journal.transactions > journal.blocks * u32::MAX as u64
            || journal.parent.height.checked_add(1) != Some(journal.batch_start)
            || journal.parent.height.checked_add(journal.blocks) != Some(journal.head.height)
            || journal.head.timestamp < journal.parent.timestamp
            || u64_at(&journal.bytes, 482)? != journal.blocks
            || u64_at(&journal.bytes, 818)? != 0
            || u64_at(&journal.bytes, 858)? != 0
            || journal.inbox != journal.empty_messages(b"inbox")
            || journal.outbox != journal.empty_messages(b"outbox")
        {
            return Err(
                "Settlement journal identity, ancestry or empty-message policy differs".into(),
            );
        }
        for offset in [
            162, 194, 234, 266, 322, 402, 490, 522, 554, 586, 690, 722, 754, 866,
        ] {
            if array::<32>(&journal.bytes, offset)? == [0; 32] {
                return Err("Settlement journal contains a zero required commitment".into());
            }
        }
        Ok(journal)
    }

    fn empty_messages(&self, kind: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"alephium-l2/authenticated-messages/v1");
        digest.update(kind);
        digest.update(&self.bytes[161..226]);
        digest.update(self.genesis);
        digest.update(0_u64.to_be_bytes());
        digest.finalize().into()
    }
}

impl Head {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 80 {
            return Err("Settlement head must contain exactly 80 bytes".into());
        }
        Ok(Self {
            bytes: bytes.try_into().map_err(|_| "Invalid settlement head")?,
            height: u64_at(bytes, 0)?,
            timestamp: u64_at(bytes, 8)?,
            commit: array(bytes, 16)?,
            genesis: array(bytes, 48)?,
        })
    }
}

pub(crate) fn header() -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_BYTES);
    framed(&mut out, b"alephium-l2-transition-proof/journal/v4");
    out.extend(4_u32.to_be_bytes());
    for field in [SCOPE, RPC, ENGINE] {
        framed(&mut out, field);
    }
    out
}

pub(crate) fn framed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u32).to_be_bytes());
    out.extend(value);
}

pub(crate) fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], String> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(N)
                    .ok_or("Settlement field offset overflow")?,
        )
        .ok_or("Truncated settlement field")?
        .try_into()
        .map_err(|_| "Invalid settlement width".into())
}

pub(crate) fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}
