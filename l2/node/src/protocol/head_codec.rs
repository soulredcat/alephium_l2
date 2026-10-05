//! Existing durable head bytes, shared unchanged by storage and proof transport.
use super::{
    Head,
    encoding::{Decoder, Encoder},
};

pub(crate) fn encode_head(head: &Head) -> Vec<u8> {
    let mut out = Encoder::default();
    out.u64(head.height);
    out.u64(head.timestamp);
    out.hash(head.commit_id);
    out.hash(head.genesis_id);
    out.0
}

pub(crate) fn decode_head(bytes: &[u8]) -> Result<Head, String> {
    let mut input = Decoder::new(bytes)?;
    let head = read_head(&mut input)?;
    input.finish()?;
    Ok(head)
}

pub(crate) fn read_head(input: &mut Decoder<'_>) -> Result<Head, String> {
    Ok(Head {
        height: input.u64()?,
        timestamp: input.u64()?,
        commit_id: input.hash()?,
        genesis_id: input.hash()?,
    })
}
