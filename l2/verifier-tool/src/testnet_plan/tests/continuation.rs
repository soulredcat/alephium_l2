//! Synthetic continuation-prefix and authenticated DA-framing fixtures only.
//! No checkpoint body, EVM execution or genuine receipt claim is made.
use super::super::{da, literal, types::Policy};
use super::check;
use crate::settlement::journal::{self, Journal};
use serde_json::Value;

pub(super) fn framing(policy: &Policy, records: &mut Vec<Value>) -> Result<(), String> {
    let mut factory = [8_u8; 32];
    factory[31] = 0;
    let mut head = policy.genesis_head;
    head[..8].copy_from_slice(&1_u64.to_be_bytes());
    head[8..16].copy_from_slice(&1_u64.to_be_bytes());
    head[16..48].copy_from_slice(&[7; 32]);
    let (_, schema, _) = da::checkpoint_prefix(
        &policy.genesis_checkpoint,
        policy.l2_chain_id,
        &policy.l2_genesis,
    )?;
    let offset = b"alephium-l2/execution-checkpoint/v1".len()
        + 4
        + 8
        + if schema == 1 { 0 } else { 24 }
        + 32;
    let mut continuation = policy.genesis_checkpoint.clone();
    continuation
        .get_mut(offset..offset + 80)
        .ok_or("Checkpoint prefix truncated")?
        .copy_from_slice(&head);
    check(
        records,
        "generic-checkpoint-prefix-supports-nongenesis-predecessor",
        da::checkpoint_prefix(&continuation, policy.l2_chain_id, &policy.l2_genesis)?.2 == head,
    )?;
    let mut root = b"alephium-l2/continuation-root/v2".to_vec();
    root.extend(policy.execution_profile);
    root.push(1);
    root.extend(policy.l1_genesis);
    root.extend(factory);
    root.extend(policy.transport_limits);
    root.extend(&continuation);
    let old_root = literal::sha(&root);
    let mut next = head;
    next[..8].copy_from_slice(&2_u64.to_be_bytes());
    next[8..16].copy_from_slice(&2_u64.to_be_bytes());
    next[16..48].copy_from_slice(&[9; 32]);
    let mut raw = journal::header();
    raw.resize(898, 0);
    raw[161] = 1;
    for (offset, value) in [
        (162, policy.l1_genesis),
        (194, factory),
        (234, policy.l2_genesis),
        (266, policy.execution_profile),
        (490, old_root),
        (522, [6; 32]),
        (554, [3; 32]),
        (586, [3; 32]),
        (690, [3; 32]),
        (722, [3; 32]),
        (754, [3; 32]),
    ] {
        raw[offset..offset + 32].copy_from_slice(&value);
    }
    raw[226..234].copy_from_slice(&policy.l2_chain_id.to_be_bytes());
    raw[298..306].copy_from_slice(&2_u64.to_be_bytes());
    raw[306..386].copy_from_slice(&head);
    raw[386..466].copy_from_slice(&next);
    for offset in [466, 474, 482] {
        raw[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
    }
    for (offset, kind) in [(786, b"inbox".as_slice()), (826, b"outbox".as_slice())] {
        let mut pre = b"alephium-l2/authenticated-messages/v1".to_vec();
        pre.extend(kind);
        pre.extend(&raw[161..226]);
        pre.extend(policy.l2_genesis);
        pre.extend(0_u64.to_be_bytes());
        raw[offset..offset + 32].copy_from_slice(&literal::sha(&pre));
    }
    let mut wire = Vec::new();
    journal::framed(
        &mut wire,
        b"alephium-l2/reconstruction/checkpoint-suffix/v4",
    );
    wire.extend(&raw[161..226]);
    wire.extend(policy.execution_profile);
    wire.extend(policy.transport_limits);
    journal::framed(&mut wire, &continuation);
    wire.extend(1_u64.to_be_bytes());
    wire.extend(2_u64.to_be_bytes());
    wire.extend(2_u64.to_be_bytes());
    wire.extend(policy.capacity[0].to_be_bytes());
    wire.extend(1_u32.to_be_bytes());
    journal::framed(&mut wire, &[1]);
    raw[866..898].copy_from_slice(&literal::sha(&wire));
    let value = Journal::decode(raw)?;
    check(
        records,
        "second-suffix-uses-its-exact-parent-and-root",
        da::validate(wire.clone(), &value, policy, false).is_ok(),
    )?;
    check(
        records,
        "second-suffix-cannot-use-genesis-bootstrap",
        da::validate(wire.clone(), &value, policy, true).is_err(),
    )?;
    let mut changed = value;
    changed.parent.bytes = policy.genesis_head;
    check(
        records,
        "second-parent-substitution-refused",
        da::validate(wire.clone(), &changed, policy, false).is_err(),
    )?;
    changed.parent.bytes = head;
    changed.old_root = [5; 32];
    check(
        records,
        "second-root-substitution-refused",
        da::validate(wire, &changed, policy, false).is_err(),
    )?;
    // These synthetic prefix fixtures deliberately make no checkpoint body or
    // EVM validity claim. The real API also requires independent receipt pairing.
    Ok(())
}
