//! Fail-closed fixture feasibility; this never changes node or proof limits.
use alephium_l2_node::{
    operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
    protocol::{
        Capacity,
        checkpoint::{MAX_CHECKPOINT_ACCOUNTS, MAX_CHECKPOINT_BYTES},
    },
};
use serde_json::json;
use std::io::Write;

// Canonical account fields from protocol/checkpoint/codec.rs; no slots/code.
const ACCOUNT_BYTES: usize = 20 + 1 + 32 + 8 + 32 + 8 + 4;
// Current custom-profile header (195), one 37-byte funder/code header (73),
// and the full 256-entry historical hash window (10240), including reserve.
const FIXTURE_HEADER_CODE_HISTORY: usize = 195 + 73 + 256 * 40;
const TRANSFER_GAS: u64 = 21_000;

pub(super) fn check(count: usize, capacity: Capacity) -> Result<(), String> {
    capacity.validate()?;
    let producer_limit = capacity.producer_checkpoint_bytes()?;
    let runtime_limit = capacity.runtime_checkpoint_bytes()?;
    let runtime_record_limit = capacity.runtime_record_bytes()?;
    let funded_accounts = count
        .checked_add(3)
        .ok_or("Fixture account count overflow")?;
    let funded_bytes = funded_accounts
        .checked_mul(ACCOUNT_BYTES)
        .and_then(|bytes| bytes.checked_add(FIXTURE_HEADER_CODE_HISTORY))
        .ok_or("Fixture size overflow")?;
    let final_accounts = count
        .checked_mul(2)
        .and_then(|accounts| accounts.checked_add(3))
        .ok_or("Fixture account count overflow")?;
    let final_bytes = final_accounts
        .checked_mul(ACCOUNT_BYTES)
        .and_then(|bytes| bytes.checked_add(FIXTURE_HEADER_CODE_HISTORY))
        .ok_or("Fixture size overflow")?;
    if funded_bytes <= producer_limit
        && final_bytes <= producer_limit
        && final_bytes <= runtime_limit
        && final_accounts <= runtime_limit / ACCOUNT_BYTES
    {
        return Ok(());
    }
    let by_gas = capacity.block_gas / TRANSFER_GAS;
    let by_pending = capacity.max_pending as u64;
    let per_block = by_gas.min(by_pending);
    let report = json!({
        "scope":"burst_fixture_feasibility","stage":"preflight","blocked":true,
        "intended_requests":count,"offered_actual":0,"durable_acks":0,"receipts":0,
        "engine_started":false,"measured_throughput_result":false,
        "ledger_and_reopen_passed":null,"target_met":null,
        "reason":"unchanged distinct funded sender/recipient workload exceeds checkpoint representation",
        "account_wire_bytes_without_slots":ACCOUNT_BYTES,
        "funding_required_checkpoint_bytes":funded_bytes,
        "completed_required_checkpoint_bytes":final_bytes,
        "completed_distinct_accounts":final_accounts,
        "producer_checkpoint_limit":producer_limit,
        "runtime_checkpoint_limit":runtime_limit,
        "runtime_record_limit":runtime_record_limit,
        "runtime_account_count_limit":runtime_limit/ACCOUNT_BYTES,
        "fixed_proof_checkpoint_limit":MAX_CONTINUATION_CHECKPOINT_BYTES,
        "fixed_proof_codec_checkpoint_limit":MAX_CHECKPOINT_BYTES,
        "fixed_proof_codec_account_limit":MAX_CHECKPOINT_ACCOUNTS,
        "proof_transport_supported":capacity.ensure_proof_transport().is_ok(),
        "profile":capacity,"max_transfers_per_block_by_gas":by_gas,
        "max_transfers_per_block_by_pending":by_pending,
        "minimum_selected_blocks":(count as u64).div_ceil(per_block),
        "financial_durability_and_capacity_guards_unchanged":true,
        "workload_substitution":false,"ten_rounds":false
    });
    let mut output = std::io::stdout().lock();
    writeln!(output, "{report}").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())?;
    Err("Burst blocked before engine start: existing checkpoint limits cannot represent the unchanged fixture".into())
}
