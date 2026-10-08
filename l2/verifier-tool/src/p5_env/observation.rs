//! Typed read-only inputs from one validated private env read; no approval.
use super::{amounts, inspect, parser};
use alephium_l2_sdk::alephium::{
    MIN_CHANGE_AMOUNT, publisher_address_from_public_key,
    read_node::{ConfirmationCounts, P2pkhAddress},
};
use alloy_primitives::U256;
use std::path::Path;

/// Sensitive account/config values deliberately omit Debug/Serialize. These
/// inputs establish neither source identity, funding eligibility nor spending.
pub(crate) struct FundingReadConfig {
    pub(crate) origin: String,
    pub(crate) caller_public_key: [u8; 33],
    pub(crate) owner: P2pkhAddress,
    pub(crate) minimum_confirmations: ConfirmationCounts,
    pub(crate) total_debit_cap_atto: U256,
    /// One protocol minimum same-owner change reserve. The actual operation
    /// package can require more; this is not its final thirty-operation quote.
    pub(crate) minimum_change_reserve_atto: U256,
    pub(crate) required_balance_atto: U256,
}

pub(crate) fn load_funding_read_config(path: &Path) -> Result<FundingReadConfig, String> {
    // The opened env is read exactly once. Both parsing passes below consume
    // that same bounded immutable text, never a second pathname resolution.
    from_text(&parser::read(path)?)
}

pub(super) fn from_text(text: &str) -> Result<FundingReadConfig, String> {
    if inspect(text)?["configuration_valid"] != true {
        return Err(
            "Funding-read config is incomplete or invalid; run the redacted env check".into(),
        );
    }
    let parsed = parser::parse(text)?;
    let value = |field| {
        parsed
            .values
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| "Validated funding-read field is missing".to_owned())
    };
    let key = value("L2_P5_PUBLISHER_PUBLIC_KEY")?;
    let key = key.strip_prefix("0x").unwrap_or(key);
    let caller_public_key: [u8; 33] = hex::decode(key)
        .map_err(|_| "Invalid funding-read compressed public key")?
        .try_into()
        .map_err(|_| "Invalid funding-read compressed public-key width")?;
    let owner = publisher_address_from_public_key(&caller_public_key)
        .map_err(|_| "Invalid funding-read native account")?;
    let configured = P2pkhAddress::parse(value("L2_P5_PUBLISHER_ADDRESS")?)
        .map_err(|_| "Invalid funding-read native address")?;
    if owner != configured || owner.group() != 0 {
        return Err("Funding-read account does not match the selected native group".into());
    }
    let count = |field| {
        amounts::u64_value(value(field)?)
            .and_then(|count| u32::try_from(count).ok())
            .filter(|count| *count != 0)
            .ok_or_else(|| "Invalid funding-read confirmation threshold".to_owned())
    };
    let minimum_confirmations = ConfirmationCounts {
        chain: count("L2_P5_MIN_CHAIN_CONFIRMATIONS")?,
        from_group: count("L2_P5_MIN_FROM_GROUP_CONFIRMATIONS")?,
        to_group: count("L2_P5_MIN_TO_GROUP_CONFIRMATIONS")?,
    };
    let debit = amounts::alph_to_atto(value("L2_P5_TOTAL_DEBIT_CAP_ALPH")?)
        .ok_or("Invalid funding-read ALPH total-debit cap")?;
    // Exact decimal parser enforces 256 bits before this native conversion.
    let total_debit_cap_atto = U256::from_be_slice(&debit.to_bytes_be());
    let minimum_change_reserve_atto = U256::from(MIN_CHANGE_AMOUNT);
    let required_balance_atto = total_debit_cap_atto
        .checked_add(minimum_change_reserve_atto)
        .ok_or("Funding-read total-debit cap plus change reserve overflows")?;
    Ok(FundingReadConfig {
        origin: value("L2_P5_NODE_URL")?.to_owned(),
        caller_public_key,
        owner,
        minimum_confirmations,
        total_debit_cap_atto,
        minimum_change_reserve_atto,
        required_balance_atto,
    })
}
