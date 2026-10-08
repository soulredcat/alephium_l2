//! Exact private bootstrap caps from one env read; never a spending capability.
use super::{FundingReadConfig, amounts, observation, parser};
use alloy_primitives::U256;
use std::path::{Path, PathBuf};

/// Identity and configuration deliberately omit Debug/Serialize. These totals
/// remain operator ceilings, not an assertion of available or eligible funds.
pub(crate) struct BootstrapConfig {
    pub(crate) funding: FundingReadConfig,
    pub(crate) max_gas: u32,
    pub(crate) max_gas_price: U256,
    pub(crate) fee_cap_atto: U256,
    pub(crate) deposit_cap_atto: U256,
    pub(crate) debit_cap_atto: U256,
    pub(crate) max_future_seconds: u64,
    pub(crate) publisher_confirmations: u64,
    /// Syntax-validated only; neither this loader nor PathBuf opens an outbox.
    pub(crate) outbox_directory: PathBuf,
}

pub(crate) fn load_bootstrap_config(path: &Path) -> Result<BootstrapConfig, String> {
    from_text(&parser::read(path)?)
}

pub(super) fn from_text(text: &str) -> Result<BootstrapConfig, String> {
    // Reuse the full checker and account/reserve projection on this SAME text.
    // There is no second file read or independently refreshed identity/cap.
    let funding = observation::from_text(text)?;
    let parsed = parser::parse(text)?;
    let value = |field| {
        parsed
            .values
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| "Validated bootstrap field is missing".to_owned())
    };
    let number = |field| {
        amounts::u64_value(value(field)?)
            .ok_or_else(|| "Invalid bootstrap integer field".to_owned())
    };
    let amount = |field| {
        let amount = amounts::alph_to_atto(value(field)?).ok_or("Invalid bootstrap ALPH cap")?;
        Ok::<_, String>(U256::from_be_slice(&amount.to_bytes_be()))
    };
    let max_gas = u32::try_from(number("L2_P5_MAX_GAS_PER_TRANSACTION")?)
        .map_err(|_| "Bootstrap gas ceiling exceeds u32")?;
    let price = amounts::integer(value("L2_P5_MAX_GAS_PRICE_ATTO")?)
        .ok_or("Invalid bootstrap atto gas-price cap")?;
    let max_gas_price = U256::from_be_slice(&price.to_bytes_be());
    let fee_cap_atto = amount("L2_P5_TOTAL_FEE_CAP_ALPH")?;
    let deposit_cap_atto = amount("L2_P5_TOTAL_DEPOSIT_CAP_ALPH")?;
    let debit_cap_atto = amount("L2_P5_TOTAL_DEBIT_CAP_ALPH")?;
    let sum = fee_cap_atto
        .checked_add(deposit_cap_atto)
        .ok_or("Bootstrap total fee plus deposit cap overflows")?;
    if sum > debit_cap_atto || debit_cap_atto != funding.total_debit_cap_atto {
        return Err("Bootstrap total caps differ from the validated funding context".into());
    }
    let max_future_seconds = number("L2_P5_MAX_FUTURE_SECONDS")?;
    max_future_seconds
        .checked_mul(1000)
        .ok_or("Bootstrap future-drift conversion overflows")?;
    let publisher_confirmations = number("L2_P5_PUBLISHER_CONFIRMATIONS")?;
    if publisher_confirmations == 0 {
        return Err("Bootstrap publisher confirmations must be positive".into());
    }
    let outbox_directory = PathBuf::from(value("L2_P5_OUTBOX_DIRECTORY")?);
    Ok(BootstrapConfig {
        funding,
        max_gas,
        max_gas_price,
        fee_cap_atto,
        deposit_cap_atto,
        debit_cap_atto,
        max_future_seconds,
        publisher_confirmations,
        outbox_directory,
    })
}
