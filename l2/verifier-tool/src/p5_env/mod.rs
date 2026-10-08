//! Offline private env inspection. No shell sourcing or external operations.
mod amounts;
mod bootstrap;
mod observation;
mod parser;
mod validation;

pub(crate) use bootstrap::{BootstrapConfig, load_bootstrap_config};
pub(crate) use observation::{FundingReadConfig, load_funding_read_config};

use serde_json::{Value, json};
use std::path::Path;

/// Report includes only allowlisted names/categories, never private values.
pub(crate) fn check(path: &Path) -> Result<Value, String> {
    inspect(&parser::read(path)?)
}

/// The entrypoint prints the redacted report and fails missing/invalid config.
/// Valid static config still reports live_ready=false and pending prerequisites.
pub(crate) fn run(path: &Path) -> Result<(), String> {
    let report = check(path)?;
    let valid = report["configuration_valid"] == true;
    println!("{report}");
    if valid {
        Ok(())
    } else {
        Err("P5 env is incomplete or unsupported; see field categories".into())
    }
}

fn inspect(text: &str) -> Result<Value, String> {
    let parsed = parser::parse(text)?;
    let checked = validation::validate(&parsed);
    let mut issues = Vec::new();
    for issue in parsed.issues.iter().chain(&checked.issues) {
        issues.push(json!({"field": issue.field, "category": issue.category, "line": issue.line}));
    }
    let mut fields = Vec::new();
    let mut valid = issues.is_empty();
    for &(name, category) in parser::FIELDS {
        let present = parsed
            .values
            .get(name)
            .is_some_and(|value| !value.is_empty());
        let status = checked.status.get(name).copied().unwrap_or("missing");
        valid &= status == "valid";
        fields.push(json!({"name":name,"category":category,"present":present,"status":status}));
    }
    Ok(json!({
        "schema":1, "mode":"offline_env_check", "configuration_valid":valid,
        "live_ready":false, "fields":fields, "issues":issues,
        "pending":["approved_package_genesis_and_derived_source_id", "actual_thirty_operation_budget_and_artifact_pins",
            "directory_provisioning_and_private_access", "real_funding_and_external_wallet", "separate_live_operation_authorization"],
        "warnings":["ALPH caps are converted exactly to integer atto; values are suppressed",
            "funding and publisher confirmations are separate inputs",
            "paths were checked as syntax only; no directory or package was opened"],
        "external_operations_performed":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alephium_l2_sdk::alephium::publisher_address_from_public_key;
    use num_bigint::BigUint;

    // Enumerate public curve points only. No wallet, private key or signing.
    fn actor() -> (String, String) {
        for last in 1..=255 {
            let mut public = [0; 33];
            public[0] = 2;
            public[32] = last;
            if let Ok(address) = publisher_address_from_public_key(&public)
                && address.group() == 0
            {
                return (hex::encode(public), address.as_str().to_owned());
            }
        }
        panic!("Public point fixture unavailable");
    }

    fn fixture() -> String {
        let (key, address) = actor();
        let value = |name| match name {
            "L2_P5_ENV_SCHEMA" | "L2_P5_L1_NETWORK_ID" => "1".to_owned(),
            "L2_P5_L1_GROUP"
            | "L2_P5_LIVE_SIGNING_ENABLED"
            | "L2_P5_LIVE_SUBMISSION_ENABLED"
            | "L2_P5_EXECUTION_DATA_DISCLOSURE_ENABLED" => "0".to_owned(),
            "L2_P5_NODE_URL" => "https://node.testnet.alephium.org".to_owned(),
            "L2_P5_PUBLISHER_PUBLIC_KEY" => key.clone(),
            "L2_P5_PUBLISHER_ADDRESS" => address.clone(),
            "L2_P5_SIGNER_ADAPTER" => "file-outbox-v1".to_owned(),
            "L2_P5_OUTBOX_DIRECTORY" => "E:/offline-fixture/outbox".to_owned(),
            "L2_P5_OPERATION_PACKAGE_DIRECTORY" => "E:/offline-fixture/package".to_owned(),
            "L2_P5_TOTAL_FEE_CAP_ALPH" => "15".to_owned(),
            "L2_P5_TOTAL_DEPOSIT_CAP_ALPH" => "0.7".to_owned(),
            "L2_P5_TOTAL_DEBIT_CAP_ALPH" => "15.7".to_owned(),
            "L2_P5_MAX_GAS_PER_TRANSACTION" => "5000000".to_owned(),
            "L2_P5_MAX_GAS_PRICE_ATTO" => "100000000000".to_owned(),
            "L2_P5_MAX_FUTURE_SECONDS" => "60".to_owned(),
            _ => "6".to_owned(),
        };
        parser::FIELDS
            .iter()
            .map(|(name, _)| format!("{name}={}\n", value(name)))
            .collect()
    }

    fn replace(text: &str, name: &str, value: &str) -> String {
        text.lines()
            .map(|line| {
                if line.starts_with(&format!("{name}=")) {
                    format!("{name}={value}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect()
    }

    #[test]
    fn aggregate_offline_env_validation() {
        let text = fixture();
        let report = inspect(&text).unwrap();
        assert!(report["configuration_valid"] == true && report["live_ready"] == false);
        let (key, address) = actor();
        let typed = observation::from_text(&text).unwrap();
        assert!(typed.origin == "https://node.testnet.alephium.org");
        assert!(hex::encode(typed.caller_public_key) == key && typed.owner.as_str() == address);
        assert!(typed.owner.group() == 0);
        assert!(
            typed.minimum_confirmations.chain == 6
                && typed.minimum_confirmations.from_group == 6
                && typed.minimum_confirmations.to_group == 6
        );
        assert!(
            typed.total_debit_cap_atto
                == alloy_primitives::U256::from(15_700_000_000_000_000_000_u128)
        );
        assert!(
            typed.minimum_change_reserve_atto
                == alloy_primitives::U256::from(alephium_l2_sdk::alephium::MIN_CHANGE_AMOUNT)
        );
        assert!(
            typed.required_balance_atto
                == typed.total_debit_cap_atto + typed.minimum_change_reserve_atto
        );
        let bootstrap = bootstrap::from_text(&text).unwrap();
        assert!(
            bootstrap.funding.caller_public_key == typed.caller_public_key
                && bootstrap.funding.owner == typed.owner
                && bootstrap.funding.origin == typed.origin
        );
        assert!(bootstrap.max_gas == 5_000_000);
        assert!(bootstrap.max_gas_price == alloy_primitives::U256::from(100_000_000_000_u64));
        assert!(
            bootstrap.fee_cap_atto == alloy_primitives::U256::from(15_000_000_000_000_000_000_u128)
        );
        assert!(
            bootstrap.deposit_cap_atto == alloy_primitives::U256::from(700_000_000_000_000_000_u64)
        );
        assert!(bootstrap.debit_cap_atto == typed.total_debit_cap_atto);
        assert!(bootstrap.max_future_seconds == 60 && bootstrap.publisher_confirmations == 6);
        assert!(
            bootstrap.outbox_directory.as_path()
                == std::path::Path::new("E:/offline-fixture/outbox")
        );
        // Projection retains changed configured ceilings. It never compares a
        // wallet balance or infers that the configured budget is funded.
        let different_caps = replace(
            &replace(&text, "L2_P5_TOTAL_FEE_CAP_ALPH", "16"),
            "L2_P5_TOTAL_DEBIT_CAP_ALPH",
            "16.7",
        );
        let changed = bootstrap::from_text(&different_caps).unwrap();
        assert!(
            changed.fee_cap_atto == alloy_primitives::U256::from(16_000_000_000_000_000_000_u128)
        );
        assert!(changed.debit_cap_atto == changed.funding.total_debit_cap_atto);
        assert!(changed.fee_cap_atto != bootstrap.fee_cap_atto);
        let output = report.to_string();
        assert!(
            !output.contains(&key)
                && !output.contains(&address)
                && !output.contains("offline-fixture")
        );
        assert!(
            amounts::alph_to_atto("15.7")
                == Some(BigUint::from(157_u32) * BigUint::from(10_u8).pow(17))
        );
        assert!(amounts::alph_to_atto("0.000000000000000001") == Some(BigUint::from(1_u8)));
        let maximum = (BigUint::from(1_u8) << 256_usize) - BigUint::from(1_u8);
        assert!(amounts::integer(&maximum.to_string()) == Some(maximum.clone()));
        assert!(amounts::integer(&(maximum + BigUint::from(1_u8)).to_string()).is_none());
        for bad in [
            "1e3",
            "-1",
            "+1",
            ".1",
            "01",
            "1.",
            "1.0000000000000000001",
            " 1",
            "1.2.3",
        ] {
            assert!(amounts::alph_to_atto(bad).is_none());
        }
        for (name, bad) in [
            ("L2_P5_ENV_SCHEMA", "2"),
            ("L2_P5_L1_NETWORK_ID", "0"),
            ("L2_P5_L1_GROUP", "1"),
            ("L2_P5_NODE_URL", "https://account:credential@node.example"),
            ("L2_P5_NODE_URL", "https://node.example/path"),
            ("L2_P5_NODE_URL", "https://node.local"),
            ("L2_P5_NODE_URL", "https://node.internal"),
            ("L2_P5_PUBLISHER_PUBLIC_KEY", "02"),
            ("L2_P5_PUBLISHER_ADDRESS", "bad-address"),
            ("L2_P5_SIGNER_ADAPTER", "wallet-command"),
            ("L2_P5_OUTBOX_DIRECTORY", "C:/offline-fixture/outbox"),
            ("L2_P5_OUTBOX_DIRECTORY", "E:/offline-fixture/../outbox"),
            ("L2_P5_OUTBOX_DIRECTORY", "E:/offline-fixture/CON"),
            ("L2_P5_OUTBOX_DIRECTORY", "E:/offline-fixture/package"),
            ("L2_P5_OUTBOX_DIRECTORY", "/mnt/e/offline-fixture/package"),
            ("L2_P5_TOTAL_DEBIT_CAP_ALPH", "15"),
            ("L2_P5_TOTAL_FEE_CAP_ALPH", "1e3"),
            ("L2_P5_MAX_GAS_PER_TRANSACTION", "19999"),
            ("L2_P5_MAX_GAS_PER_TRANSACTION", "5000001"),
            ("L2_P5_MAX_GAS_PRICE_ATTO", "99999999999"),
            ("L2_P5_MIN_CHAIN_CONFIRMATIONS", "0"),
            ("L2_P5_MIN_FROM_GROUP_CONFIRMATIONS", "4294967296"),
            ("L2_P5_PUBLISHER_CONFIRMATIONS", "0"),
            ("L2_P5_MAX_FUTURE_SECONDS", "18446744073709552"),
            ("L2_P5_LIVE_SIGNING_ENABLED", "1"),
            ("L2_P5_LIVE_SUBMISSION_ENABLED", "1"),
            ("L2_P5_EXECUTION_DATA_DISCLOSURE_ENABLED", "1"),
        ] {
            let invalid = replace(&text, name, bad);
            assert!(inspect(&invalid).unwrap()["configuration_valid"] == false);
            assert!(observation::from_text(&invalid).is_err());
            assert!(bootstrap::from_text(&invalid).is_err());
        }
        for suffix in [
            "L2_P5_ENV_SCHEMA=1\n",
            "SECRET_VALUE=not-printed\n",
            "export L2_P5_ENV_SCHEMA=1\n",
            "malformed-line\n",
            "L2_P5_NODE_URL=$(command)\n",
        ] {
            let output = inspect(&(text.clone() + suffix)).unwrap();
            assert!(
                output["configuration_valid"] == false
                    && !output.to_string().contains("not-printed")
            );
            assert!(observation::from_text(&(text.clone() + suffix)).is_err());
            assert!(bootstrap::from_text(&(text.clone() + suffix)).is_err());
        }
        let windows = replace(
            &text,
            "L2_P5_OUTBOX_DIRECTORY",
            "\"E:\\offline-fixture\\outbox\"",
        );
        assert!(inspect(&windows).unwrap()["configuration_valid"] == true);
        let missing = replace(&text, "L2_P5_TOTAL_FEE_CAP_ALPH", "");
        assert!(inspect(&missing).unwrap()["configuration_valid"] == false);
        assert!(observation::from_text(&missing).is_err());
        assert!(bootstrap::from_text(&missing).is_err());
        let scale = BigUint::from(10_u8).pow(18);
        let max_debit = (BigUint::from(1_u8) << 256_usize) - BigUint::from(1_u8);
        let max_debit = format!(
            "{}.{:0>18}",
            &max_debit / &scale,
            (&max_debit % &scale).to_string()
        );
        let overflow = replace(&text, "L2_P5_TOTAL_DEBIT_CAP_ALPH", &max_debit);
        assert!(inspect(&overflow).unwrap()["configuration_valid"] == true);
        assert!(observation::from_text(&overflow).is_err());
        assert!(bootstrap::from_text(&overflow).is_err());
        let overflowing_caps = replace(&text, "L2_P5_TOTAL_FEE_CAP_ALPH", &max_debit);
        assert!(inspect(&overflowing_caps).unwrap()["configuration_valid"] == false);
        assert!(bootstrap::from_text(&overflowing_caps).is_err());
        assert!(inspect(&"#".repeat(parser::MAX_BYTES + 1)).is_err());
    }
}
