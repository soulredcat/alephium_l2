//! Static checks only. Paths are syntax, never opened or created here.
use super::{
    amounts,
    parser::{FIELDS, Issue, Parsed},
};
use alephium_l2_sdk::alephium::{
    MAX_ALPH_VALUE, MAX_GAS_AMOUNT, MIN_GAS_AMOUNT, MIN_GAS_PRICE,
    publisher_address_from_public_key, read_node::P2pkhAddress,
};
use num_bigint::BigUint;
use reqwest::Url;
use std::collections::BTreeMap;

pub(super) struct Checked {
    pub status: BTreeMap<&'static str, &'static str>,
    pub issues: Vec<Issue>,
}

impl Checked {
    fn fail(&mut self, field: &'static str, category: &'static str) {
        self.status.insert(field, "invalid");
        self.issues.push(Issue {
            field,
            category,
            line: None,
        });
    }
}

pub(super) fn validate(parsed: &Parsed) -> Checked {
    let mut out = Checked {
        status: BTreeMap::new(),
        issues: Vec::new(),
    };
    for &(field, _) in FIELDS {
        let Some(value) = parsed.values.get(field).filter(|value| !value.is_empty()) else {
            out.status.insert(field, "missing");
            continue;
        };
        out.status.insert(field, "valid");
        let valid = match field {
            "L2_P5_ENV_SCHEMA" => value == "1",
            "L2_P5_L1_NETWORK_ID" => value == "1",
            "L2_P5_L1_GROUP" => value == "0",
            "L2_P5_NODE_URL" => https_origin(value),
            "L2_P5_SIGNER_ADAPTER" => value == "file-outbox-v1",
            "L2_P5_OUTBOX_DIRECTORY" | "L2_P5_OPERATION_PACKAGE_DIRECTORY" => {
                project_directory(value)
            }
            "L2_P5_TOTAL_FEE_CAP_ALPH"
            | "L2_P5_TOTAL_DEPOSIT_CAP_ALPH"
            | "L2_P5_TOTAL_DEBIT_CAP_ALPH" => amounts::alph_to_atto(value).is_some(),
            "L2_P5_MAX_GAS_PER_TRANSACTION" => amounts::u64_value(value).is_some_and(|gas| {
                gas >= u64::from(MIN_GAS_AMOUNT) && gas <= u64::from(MAX_GAS_AMOUNT)
            }),
            "L2_P5_MAX_GAS_PRICE_ATTO" => amounts::integer(value).is_some_and(|price| {
                price >= BigUint::from(MIN_GAS_PRICE) && price < BigUint::from(MAX_ALPH_VALUE)
            }),
            "L2_P5_MIN_CHAIN_CONFIRMATIONS"
            | "L2_P5_MIN_FROM_GROUP_CONFIRMATIONS"
            | "L2_P5_MIN_TO_GROUP_CONFIRMATIONS" => amounts::u64_value(value)
                .is_some_and(|count| count != 0 && count <= u64::from(u32::MAX)),
            "L2_P5_PUBLISHER_CONFIRMATIONS" => {
                amounts::u64_value(value).is_some_and(|count| count != 0)
            }
            "L2_P5_MAX_FUTURE_SECONDS" => {
                amounts::u64_value(value).is_some_and(|seconds| seconds.checked_mul(1000).is_some())
            }
            "L2_P5_LIVE_SIGNING_ENABLED"
            | "L2_P5_LIVE_SUBMISSION_ENABLED"
            | "L2_P5_EXECUTION_DATA_DISCLOSURE_ENABLED" => value == "0",
            "L2_P5_PUBLISHER_PUBLIC_KEY" | "L2_P5_PUBLISHER_ADDRESS" => true, // Joint native checks below.
            _ => false,
        };
        if !valid {
            out.fail(field, "unsupported_or_invalid_static_input");
        }
    }
    account(parsed, &mut out);
    budget(parsed, &mut out);
    if let (Some(outbox), Some(package)) = (
        parsed.values.get("L2_P5_OUTBOX_DIRECTORY"),
        parsed.values.get("L2_P5_OPERATION_PACKAGE_DIRECTORY"),
    ) && directory_identity(outbox) == directory_identity(package)
    {
        out.fail(
            "L2_P5_OUTBOX_DIRECTORY",
            "outbox_and_package_must_be_distinct",
        );
    }
    out
}

fn account(parsed: &Parsed, out: &mut Checked) {
    let (Some(key), Some(address)) = (
        parsed
            .values
            .get("L2_P5_PUBLISHER_PUBLIC_KEY")
            .filter(|value| !value.is_empty()),
        parsed
            .values
            .get("L2_P5_PUBLISHER_ADDRESS")
            .filter(|value| !value.is_empty()),
    ) else {
        return;
    };
    let key = key.strip_prefix("0x").unwrap_or(key);
    let derived = if key.len() == 66 {
        hex::decode(key)
            .ok()
            .and_then(|key| publisher_address_from_public_key(&key).ok())
    } else {
        None
    };
    let Some(derived) = derived else {
        out.fail(
            "L2_P5_PUBLISHER_PUBLIC_KEY",
            "invalid_compressed_native_public_key",
        );
        return;
    };
    let configured = P2pkhAddress::parse(address);
    if !configured.as_ref().is_ok_and(|value| *value == derived) {
        out.fail(
            "L2_P5_PUBLISHER_ADDRESS",
            "native_address_does_not_match_public_key",
        );
    }
    if derived.group() != 0 {
        out.fail(
            "L2_P5_PUBLISHER_PUBLIC_KEY",
            "unsupported_native_account_group",
        );
    }
}

fn budget(parsed: &Parsed, out: &mut Checked) {
    let value = |field| {
        parsed
            .values
            .get(field)
            .and_then(|value| amounts::alph_to_atto(value))
    };
    if let (Some(fee), Some(deposit), Some(debit)) = (
        value("L2_P5_TOTAL_FEE_CAP_ALPH"),
        value("L2_P5_TOTAL_DEPOSIT_CAP_ALPH"),
        value("L2_P5_TOTAL_DEBIT_CAP_ALPH"),
    ) {
        if fee == BigUint::from(0_u8) || deposit == BigUint::from(0_u8) {
            out.fail(
                "L2_P5_TOTAL_DEBIT_CAP_ALPH",
                "zero_budget_cannot_cover_selected_p5_operations",
            );
        }
        let sum = fee + deposit;
        if sum.bits() > 256 || debit < sum {
            out.fail(
                "L2_P5_TOTAL_DEBIT_CAP_ALPH",
                "inconsistent_or_overflowing_total_budget",
            );
        }
    }
    // The actual per-operation fee/deposit sums require the approved package.
    // No two-template estimate is relabelled as the full thirty-operation plan.
}

fn https_origin(value: &str) -> bool {
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
    {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    let canonical = url.origin().ascii_serialization();
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && matches!(url.path(), "" | "/")
        && url.port_or_known_default() == Some(443)
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && ![".localhost", ".local", ".internal"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
        && (value == canonical || value == format!("{canonical}/"))
}

/// Platform-independent E-drive syntax; UNC/device/relative paths are refused.
fn project_directory(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    let tail = normalized
        .strip_prefix("E:/")
        .or_else(|| normalized.strip_prefix("e:/"))
        .or_else(|| normalized.strip_prefix("/mnt/e/"));
    let Some(tail) = tail else {
        return false;
    };
    !tail.is_empty()
        && !tail.ends_with('/')
        && tail.split('/').all(|part| {
            !part.is_empty()
                && !matches!(part, "." | "..")
                && !part.ends_with(['.', ' '])
                && !part.contains([':', '*', '?', '<', '>', '|'])
                && !part.chars().any(char::is_control)
                && !reserved_device(part)
        })
}

fn directory_identity(value: &str) -> String {
    let normalized = value.replace('\\', "/").to_ascii_lowercase();
    normalized
        .strip_prefix("/mnt/e/")
        .map_or_else(|| normalized.clone(), |tail| format!("e:/{tail}"))
}

fn reserved_device(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9')
}
