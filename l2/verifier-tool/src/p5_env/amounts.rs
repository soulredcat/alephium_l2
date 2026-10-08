//! Exact nonnegative ALPH/atto parsing; no float, exponent or rounding path.
use num_bigint::BigUint;

pub(super) fn integer(value: &str) -> Option<BigUint> {
    if value.is_empty()
        || value.len() > 78
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return None;
    }
    let amount = BigUint::parse_bytes(value.as_bytes(), 10)?;
    (amount.bits() <= 256).then_some(amount)
}

pub(super) fn alph_to_atto(value: &str) -> Option<BigUint> {
    let (whole, fraction) = value
        .split_once('.')
        .map_or((value, None), |(whole, fraction)| (whole, Some(fraction)));
    let mut amount = integer(whole)? * BigUint::from(10_u8).pow(18);
    if let Some(fraction) = fraction {
        if fraction.is_empty()
            || fraction.len() > 18
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        amount += BigUint::parse_bytes(fraction.as_bytes(), 10)?
            * BigUint::from(10_u8).pow(18 - fraction.len() as u32);
    }
    (amount.bits() <= 256).then_some(amount)
}

pub(super) fn u64_value(value: &str) -> Option<u64> {
    integer(value)?.try_into().ok()
}
