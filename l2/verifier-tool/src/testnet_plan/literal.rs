//! Closed literal grammar and domain-separated offline commitments.
use super::{artifacts::Hash, types::Actor};
use blake2::{
    Blake2b,
    digest::{Digest, consts::U32},
};
use num_bigint::BigUint;
use serde_json::Value;

pub(crate) fn sha(bytes: &[u8]) -> Hash {
    sha2::Sha256::digest(bytes).into()
}

pub(crate) fn blake(bytes: &[u8]) -> Hash {
    Blake2b::<U32>::digest(bytes).into()
}

pub(crate) fn bytes(value: &[u8]) -> String {
    format!("#{}", hex::encode(value))
}

pub(crate) fn amount(value: &BigUint) -> Result<String, String> {
    if value.bits() > 256 {
        return Err("Ralph amount exceeds U256".into());
    }
    Ok(value.to_string())
}

pub(crate) fn hash_value(domain: &[u8], value: &Value) -> Result<Hash, String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| "Cannot encode bounded planner commitment")?;
    if bytes.len() > 1_048_576 {
        return Err("Planner commitment exceeds its byte bound".into());
    }
    let mut preimage = domain.to_vec();
    preimage.extend((bytes.len() as u32).to_be_bytes());
    preimage.extend(bytes);
    Ok(sha(&preimage))
}

pub(crate) fn caller(actor: &Actor) -> Result<String, String> {
    if !matches!(actor.public_key[0], 2 | 3) || actor.canonical_source == [0; 32] {
        return Err("Actual compressed signer and canonical source pins required".into());
    }
    let owner = blake(&actor.public_key);
    let hint = owner.iter().fold(5381_u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(*byte))
    }) | 1;
    let group = ((hint ^ (hint >> 8) ^ (hint >> 16) ^ (hint >> 24)) as u8) % 4;
    if group != 0 {
        return Err("Offline public-testnet route requires actual group-zero signer".into());
    }
    let mut address = vec![0]; // canonical P2PKH address discriminator
    address.extend(owner);
    let leading = address.iter().take_while(|byte| **byte == 0).count();
    let mut number = BigUint::from_bytes_be(&address);
    let radix = BigUint::from(58_u8);
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut text = Vec::new();
    while number != BigUint::from(0_u8) {
        let remainder = (&number % &radix).to_bytes_le();
        text.push(alphabet[usize::from(remainder.first().copied().unwrap_or(0))]);
        number /= &radix;
    }
    text.extend(std::iter::repeat_n(b'1', leading));
    text.reverse();
    String::from_utf8(text)
        .map(|value| format!("@{value}"))
        .map_err(|_| "Cannot encode canonical caller address".into())
}

pub(crate) fn child(factory: &Hash, path: &[u8]) -> Hash {
    let mut preimage = factory.to_vec();
    preimage.extend(path);
    let mut id = blake(&blake(&preimage));
    id[31] = 0;
    id
}

pub(crate) fn session(
    factory: &Hash,
    image: &Hash,
    journal: &Hash,
    seal: &Hash,
    auxiliary: &Hash,
) -> Hash {
    let mut input = b"ALPH/L2/batch-session/v1".to_vec();
    for part in [factory, image, journal, seal, auxiliary] {
        input.extend(part);
    }
    sha(&input)
}

pub(crate) fn payload(image: &Hash, journal: &Hash, seal: &Hash, auxiliary: &Hash) -> Hash {
    let mut input = b"ALPH/L2/stagedpayload/v1".to_vec();
    input.extend([0x73, 0xc4, 0x57, 0xba]);
    for part in [image, journal, seal, auxiliary] {
        input.extend(part);
    }
    sha(&input)
}

pub(crate) fn statement(
    child: &Hash,
    image: &Hash,
    journal: &Hash,
    seal: &Hash,
    auxiliary: &Hash,
) -> Hash {
    let mut input = b"ALPH/L2/stagedreceipt/v1".to_vec();
    input.extend(child);
    input.extend([0x73, 0xc4, 0x57, 0xba]);
    for part in [image, journal, seal, auxiliary] {
        input.extend(part);
    }
    sha(&input)
}
