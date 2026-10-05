//! Pinned inputs and independent identities for the synthetic staged lifecycle.
use crate::{ordinary_miller, receipt_cases, residue_witness};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_REQUESTS: usize = 40;
pub const MUTABLE_WORDS: usize = 80;
pub const INITIAL_CURSOR: u64 = 65;
pub const ID_DOMAIN: &[u8] = b"ALPH/L2/stagedreceipt/v1";

pub struct Fixture {
    pub begin_args: Vec<Value>,
    pub wrong_image_args: Vec<Value>,
    pub wrong_journal_args: Vec<Value>,
    pub statement_id: String,
    pub wrong_image_id: String,
    pub wrong_journal_id: String,
    pub contract_id: [u8; 32],
    pub address: String,
}

impl Fixture {
    pub fn load() -> Result<Self, String> {
        let mut contract_id: [u8; 32] =
            Sha256::digest(b"ALPH/L2/stagedreceipt/development-fixture/v1").into();
        contract_id[31] = 0;
        Self::at_id(&contract_id)
    }

    pub fn at_id(contract_id: &[u8; 32]) -> Result<Self, String> {
        if contract_id[31] != 0 {
            return Err("Staged fixture must use exact group zero".into());
        }
        // This independently verifies the actual pairing and proves both image
        // and journal perturbations false before any target request is made.
        let corpus = receipt_cases::corpus()?;
        let official = corpus.first().ok_or("Missing official receipt case")?;
        let pairs = receipt_cases::official_pair_inputs()?;
        let product = ordinary_miller::miller_product(&pairs)?;
        ordinary_miller::certify_normalized_product(&pairs, product)?;
        let auxiliary = residue_witness::generate(product)?;
        let mut encoded = official.args.clone();
        encoded.push(hex::encode(auxiliary));
        Self::from_encoded(contract_id, &encoded)
    }

    /// The caller must certify the original equation and both altered claims.
    /// This constructor binds exact bytes; it grants no target acceptance.
    pub(crate) fn from_encoded(contract_id: &[u8; 32], encoded: &[String]) -> Result<Self, String> {
        if contract_id[31] != 0 {
            return Err("Staged fixture must use exact group zero".into());
        }
        let statement = statement_id(contract_id, encoded)?;
        let changed = |index: usize| -> Result<Vec<String>, String> {
            let mut args = encoded.to_vec();
            let mut field = hex::decode(&args[index]).map_err(|_| "Invalid staged claim bytes")?;
            field[0] ^= 1;
            args[index] = hex::encode(field);
            Ok(args)
        };
        let wrong_image = changed(1)?;
        let wrong_journal = changed(2)?;
        Ok(Self {
            statement_id: statement,
            wrong_image_id: statement_id(contract_id, &wrong_image)?,
            wrong_journal_id: statement_id(contract_id, &wrong_journal)?,
            begin_args: encoded.iter().map(|value| bytes(value)).collect(),
            wrong_image_args: wrong_image.iter().map(|value| bytes(value)).collect(),
            wrong_journal_args: wrong_journal.iter().map(|value| bytes(value)).collect(),
            contract_id: *contract_id,
            address: contract_address(contract_id),
        })
    }

    pub fn zero_witness_args(&self) -> Result<Vec<Value>, String> {
        let mut args = self.begin_args.clone();
        let encoded = args[3]["value"].as_str().ok_or("Missing auxiliary bytes")?;
        let mut auxiliary = hex::decode(encoded).map_err(|_| "Malformed auxiliary bytes")?;
        if auxiliary.len() != 577 || auxiliary[0] != 1 {
            return Err("Staged auxiliary wire version or size differs".into());
        }
        auxiliary[1..385].fill(0);
        args[3] = bytes(&hex::encode(auxiliary));
        Ok(args)
    }
}

fn statement_id(contract_id: &[u8; 32], args: &[String]) -> Result<String, String> {
    if args.len() != 4 {
        return Err("Staged statement requires exactly four byte vectors".into());
    }
    let input = args
        .iter()
        .map(|encoded| hex::decode(encoded).map_err(|_| "Invalid staged input hex"))
        .collect::<Result<Vec<_>, _>>()?;
    if input[0].len() != 260
        || input[1].len() != 32
        || input[2].len() != 32
        || input[3].len() != 577
    {
        return Err("Staged input differs from the fixed wire layout".into());
    }
    let mut hash = Sha256::new();
    hash.update(ID_DOMAIN);
    hash.update(contract_id);
    if input[0][..4] != [0x73, 0xc4, 0x57, 0xba] {
        return Err("Staged statement selector differs from the certified key".into());
    }
    hash.update([0x73, 0xc4, 0x57, 0xba]);
    hash.update(&input[1]);
    hash.update(&input[2]);
    hash.update(Sha256::digest(&input[0]));
    hash.update(Sha256::digest(&input[3]));
    Ok(hex::encode(hash.finalize()))
}

// v4.7.0 LockupScript.P2C serializes as 03 || ContractId, without a checksum.
// Existing BigUint avoids adding an unreviewed address-codec dependency.
pub fn contract_address(contract_id: &[u8; 32]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut raw = vec![3];
    raw.extend(contract_id);
    let mut integer = BigUint::from_bytes_be(&raw);
    let base = BigUint::from(58_u8);
    let mut encoded = Vec::new();
    while integer != BigUint::from(0_u8) {
        let remainder = (&integer % &base).to_u32_digits();
        let index = remainder.first().copied().unwrap_or(0) as usize;
        encoded.push(ALPHABET[index]);
        integer /= &base;
    }
    encoded.reverse();
    encoded.into_iter().map(char::from).collect()
}

pub fn initial_fields() -> Vec<Value> {
    let mut fields = vec![crate::cases::word("0"); MUTABLE_WORDS];
    fields.push(bytes(&"00".repeat(32)));
    fields
}

pub fn bytes(value: &str) -> Value {
    json!({"type": "ByteVec", "value": value})
}

pub fn different_id(id: &str) -> Result<String, String> {
    let mut id = hex::decode(id).map_err(|_| "Invalid statement identity")?;
    if id.len() != 32 {
        return Err("Statement identity is not exactly 32 bytes".into());
    }
    id[0] ^= 1;
    Ok(hex::encode(id))
}
