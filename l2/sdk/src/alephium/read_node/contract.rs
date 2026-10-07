use super::{
    ContractAddress, ContractValue, ContractView, CurrentContractState, IdentityObservation,
    MAX_CONTRACT_DATA_BYTES, P2pkhAddress, ReadNodeError as Error, wire,
};
use alloy_primitives::{B256, I256};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
enum Field {
    Bool(bool),
    I256(String),
    U256(wire::Amount),
    ByteVec(wire::Bytes<MAX_CONTRACT_DATA_BYTES>),
    Address(String),
    Array(wire::List<Field, 256>),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Asset {
    atto_alph_amount: wire::Amount,
    tokens: Option<wire::List<wire::Token, 64>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct State {
    address: String,
    bytecode: wire::Bytes<32768>,
    code_hash: wire::Hash,
    initial_state_hash: Option<wire::Hash>,
    imm_fields: wire::List<Field, 256>,
    mut_fields: wire::List<Field, 256>,
    asset: Asset,
}

struct Budget {
    remaining: usize,
    values: usize,
}
impl Budget {
    fn add(&mut self, bytes: usize) -> Result<(), Error> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(Error::ResponseTooLarge)?;
        self.values += 1;
        if self.values > 1024 {
            return Err(Error::ResponseTooLarge);
        }
        Ok(())
    }
}

fn field(value: Field, budget: &mut Budget, depth: usize) -> Result<ContractValue, Error> {
    if depth > 8 {
        return Err(Error::UnsupportedValue);
    }
    Ok(match value {
        Field::Bool(value) => {
            budget.add(1)?;
            ContractValue::Bool(value)
        }
        Field::I256(value) => {
            let digits = value.strip_prefix('-').unwrap_or(&value);
            if value.len() > 78
                || digits.is_empty()
                || !digits.bytes().all(|b| b.is_ascii_digit())
                || digits.len() > 1 && digits.starts_with('0')
                || value == "-0"
            {
                return Err(Error::MalformedResponse);
            }
            let value = value
                .parse::<I256>()
                .map_err(|_| Error::MalformedResponse)?;
            budget.add(32)?;
            ContractValue::I256(value)
        }
        Field::U256(value) => {
            budget.add(32)?;
            ContractValue::U256(value.0)
        }
        Field::ByteVec(value) => {
            budget.add(value.0.len())?;
            ContractValue::ByteVec(value.0)
        }
        Field::Address(value) => {
            budget.add(33)?;
            if let Ok(address) = P2pkhAddress::parse(&value) {
                ContractValue::P2pkhAddress(address)
            } else {
                ContractValue::ContractAddress(ContractAddress::parse(&value)?)
            }
        }
        Field::Array(values) => {
            budget.add(0)?;
            ContractValue::Array(
                values
                    .0
                    .into_iter()
                    .map(|value| field(value, budget, depth + 1))
                    .collect::<Result<_, _>>()?,
            )
        }
    })
}

impl State {
    pub(super) fn checked(
        self,
        identity: IdentityObservation,
        expected: &ContractAddress,
        expected_code_hash: B256,
        code: Vec<u8>,
        maximum_data_bytes: usize,
    ) -> Result<CurrentContractState, Error> {
        if maximum_data_bytes == 0 || maximum_data_bytes > MAX_CONTRACT_DATA_BYTES {
            return Err(Error::InvalidConfiguration);
        }
        if expected_code_hash == B256::ZERO
            || ContractAddress::parse(&self.address)? != *expected
            || self.code_hash.0 != expected_code_hash
            || self.bytecode.0 != code
            || code.is_empty()
            || crate::alephium::alephium_hash(&code) != expected_code_hash
        {
            return Err(Error::ContractMismatch);
        }
        let mut budget = Budget {
            remaining: maximum_data_bytes,
            values: 0,
        };
        let immutable_fields = self
            .imm_fields
            .0
            .into_iter()
            .map(|value| field(value, &mut budget, 0))
            .collect::<Result<_, _>>()?;
        let mutable_fields = self
            .mut_fields
            .0
            .into_iter()
            .map(|value| field(value, &mut budget, 0))
            .collect::<Result<_, _>>()?;
        Ok(CurrentContractState {
            identity,
            view: ContractView::CurrentUnanchored,
            address: expected.clone(),
            code_hash: expected_code_hash,
            bytecode: code,
            initial_state_hash: self.initial_state_hash.map(|hash| hash.0),
            immutable_fields,
            mutable_fields,
            atto_alph_amount: self.asset.atto_alph_amount.0,
            tokens: wire::tokens(self.asset.tokens.map_or_else(Vec::new, |tokens| tokens.0))?,
            field_data_bytes: maximum_data_bytes - budget.remaining,
        })
    }
}
