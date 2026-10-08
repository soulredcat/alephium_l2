use super::{blocks, contract, identity, transactions, transport::Transport, utxos, wire, *};
use alloy_primitives::B256;

/// A blocking GET-only observer of one independently configured HTTPS origin.
/// Multiple GETs are not an atomic consensus snapshot. No method polls, retries,
/// signs, submits, supplies historical contract effects or authorizes funding.
pub struct ReadNode {
    transport: Transport,
    config: ReadNodeConfig,
    identity: Option<IdentityObservation>,
}

impl ReadNode {
    /// Construct transport without performing DNS or HTTP requests.
    pub fn new(config: ReadNodeConfig) -> Result<Self, ReadNodeError> {
        if config.source_id == B256::ZERO || config.chain_0_0_genesis.hash == B256::ZERO {
            return Err(ReadNodeError::InvalidConfiguration);
        }
        Ok(Self {
            transport: Transport::new(&config.origin)?,
            config,
            identity: None,
        })
    }

    pub fn identity(&self) -> Option<&IdentityObservation> {
        self.identity.as_ref()
    }

    /// Check exact version/network/groups/readiness and the supplied chain-0_0
    /// genesis pin. A failed refresh invalidates the previous handshake.
    pub fn handshake(&mut self) -> Result<IdentityObservation, ReadNodeError> {
        self.identity = None;
        let observed = self.read_identity()?;
        let genesis = self.canonical_header_inner(0)?;
        check_genesis(&observed, &genesis)?;
        self.identity = Some(observed.clone());
        Ok(observed)
    }

    pub fn current_height(&self) -> Result<HeightObservation, ReadNodeError> {
        let identity = self.guard()?;
        Ok(HeightObservation {
            identity,
            height: self.height_inner()?,
        })
    }

    /// The head height and header are separate node observations, not an atomic
    /// head snapshot. The reported header is rechecked for main-chain membership.
    pub fn head(&self) -> Result<HeaderObservation, ReadNodeError> {
        let identity = self.guard()?;
        let header = self.canonical_header_inner(self.height_inner()?)?;
        Ok(HeaderObservation { identity, header })
    }

    pub fn canonical_header(&self, height: u64) -> Result<HeaderObservation, ReadNodeError> {
        let identity = self.guard()?;
        let header = self.canonical_header_inner(height)?;
        Ok(HeaderObservation { identity, header })
    }

    /// Reconcile once. NotFound, Conflicted, HTTP failure and changing inclusion
    /// do not authorize a retry, replacement, re-signature or resubmission.
    pub fn transaction(&self, tx_id: B256) -> Result<TransactionObservation, ReadNodeError> {
        self.transaction_details(tx_id)
            .map(TransactionDetailsObservation::into_observation)
    }

    /// Discover one funding creator across chains 0..3 -> 0. Settlement reads
    /// remain on 0 -> 0. Creator heights must not be compared across chains.
    pub fn funding_creator_details(
        &self,
        tx_id: B256,
    ) -> Result<Owner0CreatorDetails, ReadNodeError> {
        if tx_id == B256::ZERO {
            return Err(ReadNodeError::InvalidConfiguration);
        }
        let identity = self.guard()?;
        super::creator_transactions::read(&self.transport, tx_id, identity)
    }

    /// Retain exact matched details for additional strict decoding. Pending,
    /// missing and conflicted outcomes carry no details. This observes a node-
    /// reported inclusion, not a historical funding snapshot or PoW proof.
    pub fn transaction_details(
        &self,
        tx_id: B256,
    ) -> Result<TransactionDetailsObservation, ReadNodeError> {
        if tx_id == B256::ZERO {
            return Err(ReadNodeError::InvalidConfiguration);
        }
        let identity = self.guard()?;
        let outcome = match self.status_inner(tx_id)? {
            TransactionStatus::TxNotFound => TransactionOutcome::TxNotFound,
            TransactionStatus::MemPooled => TransactionOutcome::MemPooled,
            TransactionStatus::Conflicted(value) => TransactionOutcome::Conflicted(value),
            TransactionStatus::Confirmed(first) => {
                return transactions::confirmed_in_chain(
                    &self.transport,
                    tx_id,
                    identity,
                    first,
                    0,
                );
            }
        };
        Ok(TransactionDetailsObservation {
            observation: TransactionObservation {
                identity,
                transaction_id: tx_id,
                outcome,
            },
            retained_details: None,
        })
    }

    /// Resolve an asset reference through the official index. No output-index
    /// guess or fallback is used; this lookup alone authenticates no amount.
    pub fn resolve_output_creator(
        &self,
        reference: crate::alephium::OutputRef,
    ) -> Result<B256, ReadNodeError> {
        let query = creator_query(reference)?;
        self.guard()?;
        let id: wire::Hash = self
            .transport
            .get("/transactions/tx-id-from-outputref", &query)?;
        if id.0 == B256::ZERO {
            return Err(ReadNodeError::TransactionMismatch);
        }
        Ok(id.0)
    }

    /// Read current state and compare its code to an independently supplied
    /// protocol code-hash pin. This is not an inclusion-time effect observation.
    pub fn contract_state(
        &self,
        address: &ContractAddress,
        expected_code_hash: B256,
        maximum_field_data_bytes: usize,
    ) -> Result<CurrentContractState, ReadNodeError> {
        if address.group() != 0
            || expected_code_hash == B256::ZERO
            || maximum_field_data_bytes == 0
            || maximum_field_data_bytes > MAX_CONTRACT_DATA_BYTES
        {
            return Err(ReadNodeError::InvalidConfiguration);
        }
        let identity = self.guard()?;
        let state: contract::State = self
            .transport
            .get(&format!("/contracts/{}/state", address.as_str()), &[])?;
        let code: wire::Bytes<32768> = self.transport.get(
            &format!("/contracts/{}/code", hex_hash(expected_code_hash)),
            &[],
        )?;
        state.checked(
            identity,
            address,
            expected_code_hash,
            code.0,
            maximum_field_data_bytes,
        )
    }

    /// The endpoint always includes mempool UTXOs and cannot query a historical
    /// canonical head. This result must never implement CanonicalFundingSource.
    pub fn unanchored_utxos(&self, owner: &P2pkhAddress) -> Result<UnanchoredUtxos, ReadNodeError> {
        if owner.group() != 0 {
            return Err(ReadNodeError::UnsupportedAddress);
        }
        let identity = self.guard()?;
        let values: utxos::Utxos = self.transport.get(
            &format!("/addresses/{}/utxos", owner.as_str()),
            &[("error-if-exceed-max-utxos", "true".into())],
        )?;
        values.checked(owner, identity)
    }

    fn read_identity(&self) -> Result<IdentityObservation, ReadNodeError> {
        let version = self.transport.get("/infos/version", &[])?;
        let params = self.transport.get("/infos/chain-params", &[])?;
        let clique = self.transport.get("/infos/self-clique", &[])?;
        identity::validate(
            &self.config,
            self.transport.origin(),
            version,
            params,
            clique,
        )
    }

    fn guard(&self) -> Result<IdentityObservation, ReadNodeError> {
        let expected = self
            .identity
            .as_ref()
            .ok_or(ReadNodeError::HandshakeRequired)?;
        let current = self.read_identity()?;
        if &current != expected {
            return Err(ReadNodeError::ObservationChanged);
        }
        // Unlike the local L2 RPC, these REST endpoints have no server-enforced
        // genesis argument. Reobserve it rather than echoing the cached pin if
        // the public origin was reset/replaced with another testnet history.
        check_genesis(&current, &self.canonical_header_inner(0)?)?;
        Ok(current)
    }

    fn height_inner(&self) -> Result<u64, ReadNodeError> {
        let info: blocks::ChainInfo = self
            .transport
            .get("/blockflow/chain-info", &chain_query())?;
        wire::nonnegative(i64::from(info.current_height))
    }

    fn canonical_header_inner(&self, height: u64) -> Result<ChainHeader, ReadNodeError> {
        blocks::read_canonical(&self.transport, height, 0)
    }
    fn status_inner(&self, tx_id: B256) -> Result<TransactionStatus, ReadNodeError> {
        transactions::read_status(&self.transport, tx_id, Some(0))
    }
}

fn chain_query() -> [(&'static str, String); 2] {
    [("fromGroup", "0".into()), ("toGroup", "0".into())]
}
fn hex_hash(hash: B256) -> String {
    hex::encode(hash.as_slice())
}

pub(super) fn creator_query(
    reference: crate::alephium::OutputRef,
) -> Result<[(&'static str, String); 2], ReadNodeError> {
    let hint = reference.hint;
    let group = ((hint ^ (hint >> 8) ^ (hint >> 16) ^ (hint >> 24)) as u8) % 4;
    if hint & 1 != 1 || group != 0 || reference.key == B256::ZERO {
        return Err(ReadNodeError::UnsupportedAddress);
    }
    Ok([
        ("hint", (hint as i32).to_string()),
        ("key", hex_hash(reference.key)),
    ])
}

pub(super) fn check_genesis(
    identity: &IdentityObservation,
    header: &ChainHeader,
) -> Result<(), ReadNodeError> {
    if header.height != 0 || header.hash != identity.chain_0_0_genesis.hash {
        return Err(ReadNodeError::GenesisMismatch);
    }
    Ok(())
}
