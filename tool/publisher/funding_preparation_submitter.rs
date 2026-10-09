//! One official testnet POST after the controller's durable submit marker.
use crate::{
    funding_preparation::{FundingPreparationPhase as Phase, FundingPreparationRecord as Record},
    funding_preparation_service::{
        PreparationExternalError as Error, PreparationSubmitter, matches_cap, same_spec,
    },
};
use alephium_l2_sdk::alephium::{
    current_funding::CurrentFundingPolicy,
    funding_preparation::{
        FundingPreparationSpec, ValidatedFundingPreparation, verify_funding_preparation_signature,
    },
    read_node::{ConfirmationCounts, GenesisPin, GenesisProvenance, OFFICIAL_TESTNET_ORIGIN},
};
use alloy_primitives::B256;
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Deserialize;
use serde_json::json;
use std::{io::Read, time::Duration};

pub struct FundingPreparationHttpSubmitter {
    client: Client,
    url: Url,
    expected: FundingPreparationSpec,
    enabled: bool,
    consumed: bool,
}

impl FundingPreparationHttpSubmitter {
    /// The authoritative root interlock is independent of the read-only projection.
    pub fn from_env(
        path: &std::path::Path,
        origin: &str,
        expected: FundingPreparationSpec,
        explicitly_enabled: bool,
    ) -> Result<Self, Error> {
        let bytes = crate::configured_signer_env::read(path).map_err(|_| Error::Rejected)?;
        let text = bytes.text().map_err(|_| Error::Rejected)?;
        let values = crate::configured_signer_env::parse(text).map_err(|_| Error::Rejected)?;
        submission_interlock(
            values.get("L2_P5_LIVE_SUBMISSION_ENABLED").copied(),
            explicitly_enabled,
        )?;
        Self::new(origin, expected, true)
    }
    pub fn new(
        origin: &str,
        expected: FundingPreparationSpec,
        enabled: bool,
    ) -> Result<Self, Error> {
        let origin = checked_origin(origin)?;
        let policy = CurrentFundingPolicy {
            minimum_confirmations: ConfirmationCounts {
                chain: 6,
                from_group: 6,
                to_group: 6,
            },
            maximum_references: 1,
            maximum_creators: 1,
        };
        let genesis = GenesisPin {
            hash: expected.network_genesis_id,
            provenance: GenesisProvenance::Independent,
        };
        if policy
            .source_id(OFFICIAL_TESTNET_ORIGIN, genesis)
            .map_err(|_| Error::Rejected)?
            != expected.funding_source_id
        {
            return Err(Error::Rejected);
        }
        let client = Client::builder()
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            client,
            url: origin
                .join("/transactions/submit")
                .map_err(|_| Error::Rejected)?,
            expected,
            enabled,
            consumed: false,
        })
    }
}

fn submission_interlock(value: Option<&str>, explicitly_enabled: bool) -> Result<(), Error> {
    if explicitly_enabled && value == Some("1") {
        Ok(())
    } else {
        Err(Error::Disabled)
    }
}

#[cfg(test)]
#[path = "../../test/publisher/funding_preparation_interlock_checks.rs"]
mod interlock_qualification;

impl PreparationSubmitter for FundingPreparationHttpSubmitter {
    fn submit(
        &mut self,
        durable: &Record,
        cap: &ValidatedFundingPreparation,
        signature: &[u8],
    ) -> Result<B256, Error> {
        if !self.enabled {
            return Err(Error::Disabled);
        }
        if self.consumed {
            return Err(Error::Consumed);
        }
        if durable.phase != Phase::SubmitAttempted
            || durable.revision < 4
            || durable.sign_attempts != 1
            || durable.submit_attempts != 1
            || durable.inclusion.is_some()
            || durable.signature.as_deref() != Some(signature)
            || !matches_cap(durable, cap)
            || !same_spec(&self.expected, cap.spec())
            || cap.pin().network_id != 1
            || cap.pin().group != 0
            || cap.pin().group_count != 4
        {
            return Err(Error::Rejected);
        }
        verify_funding_preparation_signature(cap, signature)
            .map_err(|_| Error::InvalidSignature)?;
        self.consumed = true; // Every send outcome consumes this local attempt.
        let body = json!({"unsignedTx":hex::encode(cap.unsigned_bytes()),"signature":hex::encode(signature)});
        let response = self
            .client
            .post(self.url.clone())
            .json(&body)
            .send()
            .map_err(|_| Error::Unavailable)?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|size| size > 4096)
        {
            return Err(Error::Rejected);
        }
        let mut bytes = Vec::new();
        response
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        parse_ack(&bytes, cap.tx_id())
    }
}

fn checked_origin(origin: &str) -> Result<Url, Error> {
    if origin != OFFICIAL_TESTNET_ORIGIN && origin != format!("{OFFICIAL_TESTNET_ORIGIN}/") {
        return Err(Error::Rejected);
    }
    Url::parse(origin).map_err(|_| Error::Rejected)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ack {
    tx_id: String,
    from_group: u8,
    to_group: u8,
}

fn parse_ack(bytes: &[u8], expected: B256) -> Result<B256, Error> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(Error::Rejected);
    }
    let ack: Ack = serde_json::from_slice(bytes).map_err(|_| Error::Rejected)?;
    if ack.from_group != 0
        || ack.to_group != 0
        || ack.tx_id.len() != 64
        || !ack
            .tx_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Rejected);
    }
    let raw = hex::decode(ack.tx_id).map_err(|_| Error::Rejected)?;
    if B256::from_slice(&raw) != expected {
        return Err(Error::Rejected);
    }
    Ok(expected) // Submission ACK, never execution/inclusion/confirmation evidence.
}

#[cfg(test)]
#[path = "../../test/publisher/funding_preparation_http_checks.rs"]
pub(crate) mod tests;
