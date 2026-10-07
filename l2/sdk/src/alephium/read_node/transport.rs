use super::{MAX_RESPONSE_BYTES, ReadNodeError as Error};
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::de::DeserializeOwned;
use std::{io::Read, time::Duration};

pub(super) struct Transport {
    client: Client,
    origin: Url,
}

pub(super) fn parse_origin(value: &str) -> Result<Url, Error> {
    if value.trim() != value || value.chars().any(|c| c.is_control() || c == '\\') {
        return Err(Error::InvalidOrigin);
    }
    let origin = Url::parse(value).map_err(|_| Error::InvalidOrigin)?;
    let canonical = origin.origin().ascii_serialization();
    if value != canonical && value != format!("{canonical}/") {
        return Err(Error::InvalidOrigin);
    }
    let host = origin
        .host_str()
        .ok_or(Error::InvalidOrigin)?
        .trim_end_matches('.');
    if origin.scheme() != "https"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || !matches!(origin.path(), "" | "/")
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.port_or_known_default() != Some(443)
        || !host.contains('.')
        || host.parse::<std::net::IpAddr>().is_ok()
        || [".localhost", ".local", ".internal"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        return Err(Error::InvalidOrigin);
    }
    Ok(origin)
}

/// Pure shared origin pinning; uses exactly the transport's accepted profile.
pub(crate) fn canonical_origin(value: &str) -> Result<String, Error> {
    Ok(parse_origin(value)?
        .as_str()
        .trim_end_matches('/')
        .to_owned())
}

impl Transport {
    pub(super) fn new(value: &str) -> Result<Self, Error> {
        let origin = parse_origin(value)?;
        let client = Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .no_proxy()
            .retry(reqwest::retry::never())
            // Hyper can separately retry an unstarted request on a canceled
            // pooled connection; keep no idle connections for this strict path.
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self { client, origin })
    }

    pub(super) fn origin(&self) -> &str {
        self.origin.as_str().trim_end_matches('/')
    }

    pub(super) fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, Error> {
        if !path.starts_with('/') || path.starts_with("//") || path.contains(['?', '#', '\\']) {
            return Err(Error::InvalidOrigin);
        }
        let url = self.origin.join(path).map_err(|_| Error::InvalidOrigin)?;
        if url.origin() != self.origin.origin() {
            return Err(Error::InvalidOrigin);
        }
        let mut response = self
            .client
            .get(url)
            .query(query)
            .header("Accept", "application/json")
            .send()
            .map_err(|_| Error::Transport)?;
        check_status(response.status().as_u16())?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(Error::ResponseTooLarge);
        }
        decode_response(&read_bounded(&mut response)?)
    }
}

pub(super) fn check_status(status: u16) -> Result<(), Error> {
    if status == 200 {
        Ok(())
    } else {
        Err(Error::HttpStatus(status))
    }
}

pub(super) fn read_bounded(source: &mut impl Read) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let remaining = MAX_RESPONSE_BYTES - bytes.len();
        let requested = chunk.len().min(remaining + 1);
        let count = source
            .read(&mut chunk[..requested])
            .map_err(|_| Error::Transport)?;
        if count == 0 {
            return Ok(bytes);
        }
        if count > remaining {
            return Err(Error::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

pub(super) fn decode_response<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::ResponseTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::MalformedResponse)
}
