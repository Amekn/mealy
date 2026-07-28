use crate::web::{resolve_pinned_public_https_destination, url_literal_ip};
use mealy_application::{
    RegistryMirrorRequest, RegistryMirrorResponse, RegistryMirrorTransport,
    RegistryMirrorTransportError,
};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    header::{
        ACCEPT, ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
        USER_AGENT,
    },
};
use std::{
    collections::BTreeSet,
    io::Read,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

const REGISTRY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REGISTRY_REQUEST_TIMEOUT: Duration = Duration::from_mins(5);
const REGISTRY_READ_BUFFER_BYTES: usize = 8 * 1024;

/// Redirect-free, proxy-free, DNS-pinned HTTPS transport for untrusted registry mirrors.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpsRegistryMirrorTransport;

impl RegistryMirrorTransport for HttpsRegistryMirrorTransport {
    fn fetch(
        &self,
        request: &RegistryMirrorRequest,
    ) -> Result<RegistryMirrorResponse, RegistryMirrorTransportError> {
        let url = request.url();
        let sockets = resolve_pinned_public_https_destination(url)
            .map_err(|_| RegistryMirrorTransportError::Rejected)?;
        let allowed_addresses = sockets.iter().map(SocketAddr::ip).collect::<BTreeSet<_>>();
        let host = url
            .host_str()
            .ok_or(RegistryMirrorTransportError::Rejected)?;
        let literal = url_literal_ip(url);
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(REGISTRY_CONNECT_TIMEOUT)
            .timeout(REGISTRY_REQUEST_TIMEOUT)
            .pool_max_idle_per_host(0);
        if literal.is_none() {
            builder = builder.resolve_to_addrs(host, &sockets);
        }
        let client = builder
            .build()
            .map_err(|_| RegistryMirrorTransportError::Unavailable)?;
        let response = client
            .get(url.clone())
            .header(
                USER_AGENT,
                concat!("Mealy/", env!("CARGO_PKG_VERSION"), " registry-mirror"),
            )
            .header(ACCEPT, request.expected_media_type())
            .header(ACCEPT_ENCODING, "identity")
            .header(CACHE_CONTROL, "no-transform")
            .send()
            .map_err(|_| RegistryMirrorTransportError::Unavailable)?;
        read_registry_response(
            response,
            &allowed_addresses,
            request.expected_media_type(),
            request.maximum_bytes(),
        )
    }
}

fn read_registry_response(
    mut response: Response,
    allowed_addresses: &BTreeSet<IpAddr>,
    expected_media_type: &str,
    maximum_bytes: u64,
) -> Result<RegistryMirrorResponse, RegistryMirrorTransportError> {
    if response
        .remote_addr()
        .is_none_or(|address| !allowed_addresses.contains(&address.ip()))
        || response.status() != StatusCode::OK
    {
        return Err(RegistryMirrorTransportError::Rejected);
    }
    let content_lengths = response.headers().get_all(CONTENT_LENGTH);
    let mut content_lengths = content_lengths.iter();
    if let Some(value) = content_lengths.next() {
        if content_lengths.next().is_some() {
            return Err(RegistryMirrorTransportError::Rejected);
        }
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(RegistryMirrorTransportError::Rejected)?;
        if length > maximum_bytes {
            return Err(RegistryMirrorTransportError::ResponseTooLarge);
        }
    }
    if response
        .headers()
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|value| value.as_bytes() != b"identity")
    {
        return Err(RegistryMirrorTransportError::Rejected);
    }
    let content_types = response.headers().get_all(CONTENT_TYPE);
    let mut content_types = content_types.iter();
    let media_type = content_types
        .next()
        .filter(|_| content_types.next().is_none())
        .and_then(|value| value.to_str().ok())
        .filter(|value| *value == expected_media_type)
        .ok_or(RegistryMirrorTransportError::Rejected)?
        .to_owned();
    let bytes = read_bounded_body(&mut response, maximum_bytes)?;
    Ok(RegistryMirrorResponse { media_type, bytes })
}

fn read_bounded_body(
    reader: &mut impl Read,
    maximum_bytes: u64,
) -> Result<Vec<u8>, RegistryMirrorTransportError> {
    let maximum =
        usize::try_from(maximum_bytes).map_err(|_| RegistryMirrorTransportError::Rejected)?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; REGISTRY_READ_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| RegistryMirrorTransportError::Unavailable)?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(read) > maximum {
            return Err(RegistryMirrorTransportError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpsRegistryMirrorTransport, read_bounded_body};
    use mealy_application::{
        RegistryMirror, RegistryMirrorError, RegistryMirrorTransportError,
        fetch_registry_snapshot_envelope,
    };
    use std::io::Cursor;

    #[test]
    fn bounded_body_accepts_exact_limit_and_rejects_one_extra_byte() {
        assert_eq!(
            read_bounded_body(&mut Cursor::new(b"exact"), 5).expect("exact body"),
            b"exact"
        );
        assert_eq!(
            read_bounded_body(&mut Cursor::new(b"excess"), 5),
            Err(RegistryMirrorTransportError::ResponseTooLarge)
        );
    }

    #[test]
    fn registry_transport_never_inherits_loopback_web_exceptions() {
        for base_url in ["https://127.0.0.1/", "https://[::1]/"] {
            let mirror = RegistryMirror {
                registry_id: "dev.mealy.registry".to_owned(),
                base_url: base_url.to_owned(),
            };
            assert_eq!(
                fetch_registry_snapshot_envelope(&HttpsRegistryMirrorTransport, &mirror),
                Err(RegistryMirrorError::Transport(
                    RegistryMirrorTransportError::Rejected
                )),
                "accepted {base_url}"
            );
        }
    }
}
