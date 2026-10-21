use hyper::header::HOST;
use hyper::http::{HeaderName, HeaderValue};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

use tracing::error;

pub mod http2;
pub mod io;
mod jwt;
mod types;
pub mod websocket;
pub mod webtransport;

pub use jwt::JWT_HEADER_PREFIX;
pub use jwt::jwt_token_to_tunnel;
pub use jwt::tunnel_to_jwt_token;
pub use jwt::{JwtTunnelConfig, TunnelMetadata};
pub use types::TransportAddr;
pub use types::TransportScheme;

pub(crate) const VERSION_HEADER: &str = "x-tunward-version";
pub(crate) const PROTOCOL_VERSION: &str = "2";

pub(crate) fn insert_client_label(headers: &mut hyper::HeaderMap, client_id: Option<&str>) {
    if let Some(value) = client_id.and_then(|id| HeaderValue::from_str(id).ok()) {
        headers.insert(HeaderName::from_static("x-client-id"), value);
    }
}

pub(crate) fn check_version(headers: &hyper::HeaderMap) -> anyhow::Result<()> {
    anyhow::ensure!(
        headers.get(VERSION_HEADER).is_some_and(|v| v == PROTOCOL_VERSION),
        "peer does not support tunnel protocol v2; upgrade both peers"
    );
    Ok(())
}

#[allow(clippy::type_complexity)]
#[inline]
pub fn headers_from_file(path: &Path) -> (Option<(HeaderName, HeaderValue)>, Vec<(HeaderName, HeaderValue)>) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            error!("Cannot read headers from file: {:?}: {:?}", path, err);
            return (None, vec![]);
        }
    };

    let mut host_header = None;
    let headers = BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let (header, value) = line.split_once(':')?;
            let header = HeaderName::from_str(header.trim()).ok()?;
            let value = HeaderValue::from_str(value.trim()).ok()?;
            if header == HOST {
                host_header = Some((header, value));
                return None;
            }
            Some((header, value))
        })
        .collect();

    (host_header, headers)
}
