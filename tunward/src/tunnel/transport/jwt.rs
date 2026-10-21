use crate::tunnel::{LocalProtocol, RemoteAddr};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use url::Host;
use uuid::Uuid;

// Routing metadata is not an authentication credential. TLS/mTLS and restriction rules
// authenticate and authorize requests; a process-local JWT key never provided peer authentication.
pub static JWT_HEADER_PREFIX: &str = "tunward.metadata.";

#[derive(Debug)]
pub struct TunnelMetadata<T> {
    pub claims: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtTunnelConfig {
    #[serde(default)]
    pub v: u8,
    pub id: String,       // tunnel id
    pub p: LocalProtocol, // protocol to use
    pub r: String,        // remote host
    pub rp: u16,          // remote port
}

impl JwtTunnelConfig {
    fn new(request_id: Uuid, dest: &RemoteAddr) -> Self {
        Self {
            v: 2,
            id: request_id.to_string(),
            p: match dest.protocol {
                LocalProtocol::Tcp { .. } => dest.protocol.clone(),
                LocalProtocol::Udp { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseTcp => dest.protocol.clone(),
                LocalProtocol::ReverseUdp { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseSocks5 { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseUnix { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseHttpProxy { .. } => dest.protocol.clone(),
                LocalProtocol::TProxyTcp => unreachable!("cannot use tproxy tcp as destination protocol"),
                LocalProtocol::TProxyUdp { .. } => unreachable!("cannot use tproxy udp as destination protocol"),
                LocalProtocol::Stdio { .. } => unreachable!("cannot use stdio as destination protocol"),
                LocalProtocol::Unix { .. } => unreachable!("canont use unix as destination protocol"),
                LocalProtocol::Socks5 { .. } => unreachable!("cannot use socks5 as destination protocol"),
                LocalProtocol::HttpProxy { .. } => unreachable!("cannot use http proxy as destination protocol"),
            },
            r: dest.host.to_string(),
            rp: dest.port,
        }
    }
}

pub fn tunnel_to_jwt_token(request_id: Uuid, tunnel: &RemoteAddr) -> String {
    let cfg = JwtTunnelConfig::new(request_id, tunnel);
    format!("v2.{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cfg).unwrap_or_default()))
}

pub fn jwt_token_to_tunnel(token: &str) -> anyhow::Result<TunnelMetadata<JwtTunnelConfig>> {
    anyhow::ensure!(token.len() <= 8192, "tunnel metadata exceeds 8 KiB");
    let payload = token
        .strip_prefix("v2.")
        .ok_or_else(|| anyhow::anyhow!("unsupported tunnel metadata; upgrade both peers to v2"))?;
    let claims: JwtTunnelConfig = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
    anyhow::ensure!(claims.v == 2, "unsupported tunnel protocol version");
    Uuid::parse_str(&claims.id)?;
    Ok(TunnelMetadata { claims })
}

impl TryFrom<JwtTunnelConfig> for RemoteAddr {
    type Error = anyhow::Error;
    fn try_from(jwt: JwtTunnelConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            jwt.v == 2,
            "unsupported tunnel protocol version {}; upgrade both peers to v2",
            jwt.v
        );
        Ok(Self {
            protocol: jwt.p,
            host: Host::parse(&jwt.r)?,
            port: jwt.rp,
        })
    }
}
