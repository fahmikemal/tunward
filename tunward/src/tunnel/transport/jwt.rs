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
    /// Requests of one client reverse tunnel whose server port is allocated (port 0) share this
    /// value, so the listener the first one opened keeps serving the tunnel. Peers that predate it
    /// ignore it, and serde ignores the field in their envelopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l: Option<Uuid>,
    /// In a server reply, the port its reverse listener is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lp: Option<u16>,
}

/// The identifiers a client request carries in its routing envelope.
#[derive(Debug, Clone, Copy)]
pub struct TunnelRequest {
    pub id: Uuid,
    /// Set by a reverse tunnel with an allocated server port; see [`JwtTunnelConfig::l`].
    pub listener: Option<Uuid>,
}

impl From<Uuid> for TunnelRequest {
    fn from(id: Uuid) -> Self {
        Self { id, listener: None }
    }
}

impl JwtTunnelConfig {
    fn new(request: TunnelRequest, dest: &RemoteAddr) -> Self {
        Self {
            v: 2,
            id: request.id.to_string(),
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
            l: request.listener,
            lp: None,
        }
    }

    fn encode(&self) -> String {
        format!("v2.{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).unwrap_or_default()))
    }
}

pub fn tunnel_to_jwt_token(request: impl Into<TunnelRequest>, tunnel: &RemoteAddr) -> String {
    JwtTunnelConfig::new(request.into(), tunnel).encode()
}

/// The envelope a server replies with: the connected destination and, for a reverse tunnel, the
/// port its listener is bound to.
pub fn reply_to_jwt_token(tunnel: &RemoteAddr, listener_port: Option<u16>) -> String {
    let mut reply = JwtTunnelConfig::new(Uuid::from_u128(0).into(), tunnel);
    reply.lp = listener_port;
    reply.encode()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn reverse_tcp(port: u16) -> RemoteAddr {
        RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port,
        }
    }

    fn json(token: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.strip_prefix("v2.").unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn a_listener_identity_round_trips_and_is_omitted_when_unset() {
        let listener = Uuid::from_u128(7);
        let request = TunnelRequest {
            id: Uuid::from_u128(1),
            listener: Some(listener),
        };
        let token = tunnel_to_jwt_token(request, &reverse_tcp(0));
        assert_eq!(jwt_token_to_tunnel(&token).unwrap().claims.l, Some(listener));

        let plain = tunnel_to_jwt_token(Uuid::from_u128(1), &reverse_tcp(0));
        let fields = json(&plain);
        assert!(fields.get("l").is_none() && fields.get("lp").is_none(), "{fields}");
        assert_eq!(jwt_token_to_tunnel(&plain).unwrap().claims.l, None);
    }

    #[test]
    fn a_reply_carries_the_listener_port() {
        let reply = jwt_token_to_tunnel(&reply_to_jwt_token(&reverse_tcp(4444), Some(4444))).unwrap();
        assert_eq!(reply.claims.lp, Some(4444));
        let forward = jwt_token_to_tunnel(&reply_to_jwt_token(&reverse_tcp(80), None)).unwrap();
        assert_eq!(forward.claims.lp, None);
    }

    #[test]
    fn an_envelope_without_the_new_fields_still_decodes() {
        // What a peer without listener identities sends.
        let legacy = r#"{"v":2,"id":"00000000-0000-0000-0000-000000000001","p":"ReverseTcp","r":"127.0.0.1","rp":0}"#;
        let token = format!("v2.{}", URL_SAFE_NO_PAD.encode(legacy));
        let claims = jwt_token_to_tunnel(&token).unwrap().claims;
        assert_eq!((claims.l, claims.lp), (None, None));
    }
}
