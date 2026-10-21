use crate::config::ServerCreationRequest;
use crate::protocols::{dns::DnsResolver, tls};
use crate::quotas::DeviceQuotaConfig;
use crate::restrictions::types::RestrictionsRules;
use crate::revocation::RevocationManager;
use crate::tenants::TenantPolicy;
use crate::tunnel::ca_reloader::SystemCaReloader;
use crate::tunnel::server::TlsServerConfig;
use anyhow::{Context, ensure};
use parking_lot::Mutex;
use url::Url;

pub(crate) struct ServerConfigFiles {
    pub tls: Option<TlsServerConfig>,
    pub restrictions: RestrictionsRules,
    pub device_quotas: Option<DeviceQuotaConfig>,
    pub http_proxy: Option<Url>,
}

/// Validate server arguments and referenced policy/TLS files without starting services.
/// Does not resolve addresses, bind sockets, start watchers, or open the inventory database.
pub fn check_server_config(args: &ServerCreationRequest) -> anyhow::Result<()> {
    load_server_files(args)?;
    Ok(())
}

pub(crate) fn load_server_files(args: &ServerCreationRequest) -> anyhow::Result<ServerConfigFiles> {
    ensure!(
        matches!(args.remote_addr.scheme(), "ws" | "http" | "wss" | "wts"),
        "server URL must use ws://, http://, wss:// or wts://; use wss:// for a TLS HTTP/2 listener"
    );
    ensure!(args.remote_addr.host().is_some(), "server URL must contain a listen host");
    if let Some(address) = args.management_api {
        ensure!(address.ip().is_loopback(), "management API must bind to loopback");
    }
    DnsResolver::validate_urls(&args.dns_resolver)?;
    let http_proxy = crate::mk_http_proxy(
        args.http_proxy.clone(),
        args.http_proxy_login.clone(),
        args.http_proxy_password.clone(),
    )?;
    let tls_enabled = matches!(args.remote_addr.scheme(), "wss" | "wts");
    ensure!(
        tls_enabled || !args.enable_webtransport,
        "--enable-webtransport requires TLS: use wss:// or wts://"
    );
    ensure!(
        tls_enabled
            || (args.tls_certificate.is_none() && args.tls_private_key.is_none() && args.tls_client_ca_certs.is_none()),
        "TLS certificate/key/client-CA options require a TLS listener (wss:// or wts://)"
    );
    ensure!(
        args.tls_certificate.is_some() == args.tls_private_key.is_some(),
        "--tls-certificate and --tls-private-key must be supplied together"
    );
    let tls = if tls_enabled {
        SystemCaReloader::init_crypto_provider();
        let (certificates, key) = match (&args.tls_certificate, &args.tls_private_key) {
            (Some(certificate), Some(key)) => (
                tls::load_certificates_from_pem(certificate)
                    .with_context(|| format!("Cannot load server certificate {}", certificate.display()))?,
                tls::load_private_key_from_file(key)
                    .with_context(|| format!("Cannot load server private key {}", key.display()))?,
            ),
            _ => (
                crate::embedded_certificate::TLS_CERTIFICATE.0.clone(),
                crate::embedded_certificate::TLS_CERTIFICATE.1.clone_key(),
            ),
        };
        let client_ca = args
            .tls_client_ca_certs
            .as_ref()
            .map(|path| {
                tls::load_certificates_from_pem(path)
                    .map(Mutex::new)
                    .with_context(|| format!("Cannot load client CA {}", path.display()))
            })
            .transpose()?;
        let config = TlsServerConfig {
            tls_certificate: Mutex::new(certificates),
            tls_key: Mutex::new(key),
            tls_client_ca_certificates: client_ca,
            tls_certificate_path: args.tls_certificate.clone(),
            tls_key_path: args.tls_private_key.clone(),
            tls_client_ca_certs_path: args.tls_client_ca_certs.clone(),
        };
        tls::validate_server_config(&config, args.enable_webtransport || args.remote_addr.scheme() == "wts")
            .context("Invalid server TLS identity or client trust bundle")?;
        Some(config)
    } else {
        None
    };
    let restrictions = if let Some(path) = &args.restrict_config {
        RestrictionsRules::from_config_file(path)
            .with_context(|| format!("Cannot load restriction config {}", path.display()))?
    } else {
        let destinations = args
            .restrict_to
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|destination| {
                let (host, port) = destination
                    .rsplit_once(':')
                    .context("--restrict-to requires HOST:PORT")?;
                ensure!(!host.is_empty(), "--restrict-to host must not be empty");
                Ok((
                    host.trim_matches(['[', ']']).to_owned(),
                    port.parse::<u16>().context("Invalid --restrict-to port")?,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        RestrictionsRules::from_path_prefix(
            args.restrict_http_upgrade_path_prefix.as_deref().unwrap_or(&[]),
            &destinations,
        )?
    };
    let verified_mtls = tls
        .as_ref()
        .is_some_and(|config| config.tls_client_ca_certificates.is_some());
    for (enabled, option) in [
        (args.device_quota_config.is_some(), "device quotas"),
        (args.device_revocation_config.is_some(), "device revocation"),
        (args.tenant_config.is_some(), "tenant isolation"),
        (args.fleet_inventory.is_some(), "fleet inventory"),
    ] {
        ensure!(
            !enabled || verified_mtls,
            "{option} requires TLS and --tls-client-ca-certs (verified mTLS identity)"
        );
    }
    let device_quotas = args
        .device_quota_config
        .as_deref()
        .map(DeviceQuotaConfig::from_path)
        .transpose()?;
    if let Some(path) = &args.device_revocation_config {
        RevocationManager::from_path(path)?;
    }
    if let Some(path) = &args.tenant_config {
        ensure!(args.restrict_config.is_some(), "tenant isolation requires --restrict-config");
        TenantPolicy::from_path(path, &restrictions)?;
    }
    Ok(ServerConfigFiles {
        tls,
        restrictions,
        device_quotas,
        http_proxy,
    })
}
