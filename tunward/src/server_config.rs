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
use std::sync::Arc;
use url::Url;

pub(crate) struct ServerConfigFiles {
    pub tls: Option<TlsServerConfig>,
    pub restrictions: RestrictionsRules,
    pub device_quotas: Option<DeviceQuotaConfig>,
    pub http_proxy: Option<Url>,
    pub tenants: Option<Arc<TenantPolicy>>,
}

/// Validate server arguments and referenced policy/TLS files without starting services.
/// Does not resolve addresses, bind sockets, start watchers, or open the inventory database.
pub fn check_server_config(args: &ServerCreationRequest) -> anyhow::Result<()> {
    load_server_files(args)?;
    Ok(())
}

/// Check if the URL listen host is strictly loopback (IPv4 127.0.0.0/8, IPv6 ::1 or IPv4-mapped loopback, or localhost).
/// Wildcard (0.0.0.0, ::), LAN, public IPs, and non-localhost domains are treated as non-loopback during offline verification
/// to prevent hostname bypass without relying on live DNS resolution.
pub fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback() || ip.to_ipv4().is_some_and(|v4| v4.is_loopback()),
        Some(url::Host::Domain(domain)) => {
            if domain.eq_ignore_ascii_case("localhost") || domain.to_ascii_lowercase().ends_with(".localhost") {
                true
            } else if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
                match ip {
                    std::net::IpAddr::V4(v4) => v4.is_loopback(),
                    std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
                }
            } else {
                false
            }
        }
        None => false,
    }
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
    ensure!(
        !(args.no_device_quotas && args.device_quota_config.is_some()),
        "--no-device-quotas conflicts with --device-quota-config"
    );
    ensure!(
        !args.tls_handshake_timeout.is_zero(),
        "--tls-handshake-timeout must be greater than zero"
    );
    DnsResolver::validate_urls(&args.dns_resolver)?;
    let http_proxy = crate::mk_http_proxy(
        args.http_proxy.clone(),
        args.http_proxy_login.clone(),
        args.http_proxy_password.clone(),
    )?;
    let tls_enabled = matches!(args.remote_addr.scheme(), "wss" | "wts");
    let mtls_configured = tls_enabled && args.tls_client_ca_certs.is_some();
    for (enabled, requirement) in [
        (args.device_quota_config.is_some(), "device quotas require TLS"),
        (args.device_revocation_config.is_some(), "device revocation requires TLS"),
        (args.tenant_config.is_some(), "tenant isolation requires TLS"),
        (args.fleet_inventory.is_some(), "fleet inventory requires TLS"),
    ] {
        ensure!(
            !enabled || mtls_configured,
            "{requirement} and --tls-client-ca-certs (verified mTLS identity)"
        );
    }
    ensure!(
        cfg!(feature = "fleet-inventory") || args.fleet_inventory.is_none(),
        "--fleet-inventory needs a build with the fleet-inventory feature (it is on by default)"
    );
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

    let is_loopback = is_loopback_host(&args.remote_addr);
    if !is_loopback && !args.allow_insecure_dev {
        ensure!(
            tls_enabled,
            "public/non-loopback listener ({}) requires TLS (wss:// or wts://); specify --allow-insecure-dev for local development exceptions",
            args.remote_addr
        );
        ensure!(
            args.tls_client_ca_certs.is_some(),
            "public/non-loopback listener ({}) requires client authentication (--tls-client-ca-certs); specify --allow-insecure-dev for local development exceptions",
            args.remote_addr
        );
        ensure!(
            args.restrict_config.is_some(),
            "public/non-loopback listener ({}) requires an explicit restriction policy file (--restrict-config); specify --allow-insecure-dev for local development exceptions",
            args.remote_addr
        );
    }
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
    let device_quotas = if let Some(path) = &args.device_quota_config {
        Some(
            DeviceQuotaConfig::from_path(path)
                .with_context(|| format!("Cannot load device quota config {}", path.display()))?,
        )
    } else if mtls_configured && !args.no_device_quotas {
        Some(DeviceQuotaConfig::default_production_limits())
    } else {
        None
    };
    if let Some(path) = &args.device_revocation_config {
        RevocationManager::from_path(path)?;
    }
    let tenants = if let Some(path) = &args.tenant_config {
        ensure!(args.restrict_config.is_some(), "tenant isolation requires --restrict-config");
        Some(TenantPolicy::from_path(path, &restrictions)?)
    } else {
        None
    };
    Ok(ServerConfigFiles {
        tls,
        restrictions,
        device_quotas,
        http_proxy,
        tenants,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientIdentityField;
    use std::time::Duration;

    #[test]
    fn test_is_loopback_host() {
        // IPv4 loopback
        assert!(is_loopback_host(&Url::parse("ws://127.0.0.1:8080").unwrap()));
        assert!(is_loopback_host(&Url::parse("ws://127.0.0.2:8080").unwrap()));
        assert!(is_loopback_host(&Url::parse("ws://127.255.255.254:8080").unwrap()));

        // IPv6 loopback
        assert!(is_loopback_host(&Url::parse("ws://[::1]:8080").unwrap()));
        assert!(is_loopback_host(&Url::parse("ws://[::ffff:127.0.0.1]:8080").unwrap()));

        // Localhost domains
        assert!(is_loopback_host(&Url::parse("ws://localhost:8080").unwrap()));
        assert!(is_loopback_host(&Url::parse("ws://LOCALHOST:8080").unwrap()));
        assert!(is_loopback_host(&Url::parse("ws://sub.localhost:8080").unwrap()));

        // Non-loopback wildcards
        assert!(!is_loopback_host(&Url::parse("ws://0.0.0.0:8080").unwrap()));
        assert!(!is_loopback_host(&Url::parse("ws://[::]:8080").unwrap()));
        assert!(!is_loopback_host(&Url::parse("ws://[::ffff:0.0.0.0]:8080").unwrap()));

        // Non-loopback LAN and public IPs
        assert!(!is_loopback_host(&Url::parse("ws://10.0.0.1:8080").unwrap()));
        assert!(!is_loopback_host(&Url::parse("ws://192.168.1.1:8080").unwrap()));
        assert!(!is_loopback_host(&Url::parse("ws://172.16.0.1:8080").unwrap()));
        assert!(!is_loopback_host(&Url::parse("ws://8.8.8.8:8080").unwrap()));

        // Non-loopback domains (hostname handling must not bypass check)
        assert!(!is_loopback_host(&Url::parse("ws://example.com:8080").unwrap()));
        assert!(!is_loopback_host(&Url::parse("ws://127.0.0.1.nip.io:8080").unwrap()));
        assert!(!is_loopback_host(&Url::parse("ws://tunward.internal:8080").unwrap()));
    }

    fn sample_server_request(url: &str) -> ServerCreationRequest {
        ServerCreationRequest {
            remote_addr: Url::parse(url).unwrap(),
            enable_webtransport: false,
            socket_so_mark: None,
            websocket_ping_frequency: Some(Duration::from_secs(30)),
            websocket_mask_frame: false,
            dns_resolver: vec![],
            dns_resolver_prefer_ipv4: false,
            restrict_to: None,
            restrict_http_upgrade_path_prefix: None,
            restrict_config: None,
            tls_certificate: None,
            tls_private_key: None,
            tls_client_ca_certs: None,
            http_proxy: None,
            http_proxy_login: None,
            http_proxy_password: None,
            remote_to_local_server_idle_timeout: Duration::from_secs(180),
            management_api: None,
            device_quota_config: None,
            device_revocation_config: None,
            fleet_inventory: None,
            fleet_inventory_max_devices: std::num::NonZeroU32::new(10000).unwrap(),
            tenant_config: None,
            allow_insecure_dev: false,
            no_device_quotas: false,
            tls_client_identity_field: ClientIdentityField::Cn,
            tls_handshake_timeout: Duration::from_secs(10),
            max_pending_tls_handshakes: std::num::NonZeroU32::new(1024).unwrap(),
        }
    }

    #[test]
    fn test_tls_handshake_timeout_must_be_nonzero() {
        let mut req = sample_server_request("ws://127.0.0.1:8080");
        req.tls_handshake_timeout = Duration::ZERO;
        let Err(err) = load_server_files(&req) else {
            panic!("expected a zero handshake timeout to be rejected");
        };
        assert!(
            err.to_string()
                .contains("--tls-handshake-timeout must be greater than zero")
        );
    }

    #[test]
    fn test_public_listener_requires_tls() {
        let req = sample_server_request("ws://0.0.0.0:8080");
        let Err(err) = load_server_files(&req) else {
            panic!("expected error for public listener without TLS");
        };
        assert!(err.to_string().contains("requires TLS (wss:// or wts://)"));
        assert!(err.to_string().contains("--allow-insecure-dev"));
    }

    #[test]
    fn test_public_listener_requires_client_ca() {
        let req = sample_server_request("wss://0.0.0.0:8080");
        let Err(err) = load_server_files(&req) else {
            panic!("expected error for public listener without client CA");
        };
        assert!(
            err.to_string()
                .contains("requires client authentication (--tls-client-ca-certs)")
        );
    }

    #[test]
    fn test_public_listener_allows_insecure_dev() {
        let mut req = sample_server_request("ws://0.0.0.0:8080");
        req.allow_insecure_dev = true;
        match load_server_files(&req) {
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_loopback_listener_allowed_without_insecure_dev() {
        let req = sample_server_request("ws://127.0.0.1:8080");
        match load_server_files(&req) {
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }

        let req_localhost = sample_server_request("ws://localhost:8080");
        match load_server_files(&req_localhost) {
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }

        let req_ipv6 = sample_server_request("ws://[::1]:8080");
        match load_server_files(&req_ipv6) {
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_management_api_still_rejects_non_loopback_even_with_allow_insecure_dev() {
        let mut req = sample_server_request("ws://0.0.0.0:8080");
        req.allow_insecure_dev = true;
        req.management_api = Some("0.0.0.0:8081".parse().unwrap());
        let Err(err) = load_server_files(&req) else {
            panic!("expected error for non-loopback management API");
        };
        assert!(err.to_string().contains("management API must bind to loopback"));
    }

    fn write_test_ca_pem(name: &str) -> std::path::PathBuf {
        use base64::Engine;
        let path = std::env::temp_dir().join(format!("tunward-test-{}-{}.pem", std::process::id(), name));
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert.der());
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        std::fs::write(&path, pem).unwrap();
        path
    }

    #[test]
    fn test_mtls_listener_defaults_to_production_resource_limits() {
        let ca_path = write_test_ca_pem("default-quotas");
        let mut req = sample_server_request("wss://127.0.0.1:8080");
        req.tls_client_ca_certs = Some(ca_path.clone());

        let files = load_server_files(&req).expect("valid mtls configuration");
        let _ = std::fs::remove_file(ca_path);
        assert_eq!(
            files.device_quotas,
            Some(DeviceQuotaConfig::default_production_limits()),
            "Default finite production limits should be applied when mTLS is enabled without explicit quota file"
        );
    }

    #[test]
    fn test_allow_insecure_dev_keeps_default_limits() {
        // A development exception relaxes listener prerequisites only; dropping limits takes --no-device-quotas.
        let ca_path = write_test_ca_pem("insecure-dev-quotas");
        let mut req = sample_server_request("wss://0.0.0.0:8080");
        req.tls_client_ca_certs = Some(ca_path.clone());
        req.allow_insecure_dev = true;

        let files = load_server_files(&req).expect("valid development configuration");
        let _ = std::fs::remove_file(ca_path);
        assert_eq!(files.device_quotas, Some(DeviceQuotaConfig::default_production_limits()));
    }

    #[test]
    fn test_no_device_quotas_disables_default_limits() {
        let ca_path = write_test_ca_pem("no-quotas");
        let mut req = sample_server_request("wss://127.0.0.1:8080");
        req.tls_client_ca_certs = Some(ca_path.clone());
        req.no_device_quotas = true;

        let files = load_server_files(&req).expect("valid configuration with --no-device-quotas");
        let _ = std::fs::remove_file(ca_path);
        assert_eq!(files.device_quotas, None);
    }

    #[test]
    fn test_fleet_inventory_follows_the_build_feature() {
        let ca_path = write_test_ca_pem("fleet-inventory");
        let mut req = sample_server_request("wss://127.0.0.1:8080");
        req.tls_client_ca_certs = Some(ca_path.clone());
        // The offline check never opens the database, so the file need not exist.
        req.fleet_inventory = Some(std::env::temp_dir().join("tunward-test-unopened-inventory.sqlite3"));

        let result = load_server_files(&req);
        let _ = std::fs::remove_file(ca_path);
        if cfg!(feature = "fleet-inventory") {
            result.expect("an mTLS listener accepts --fleet-inventory");
        } else {
            let Err(err) = result else {
                panic!("expected a build without the fleet-inventory feature to refuse --fleet-inventory");
            };
            assert!(
                err.to_string()
                    .contains("needs a build with the fleet-inventory feature")
            );
        }
    }

    #[test]
    fn test_no_device_quotas_conflicts_with_device_quota_config() {
        let mut req = sample_server_request("wss://127.0.0.1:8080");
        req.no_device_quotas = true;
        req.device_quota_config = Some(std::path::PathBuf::from("/any/path"));

        let Err(err) = load_server_files(&req) else {
            panic!("expected conflict error when both no_device_quotas and device_quota_config are set");
        };
        assert!(
            err.to_string()
                .contains("--no-device-quotas conflicts with --device-quota-config")
        );
    }
}
