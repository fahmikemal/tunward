use ipnet::IpNet;
use regex::Regex;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::Path;
use std::str::FromStr;
use std::vec;
use types::RestrictionsRules;

pub mod config_reloader;
pub mod types;

impl RestrictionsRules {
    pub fn from_config_file(config_path: &Path) -> anyhow::Result<Self> {
        let restrictions: Self = crate::yaml::from_reader(BufReader::new(File::open(config_path)?))?;
        Ok(restrictions)
    }

    pub fn from_path_prefix(path_prefixes: &[String], restrict_to: &[(String, u16)]) -> anyhow::Result<Self> {
        let tunnels_restrictions = if restrict_to.is_empty() {
            // OWASP Deny-by-default: If no explicit destination rules are provided,
            // synthesize an empty allow list rather than allowing all destinations.
            vec![]
        } else {
            restrict_to
                .iter()
                .map(|(host, port)| {
                    let tunnels = if let Ok(ip) = IpAddr::from_str(host) {
                        vec![types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                            protocol: vec![],
                            port: vec![RangeInclusive::new(*port, *port)],
                            host: Regex::new("^$")?,
                            cidr: vec![IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 })?],
                        })]
                    } else {
                        vec![types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                            protocol: vec![],
                            port: vec![RangeInclusive::new(*port, *port)],
                            host: Regex::new(&format!("^{}$", regex::escape(host)))?,
                            cidr: vec![],
                        })]
                    };

                    Ok(tunnels)
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
                .into_iter()
                .flatten()
                .collect()
        };

        let restrictions = if path_prefixes.is_empty() {
            let r = types::RestrictionConfig {
                name: "Default Policy".to_string(),
                r#match: vec![types::MatchConfig::Any],
                allow: tunnels_restrictions,
            };
            vec![r]
        } else {
            path_prefixes
                .iter()
                .map(|path_prefix| {
                    let reg = Regex::new(&format!("^{}$", regex::escape(path_prefix)))?;
                    Ok(types::RestrictionConfig {
                        name: format!("Allow path prefix {path_prefix}"),
                        r#match: vec![types::MatchConfig::PathPrefix(reg)],
                        allow: tunnels_restrictions.clone(),
                    })
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
        };

        Ok(Self { restrictions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restrictions::types::{AllowConfig, MatchConfig};
    use std::net::Ipv4Addr;

    fn parse(allow: &str) -> anyhow::Result<RestrictionsRules> {
        let yaml = format!("restrictions:\n  - name: r\n    match: [Any]\n    allow:\n{allow}");
        Ok(crate::yaml::from_slice(yaml.as_bytes())?)
    }

    #[test]
    fn blank_values_are_refused_where_empty_would_allow_everything() {
        for allow in [
            "      - !Tunnel",
            "      - !ReverseTunnel ~",
            "      - !Tunnel\n        port:",
            "      - !Tunnel {protocol: ~}",
            "      - !ReverseTunnel {port: null}",
            "      - !ReverseTunnel {protocol:}",
        ] {
            assert!(parse(allow).is_err(), "{allow}");
        }
        // Spelled out, an empty rule still allows every port and protocol.
        let rules = parse("      - !Tunnel {}\n      - !ReverseTunnel {protocol: [], port: []}").unwrap();
        assert!(
            matches!(&rules.restrictions[0].allow[0], AllowConfig::Tunnel(t) if t.port.is_empty() && t.protocol.is_empty())
        );
        assert!(matches!(&rules.restrictions[0].allow[1], AllowConfig::ReverseTunnel(t) if t.port.is_empty()));
    }

    #[test]
    fn tagged_and_mapping_forms_read_the_same_rule() {
        let tagged = parse("      - !Tunnel {protocol: [Tcp], port: [443, 8000..8010]}").unwrap();
        let mapping = parse("      - Tunnel: {protocol: [Tcp], port: ['443', '8000..8010']}").unwrap();
        for rules in [tagged, mapping] {
            let AllowConfig::Tunnel(tunnel) = &rules.restrictions[0].allow[0] else {
                panic!("Expected Tunnel configuration");
            };
            assert_eq!(tunnel.protocol, [crate::restrictions::types::TunnelProtocol::Tcp]);
            assert_eq!(tunnel.port, [443..=443, 8000..=8010]);
        }
    }

    #[test]
    fn test_restriction_rule_with_host_restriction() -> anyhow::Result<()> {
        // Test setup with empty path prefixes and specific host restriction
        let path_prefixes: Vec<String> = vec![];
        let restrict_to = vec![("google.com".to_string(), 443)];

        let rules = RestrictionsRules::from_path_prefix(&path_prefixes, &restrict_to)?;

        // Validate the rules structure
        assert_eq!(rules.restrictions.len(), 1);

        // Get the first restriction
        let restriction = &rules.restrictions[0];

        // Validate the restriction name
        assert_eq!(restriction.name, "Default Policy");

        // Validate that there's exactly one allow rule
        assert_eq!(restriction.allow.len(), 1);

        // Check the tunnel configuration
        if let AllowConfig::Tunnel(tunnel_config) = &restriction.allow[0] {
            // Validate the host regex pattern
            assert_eq!(tunnel_config.host.as_str(), "^google\\.com$");

            // Validate the port configuration
            assert_eq!(tunnel_config.port.len(), 1);
            assert_eq!(*tunnel_config.port[0].start(), 443);
            assert_eq!(*tunnel_config.port[0].end(), 443);

            // Validate that CIDR list is empty (since we're using hostname)
            assert!(tunnel_config.cidr.is_empty());
        } else {
            panic!("Expected Tunnel configuration");
        }

        Ok(())
    }

    #[test]
    fn test_restriction_rule_with_ip_restriction() -> anyhow::Result<()> {
        // Test setup with empty path prefixes and specific host restriction
        let path_prefixes: Vec<String> = vec![];
        let restrict_to = vec![("127.0.0.1".to_string(), 443)];

        let rules = RestrictionsRules::from_path_prefix(&path_prefixes, &restrict_to)?;

        // Validate the rules structure
        assert_eq!(rules.restrictions.len(), 1);

        // Get the first restriction
        let restriction = &rules.restrictions[0];

        // Validate the restriction name
        assert_eq!(restriction.name, "Default Policy");

        // Validate that there's exactly one allow rule
        assert_eq!(restriction.allow.len(), 1);
        assert_eq!(restriction.r#match.len(), 1);

        // Check the tunnel configuration
        if let AllowConfig::Tunnel(tunnel_config) = &restriction.allow[0] {
            // Validate the host regex pattern
            assert_eq!(tunnel_config.host.as_str(), "^$");

            // Validate the port configuration
            assert_eq!(tunnel_config.port.len(), 1);
            assert_eq!(*tunnel_config.port[0].start(), 443);
            assert_eq!(*tunnel_config.port[0].end(), 443);

            // Validate that CIDR is correct
            assert_eq!(tunnel_config.cidr.len(), 1);
            assert_eq!(tunnel_config.cidr[0], IpNet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)?);
        } else {
            panic!("Expected Tunnel configuration");
        }

        Ok(())
    }

    #[test]
    fn test_restriction_rule_with_path_prefix() -> anyhow::Result<()> {
        // Test setup with path prefix and host restriction
        let path_prefixes = vec!["/test/path".to_string()];
        let restrict_to = vec![];

        let rules = RestrictionsRules::from_path_prefix(&path_prefixes, &restrict_to)?;

        // Validate the rules structure
        assert_eq!(rules.restrictions.len(), 1);

        // Get the first restriction
        let restriction = &rules.restrictions[0];

        // Validate the restriction name
        assert_eq!(restriction.name, "Allow path prefix /test/path");

        if let MatchConfig::PathPrefix(reg) = &restriction.r#match[0] {
            // Validate the host regex pattern
            assert_eq!(reg.as_str(), "^/test/path$");
        } else {
            panic!("Expected Match configuration");
        }

        // Under Priority 3 (deny by default), without an explicit destination restriction,
        // allow rules must be empty so that no tunnel can be established.
        assert!(restriction.allow.is_empty());

        Ok(())
    }

    #[test]
    fn test_empty_restrictions_rules_deny_by_default() -> anyhow::Result<()> {
        let rules = RestrictionsRules::from_path_prefix(&[], &[])?;
        assert_eq!(rules.restrictions.len(), 1);
        let restriction = &rules.restrictions[0];
        assert_eq!(restriction.name, "Default Policy");
        assert!(restriction.allow.is_empty());
        Ok(())
    }
}
