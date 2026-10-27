use crate::config::ClientIdentityField;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::X509Certificate;

/// Find a leaf certificate in a vector of certificates. It is assumed only a single leaf certificate
/// is present in the vector. The other certificates should be (intermediate) CA certificates.
pub fn find_leaf_certificate<'a>(tls_certificates: &'a [CertificateDer<'static>]) -> Option<X509Certificate<'a>> {
    for tls_certificate in tls_certificates {
        if let Ok((_, tls_certificate_x509)) = parse_x509_certificate(tls_certificate)
            && !tls_certificate_x509.is_ca()
        {
            return Some(tls_certificate_x509);
        }
    }
    None
}

/// Returns the common name (CN) as specified in the supplied certificate.
pub fn cn_from_certificate(tls_certificate_x509: &X509Certificate) -> Option<String> {
    tls_certificate_x509
        .tbs_certificate
        .subject
        .iter_common_name()
        .flat_map(|cn| cn.as_str().ok())
        .next()
        .map(|cn| cn.to_string())
}

/// Returns the Subject Alternative Name URI (SAN URI / SPIFFE ID) from the certificate.
/// Enforces that exactly one SAN URI is present and non-empty.
pub fn san_uri_from_certificate(tls_certificate_x509: &X509Certificate) -> anyhow::Result<String> {
    let san_ext = match tls_certificate_x509.tbs_certificate.subject_alternative_name() {
        Ok(Some(ext)) => ext,
        Ok(None) => anyhow::bail!("mTLS client certificate has no Subject Alternative Name extension"),
        Err(err) => anyhow::bail!("failed to parse Subject Alternative Name extension: {err}"),
    };

    let mut uris = san_ext
        .value
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::URI(uri) => Some(uri.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();

    anyhow::ensure!(
        uris.len() == 1,
        "mTLS client certificate must contain exactly one SAN URI, found {}",
        uris.len()
    );

    let uri = uris.pop().unwrap();
    anyhow::ensure!(!uri.is_empty(), "mTLS client certificate has empty SAN URI");
    Ok(uri)
}

/// Returns the Subject Alternative Name DNS Name (SAN DNS) from the certificate.
/// Enforces that exactly one SAN DNS entry is present and non-empty.
pub fn san_dns_from_certificate(tls_certificate_x509: &X509Certificate) -> anyhow::Result<String> {
    let san_ext = match tls_certificate_x509.tbs_certificate.subject_alternative_name() {
        Ok(Some(ext)) => ext,
        Ok(None) => anyhow::bail!("mTLS client certificate has no Subject Alternative Name extension"),
        Err(err) => anyhow::bail!("failed to parse Subject Alternative Name extension: {err}"),
    };

    let mut dns_names = san_ext
        .value
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();

    anyhow::ensure!(
        dns_names.len() == 1,
        "mTLS client certificate must contain exactly one SAN DNS name, found {}",
        dns_names.len()
    );

    let dns = dns_names.pop().unwrap();
    anyhow::ensure!(!dns.is_empty(), "mTLS client certificate has empty SAN DNS name");
    Ok(dns)
}

/// Extracts verified client identity from the certificate according to the specified field selector.
pub fn identity_from_certificate(
    tls_certificate_x509: &X509Certificate,
    field: ClientIdentityField,
) -> anyhow::Result<String> {
    match field {
        ClientIdentityField::Cn => {
            let count = tls_certificate_x509.subject().iter_common_name().count();
            anyhow::ensure!(
                count == 1,
                "mTLS client certificate must contain exactly one Common Name, found {count}"
            );
            cn_from_certificate(tls_certificate_x509)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| anyhow::anyhow!("mTLS client certificate has no usable Common Name"))
        }
        ClientIdentityField::SanUri => san_uri_from_certificate(tls_certificate_x509),
        ClientIdentityField::SanDns => san_dns_from_certificate(tls_certificate_x509),
    }
}

/// The mTLS restriction scheme binds each verified client certificate to one path prefix.
/// A trusted chain without that identity must not fall back to unrestricted path selection.
pub fn client_path_from_certificate(
    certificates: Option<&[CertificateDer<'static>]>,
    required: bool,
    field: ClientIdentityField,
) -> anyhow::Result<Option<String>> {
    if !required {
        return Ok(None);
    }
    let leaf = certificates
        .and_then(find_leaf_certificate)
        .ok_or_else(|| anyhow::anyhow!("mTLS client certificate has no usable leaf identity"))?;
    let identity = identity_from_certificate(&leaf, field)?;
    Ok(Some(identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    #[test]
    fn test_client_path_from_certificate_not_required() {
        let result = client_path_from_certificate(None, false, ClientIdentityField::Cn);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_client_path_from_certificate_no_leaf() {
        let result = client_path_from_certificate(None, true, ClientIdentityField::Cn);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mTLS client certificate has no usable leaf identity")
        );
    }

    #[test]
    fn test_client_identity_field_cn() {
        let key_pair = KeyPair::generate().unwrap();

        // 1. Valid single CN
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "device-cn-01".to_string());
        let cert = params.self_signed(&key_pair).unwrap().der().clone();
        let certs = vec![cert];

        let id = client_path_from_certificate(Some(&certs), true, ClientIdentityField::Cn).unwrap();
        assert_eq!(id, Some("device-cn-01".to_string()));

        // 2. Missing CN
        let mut params_no_cn = CertificateParams::new(vec![]).unwrap();
        params_no_cn.distinguished_name = rcgen::DistinguishedName::new();
        params_no_cn
            .distinguished_name
            .push(DnType::OrganizationName, "ACME Corp".to_string());
        let cert_no_cn = params_no_cn.self_signed(&key_pair).unwrap().der().clone();
        let certs_no_cn = vec![cert_no_cn];

        let err = client_path_from_certificate(Some(&certs_no_cn), true, ClientIdentityField::Cn).unwrap_err();
        assert!(
            err.to_string()
                .contains("mTLS client certificate must contain exactly one Common Name")
        );

        // 3. Empty CN
        let mut params_empty = CertificateParams::new(vec![]).unwrap();
        params_empty.distinguished_name = rcgen::DistinguishedName::new();
        params_empty.distinguished_name.push(DnType::CommonName, "".to_string());
        let cert_empty = params_empty.self_signed(&key_pair).unwrap().der().clone();
        let certs_empty = vec![cert_empty];

        let err = client_path_from_certificate(Some(&certs_empty), true, ClientIdentityField::Cn).unwrap_err();
        assert!(
            err.to_string()
                .contains("mTLS client certificate has no usable Common Name")
        );
    }

    #[test]
    fn test_client_identity_field_san_uri() {
        let key_pair = KeyPair::generate().unwrap();

        // 1. Valid SPIFFE SAN URI
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .subject_alt_names
            .push(SanType::URI("spiffe://example.org/ns/prod/sa/device-1".try_into().unwrap()));
        let cert = params.self_signed(&key_pair).unwrap().der().clone();
        let certs = vec![cert];

        let id = client_path_from_certificate(Some(&certs), true, ClientIdentityField::SanUri).unwrap();
        assert_eq!(id, Some("spiffe://example.org/ns/prod/sa/device-1".to_string()));

        // 2. Missing SAN extension
        let mut params_no_san = CertificateParams::new(vec![]).unwrap();
        params_no_san.distinguished_name = rcgen::DistinguishedName::new();
        let cert_no_san = params_no_san.self_signed(&key_pair).unwrap().der().clone();
        let certs_no_san = vec![cert_no_san];

        let err = client_path_from_certificate(Some(&certs_no_san), true, ClientIdentityField::SanUri).unwrap_err();
        assert!(
            err.to_string()
                .contains("mTLS client certificate has no Subject Alternative Name extension")
        );

        // 3. Multiple SAN URIs
        let mut params_multi = CertificateParams::new(vec![]).unwrap();
        params_multi.distinguished_name = rcgen::DistinguishedName::new();
        params_multi
            .subject_alt_names
            .push(SanType::URI("spiffe://example.org/sa/1".try_into().unwrap()));
        params_multi
            .subject_alt_names
            .push(SanType::URI("spiffe://example.org/sa/2".try_into().unwrap()));
        let cert_multi = params_multi.self_signed(&key_pair).unwrap().der().clone();
        let certs_multi = vec![cert_multi];

        let err = client_path_from_certificate(Some(&certs_multi), true, ClientIdentityField::SanUri).unwrap_err();
        assert!(
            err.to_string()
                .contains("mTLS client certificate must contain exactly one SAN URI, found 2")
        );

        // 4. SAN extension present but only contains DNS (no URI)
        let mut params_dns_only = CertificateParams::new(vec![]).unwrap();
        params_dns_only.distinguished_name = rcgen::DistinguishedName::new();
        params_dns_only
            .subject_alt_names
            .push(SanType::DnsName("host.corp.internal".try_into().unwrap()));
        let cert_dns_only = params_dns_only.self_signed(&key_pair).unwrap().der().clone();
        let certs_dns_only = vec![cert_dns_only];

        let err = client_path_from_certificate(Some(&certs_dns_only), true, ClientIdentityField::SanUri).unwrap_err();
        assert!(
            err.to_string()
                .contains("mTLS client certificate must contain exactly one SAN URI, found 0")
        );
    }

    #[test]
    fn test_client_identity_field_san_dns() {
        let key_pair = KeyPair::generate().unwrap();

        // 1. Valid SAN DNS
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .subject_alt_names
            .push(SanType::DnsName("device-01.corp.internal".try_into().unwrap()));
        let cert = params.self_signed(&key_pair).unwrap().der().clone();
        let certs = vec![cert];

        let id = client_path_from_certificate(Some(&certs), true, ClientIdentityField::SanDns).unwrap();
        assert_eq!(id, Some("device-01.corp.internal".to_string()));

        // 2. Missing SAN extension
        let mut params_no_san = CertificateParams::new(vec![]).unwrap();
        params_no_san.distinguished_name = rcgen::DistinguishedName::new();
        let cert_no_san = params_no_san.self_signed(&key_pair).unwrap().der().clone();
        let certs_no_san = vec![cert_no_san];

        let err = client_path_from_certificate(Some(&certs_no_san), true, ClientIdentityField::SanDns).unwrap_err();
        assert!(
            err.to_string()
                .contains("mTLS client certificate has no Subject Alternative Name extension")
        );

        // 3. Multiple SAN DNS
        let mut params_multi = CertificateParams::new(vec![]).unwrap();
        params_multi.distinguished_name = rcgen::DistinguishedName::new();
        params_multi
            .subject_alt_names
            .push(SanType::DnsName("d1.corp.internal".try_into().unwrap()));
        params_multi
            .subject_alt_names
            .push(SanType::DnsName("d2.corp.internal".try_into().unwrap()));
        let cert_multi = params_multi.self_signed(&key_pair).unwrap().der().clone();
        let certs_multi = vec![cert_multi];

        let err = client_path_from_certificate(Some(&certs_multi), true, ClientIdentityField::SanDns).unwrap_err();
        assert!(
            err.to_string()
                .contains("mTLS client certificate must contain exactly one SAN DNS name, found 2")
        );

        // 4. SAN extension present but only contains URI (no DNS)
        let mut params_uri_only = CertificateParams::new(vec![]).unwrap();
        params_uri_only.distinguished_name = rcgen::DistinguishedName::new();
        params_uri_only
            .subject_alt_names
            .push(SanType::URI("spiffe://example.org/sa/dev".try_into().unwrap()));
        let cert_uri_only = params_uri_only.self_signed(&key_pair).unwrap().der().clone();
        let certs_uri_only = vec![cert_uri_only];

        let err = client_path_from_certificate(Some(&certs_uri_only), true, ClientIdentityField::SanDns).unwrap_err();
        assert!(
            err.to_string()
                .contains("mTLS client certificate must contain exactly one SAN DNS name, found 0")
        );
    }
}
