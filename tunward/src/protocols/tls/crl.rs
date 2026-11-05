//! Certificate revocation lists for client certificate authentication (`--tls-client-crl`).
//!
//! The TLS verifier checks a client chain against these CRLs during the handshake. The same CRLs
//! are also indexed here by issuer and serial number, so that sessions authenticated before a CRL
//! listed their certificate can be found and closed when it is loaded.

use crate::config::ClientCrlScope;
use anyhow::{Context, anyhow, ensure};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tracing::{info, warn};
use x509_parser::certificate::X509Certificate;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::{parse_x509_certificate, parse_x509_crl};

/// A CRL file larger than this is refused rather than read: a private device CA's list is far
/// smaller, and every entry is also kept in memory.
const MAX_CRL_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Intermediate CA certificates followed from a client certificate towards its trust anchor.
const MAX_CHAIN_DEPTH: usize = 8;

/// The CRLs of one `--tls-client-crl` file.
pub struct ClientCrls {
    ders: Vec<CertificateRevocationListDer<'static>>,
    /// Revoked serial numbers, keyed by the DER-encoded name of the CA that issued them.
    revoked: HashMap<Box<[u8]>, HashSet<Box<[u8]>>>,
    /// The earliest nextUpdate of the CRLs: past it, at least one of them is out of date.
    next_update: Option<SystemTime>,
}

impl fmt::Debug for ClientCrls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCrls")
            .field("crls", &self.ders.len())
            .field("revoked", &self.revoked_count())
            .field("next_update", &self.next_update)
            .finish()
    }
}

impl ClientCrls {
    /// The CRLs, as given to the TLS verifier.
    pub fn ders(&self) -> &[CertificateRevocationListDer<'static>] {
        &self.ders
    }

    /// The earliest nextUpdate of the CRLs.
    pub fn next_update(&self) -> Option<SystemTime> {
        self.next_update
    }

    /// Whether a CRL is past its nextUpdate at `now`.
    pub fn expired_at(&self, now: SystemTime) -> bool {
        self.next_update.is_some_and(|next_update| now > next_update)
    }

    fn revoked_count(&self) -> usize {
        self.revoked.values().map(HashSet::len).sum()
    }

    /// Whether any certificate that `keys` were taken from is revoked by these CRLs.
    pub(crate) fn revokes(&self, keys: &RevocationKeys) -> bool {
        keys.0.iter().any(|(issuer, serial)| {
            self.revoked
                .get(issuer.as_ref())
                .is_some_and(|serials| serials.contains(serial.as_ref()))
        })
    }

    /// Read and check a CRL file for the client CAs `client_cas`.
    ///
    /// A CRL issued by one of those CAs must carry its valid signature. A CRL issued by an
    /// intermediate CA cannot be checked here; the TLS verifier checks it during the handshakes
    /// that use it.
    pub fn load(path: &Path, client_cas: &[CertificateDer<'_>], scope: ClientCrlScope) -> anyhow::Result<Self> {
        let crls = Self::parse(&read_crl_file(path)?, client_cas)
            .with_context(|| format!("Invalid client CRL file {}", path.display()))?;
        crls.report(path, client_cas, scope);
        Ok(crls)
    }

    pub(crate) fn parse(bytes: &[u8], client_cas: &[CertificateDer<'_>]) -> anyhow::Result<Self> {
        let ders = if bytes.trim_ascii_start().starts_with(b"-----BEGIN") {
            CertificateRevocationListDer::pem_slice_iter(bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| anyhow!("Cannot read PEM: {err}"))?
        } else {
            vec![CertificateRevocationListDer::from(bytes.to_vec())]
        };
        ensure!(!ders.is_empty(), "No X509 CRL found");

        // The TLS verifier refuses what it cannot use, such as delta and indirect CRLs: ask it now
        // rather than at the first handshake.
        let mut roots = RootCertStore::empty();
        for ca in client_cas {
            roots
                .add(ca.clone().into_owned())
                .context("Invalid client CA certificate")?;
        }
        WebPkiClientVerifier::builder(Arc::new(roots))
            .with_crls(ders.iter().cloned())
            .build()
            .map_err(|err| anyhow!("Unusable CRL: {err:?}"))?;

        let cas = client_cas
            .iter()
            .map(|ca| parse_x509_certificate(ca.as_ref()).map(|(_, ca)| ca))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| anyhow!("Invalid client CA certificate"))?;
        let mut revoked: HashMap<Box<[u8]>, HashSet<Box<[u8]>>> = HashMap::new();
        let mut next_update: Option<SystemTime> = None;
        for der in &ders {
            let (remaining, crl) = parse_x509_crl(der.as_ref()).map_err(|_| anyhow!("Invalid X509 CRL"))?;
            ensure!(remaining.is_empty(), "Trailing data after an X509 CRL");
            check_signature(&crl, &cas)?;
            let serials = revoked.entry(crl.issuer().as_raw().into()).or_default();
            serials.extend(crl.iter_revoked_certificates().map(|entry| entry.raw_serial().into()));
            if let Some(time) = crl.next_update() {
                let time = unix_time(time.timestamp());
                next_update = Some(next_update.map_or(time, |earliest| earliest.min(time)));
            }
        }
        Ok(Self {
            ders,
            revoked,
            next_update,
        })
    }

    /// Log what was loaded, and the client CAs whose certificates every handshake will refuse.
    fn report(&self, path: &Path, client_cas: &[CertificateDer<'_>], scope: ClientCrlScope) {
        let next_update = self.next_update.map_or_else(|| "none".into(), rfc3339);
        info!(
            "Loaded {} client CRL(s) from {}: {} revoked certificate(s), earliest next update {next_update}",
            self.ders.len(),
            path.display(),
            self.revoked_count(),
        );
        if self.expired_at(SystemTime::now()) {
            warn!(
                "A client CRL in {} is past its next update ({next_update}): without --tls-client-crl-allow-expired, \
                 handshakes that need it fail until a current CRL is loaded",
                path.display()
            );
        }
        for ca in client_cas {
            let Ok((_, ca)) = parse_x509_certificate(ca.as_ref()) else {
                continue;
            };
            if !self.revoked.contains_key(ca.subject().as_raw()) {
                let refused = match scope {
                    ClientCrlScope::Chain => "certificates chaining to it",
                    ClientCrlScope::EndEntity => "client certificates it issued directly",
                };
                warn!(
                    "{} has no CRL issued by client CA \"{}\": {refused} will be refused",
                    path.display(),
                    ca.subject()
                );
            }
        }
    }
}

fn read_crl_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("Cannot read client CRL file {}", path.display()))?;
    ensure!(metadata.is_file(), "Client CRL {} must be a regular file", path.display());
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("Cannot read client CRL file {}", path.display()))?
        .take(MAX_CRL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Cannot read client CRL file {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_CRL_FILE_BYTES,
        "Client CRL file {} exceeds 16 MiB",
        path.display()
    );
    Ok(bytes)
}

/// `time` as an RFC 3339 UTC timestamp, to the second.
pub(crate) fn rfc3339(time: SystemTime) -> String {
    let seconds = match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs() as i64,
        Err(before) => -(before.duration().as_secs() as i64),
    };
    match time::OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(time) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            time.year(),
            u8::from(time.month()),
            time.day(),
            time.hour(),
            time.minute(),
            time.second()
        ),
        Err(_) => format!("{seconds} seconds after the Unix epoch"),
    }
}

fn unix_time(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    }
}

/// A CRL issued by a configured client CA must be signed by it: a CRL from another CA that
/// happens to share its name would otherwise make every handshake it covers fail.
fn check_signature(crl: &CertificateRevocationList<'_>, cas: &[X509Certificate<'_>]) -> anyhow::Result<()> {
    let issuers = cas
        .iter()
        .filter(|ca| ca.subject().as_raw() == crl.issuer().as_raw())
        .collect::<Vec<_>>();
    if issuers.is_empty() {
        return Ok(());
    }
    ensure!(
        issuers.iter().any(|ca| verify_signature(crl, ca)),
        "The CRL issued by \"{}\" is not signed by the client CA of that name",
        crl.issuer()
    );
    Ok(())
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
fn verify_signature(crl: &CertificateRevocationList<'_>, ca: &X509Certificate<'_>) -> bool {
    crl.verify_signature(ca.public_key()).is_ok()
}

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
fn verify_signature(_crl: &CertificateRevocationList<'_>, _ca: &X509Certificate<'_>) -> bool {
    // Without a crypto backend there is no TLS either; the verifier checks signatures when it runs.
    true
}

/// The issuer name and serial number of each certificate of a client chain that a CRL check
/// covers, kept with a session so a CRL loaded later can be checked against it.
#[derive(Clone, Debug, Default)]
pub(crate) struct RevocationKeys(Box<[CertificateKey]>);

/// A DER-encoded issuer name and the raw serial number it issued.
type CertificateKey = (Box<[u8]>, Box<[u8]>);

impl RevocationKeys {
    /// `chain` is the client's certificate followed by the CA certificates it presented. With
    /// `ClientCrlScope::Chain`, the CA certificates are followed by name from the client
    /// certificate up to a self-issued one, which is where the TLS verifier stops checking.
    pub fn of(chain: &[CertificateDer<'_>], scope: ClientCrlScope) -> Self {
        let mut certificates = chain
            .iter()
            .filter_map(|der| parse_x509_certificate(der.as_ref()).ok().map(|(_, cert)| cert))
            .collect::<Vec<_>>();
        if certificates.is_empty() {
            return Self::default();
        }
        let leaf = certificates.remove(0);
        let mut keys = vec![key(&leaf)];
        if scope == ClientCrlScope::Chain {
            let mut issuer = leaf.tbs_certificate.issuer.as_raw();
            while keys.len() <= MAX_CHAIN_DEPTH {
                let Some(position) = certificates.iter().position(|cert| {
                    cert.subject().as_raw() == issuer && cert.issuer().as_raw() != cert.subject().as_raw()
                }) else {
                    break;
                };
                let ca = certificates.swap_remove(position);
                keys.push(key(&ca));
                issuer = ca.tbs_certificate.issuer.as_raw();
            }
        }
        Self(keys.into_boxed_slice())
    }
}

fn key(cert: &X509Certificate<'_>) -> CertificateKey {
    (cert.issuer().as_raw().into(), cert.raw_serial().into())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType, IsCa,
        KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber,
    };
    use time::OffsetDateTime;

    /// A CA that issues client certificates and CRLs, for tests.
    pub(crate) struct TestCa {
        pub issuer: CertifiedIssuer<'static, KeyPair>,
    }

    impl TestCa {
        pub fn new(name: &str) -> Self {
            Self::issued_by(name, None)
        }

        /// An intermediate CA with serial number `serial` when `parent` is given, else a
        /// self-signed one.
        pub fn issued_by(name: &str, parent: Option<(&TestCa, u64)>) -> Self {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name.push(DnType::CommonName, name);
            if let Some((_, serial)) = parent {
                params.serial_number = Some(SerialNumber::from(serial));
            }
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let key = KeyPair::generate().unwrap();
            let issuer = match parent {
                None => CertifiedIssuer::self_signed(params, key).unwrap(),
                Some((parent, _)) => CertifiedIssuer::signed_by(params, key, &*parent.issuer).unwrap(),
            };
            Self { issuer }
        }

        pub fn der(&self) -> CertificateDer<'static> {
            self.issuer.der().clone()
        }

        /// A client certificate for `name`, with serial number `serial`.
        pub fn client(&self, name: &str, serial: u64) -> CertificateDer<'static> {
            self.client_identity(name, serial).0
        }

        /// A client certificate for `name`, with serial number `serial`, and its private key.
        pub fn client_identity(
            &self,
            name: &str,
            serial: u64,
        ) -> (CertificateDer<'static>, tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>) {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name.push(DnType::CommonName, name);
            params.serial_number = Some(SerialNumber::from(serial));
            let key = KeyPair::generate().unwrap();
            let certificate = params.signed_by(&key, &*self.issuer).unwrap().der().clone();
            let key = tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
            (certificate, key.into())
        }

        /// A CRL revoking `serials`, whose next update is `valid_for` from now (negative: in the past).
        pub fn crl(&self, serials: &[u64], valid_for: time::Duration) -> CertificateRevocationListDer<'static> {
            let now = OffsetDateTime::now_utc();
            CertificateRevocationListParams {
                this_update: now - time::Duration::hours(1),
                next_update: now + valid_for,
                crl_number: SerialNumber::from(1u64),
                issuing_distribution_point: None,
                revoked_certs: serials
                    .iter()
                    .map(|serial| RevokedCertParams {
                        serial_number: SerialNumber::from(*serial),
                        revocation_time: now - time::Duration::minutes(30),
                        reason_code: None,
                        invalidity_date: None,
                    })
                    .collect(),
                key_identifier_method: KeyIdMethod::Sha256,
            }
            .signed_by(&*self.issuer)
            .unwrap()
            .der()
            .clone()
        }
    }

    pub(crate) fn pem(label: &str, der: &[u8]) -> String {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        let lines = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>();
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
    }

    fn day() -> time::Duration {
        time::Duration::days(1)
    }

    fn init() {
        crate::tunnel::ca_reloader::SystemCaReloader::init_crypto_provider();
    }

    #[test]
    fn pem_and_der_files_index_revoked_serials_by_issuer() {
        init();
        let (a, b) = (TestCa::new("CA A"), TestCa::new("CA B"));
        let pem_file = [
            pem("X509 CRL", &a.crl(&[7], day())),
            pem("X509 CRL", &b.crl(&[9], day())),
        ]
        .concat();
        let crls = ClientCrls::parse(pem_file.as_bytes(), &[a.der(), b.der()]).unwrap();
        assert_eq!(crls.ders().len(), 2);
        assert_eq!(crls.revoked_count(), 2);
        let revoked =
            |ca: &TestCa, serial| crls.revokes(&RevocationKeys::of(&[ca.client("d", serial)], ClientCrlScope::Chain));
        assert!(revoked(&a, 7));
        assert!(revoked(&b, 9));
        // A serial number belongs to the CA that issued it.
        assert!(!revoked(&a, 9));
        assert!(!revoked(&b, 7));

        let der = ClientCrls::parse(a.crl(&[7], day()).as_ref(), &[a.der()]).unwrap();
        assert_eq!(der.ders().len(), 1);
        assert!(der.revokes(&RevocationKeys::of(&[a.client("d", 7)], ClientCrlScope::Chain)));
    }

    #[test]
    fn a_file_without_a_usable_crl_is_refused() {
        init();
        let ca = TestCa::new("CA");
        let error = |bytes: &[u8]| format!("{:#}", ClientCrls::parse(bytes, &[ca.der()]).err().unwrap());
        // A certificate where a CRL is expected, as when the CA file is given by mistake.
        assert!(error(pem("CERTIFICATE", &ca.der()).as_bytes()).contains("No X509 CRL found"));
        assert!(error(b"not a CRL").contains("Unusable CRL"));
        let mut trailing = ca.crl(&[], day()).to_vec();
        trailing.push(0);
        assert!(error(&trailing).contains("Unusable CRL"));
    }

    #[test]
    fn a_crl_must_be_signed_by_the_client_ca_it_names() {
        init();
        let ca = TestCa::new("CA");
        // Another CA with the same name, as after a CA key was replaced.
        let impostor = TestCa::new("CA");
        let error = ClientCrls::parse(impostor.crl(&[1], day()).as_ref(), &[ca.der()]).unwrap_err();
        assert!(
            format!("{error:#}").contains("is not signed by the client CA of that name"),
            "{error:#}"
        );
        // A CRL from an intermediate CA is checked by the TLS verifier instead.
        let intermediate = TestCa::issued_by("Intermediate", Some((&ca, 77)));
        assert!(ClientCrls::parse(intermediate.crl(&[1], day()).as_ref(), &[ca.der()]).is_ok());
    }

    #[test]
    fn the_earliest_next_update_decides_expiry() {
        init();
        let (a, b) = (TestCa::new("CA A"), TestCa::new("CA B"));
        let bytes = [
            pem("X509 CRL", &a.crl(&[], day() * 7)),
            pem("X509 CRL", &b.crl(&[], -time::Duration::minutes(5))),
        ]
        .concat();
        let crls = ClientCrls::parse(bytes.as_bytes(), &[a.der(), b.der()]).unwrap();
        let now = SystemTime::now();
        assert!(crls.expired_at(now));
        assert!(crls.next_update().unwrap() < now);
        assert!(!crls.expired_at(now - Duration::from_secs(3600)));
    }

    #[test]
    fn the_chain_scope_follows_intermediates_up_to_the_root() {
        init();
        let root = TestCa::new("Root");
        let intermediate = TestCa::issued_by("Intermediate", Some((&root, 77)));
        let client = intermediate.client("device", 5);
        // The client also sends the root, and an unrelated CA certificate.
        let chain = [client, intermediate.der(), TestCa::new("Other").der(), root.der()];
        let intermediate_serial = parse_x509_certificate(intermediate.der().as_ref())
            .unwrap()
            .1
            .raw_serial()
            .to_vec();

        let chain_keys = RevocationKeys::of(&chain, ClientCrlScope::Chain);
        assert_eq!(
            chain_keys.0.len(),
            2,
            "the client and its intermediate, not the root or the unrelated CA"
        );
        assert_eq!(chain_keys.0[1].1.as_ref(), intermediate_serial.as_slice());
        assert_eq!(RevocationKeys::of(&chain, ClientCrlScope::EndEntity).0.len(), 1);

        let crls = ClientCrls {
            ders: Vec::new(),
            revoked: HashMap::from([(
                parse_x509_certificate(root.der().as_ref())
                    .unwrap()
                    .1
                    .subject()
                    .as_raw()
                    .into(),
                HashSet::from([Box::<[u8]>::from(intermediate_serial.as_slice())]),
            )]),
            next_update: None,
        };
        assert!(crls.revokes(&chain_keys));
        assert!(!crls.revokes(&RevocationKeys::of(&chain, ClientCrlScope::EndEntity)));
    }
}
