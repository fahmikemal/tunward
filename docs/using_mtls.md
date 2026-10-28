# mTLS and certificate ownership

This guide describes the current CN-to-path authorization scheme and the
development generator. The production boundary is explicit: the generator
creates unencrypted local keys and one example device; it does not manage device
enrollment, renewal, revocation, hardware key storage, or fleet quotas.

## Generate a local bundle

From the repository root, install Python 3 and OpenSSL, then run:

~~~sh
python3 scripts/generate_mtls.py
~~~

The default output is `certs/mTLS/generated/`. The script refuses to overwrite
an existing directory. Choose a new `--output` path for an independent bundle;
rerunning into a different directory creates a different CA, not a renewal.

| File relative to the output directory | Purpose |
| --- | --- |
| `certs/ca.cert.pem` | Public CA certificate used as a trust anchor |
| `private/ca.key.pem` | CA signing key; keep with the issuer |
| `certs/tunward-server.cert.pem` | Server certificate with DNS/IP SANs |
| `private/tunward-server.pem` | Server private key |
| `certs/tunward-client-1.cert.pem` | Example client certificate |
| `private/tunward-client-1.pem` | Example client's private key |
| `csr/`, `newcerts/`, `index.txt*`, `serial*`, `crlnumber` | Local CA issuance state |
| `openssl.cnf` | Copy of the template containing this bundle's SAN configuration |

The development CA uses RSA-4096 and lasts 3650 days. Server/client keys use
RSA-3072 and their certificates last 365 days. On POSIX systems, generated
directories and files are restricted by the process umask; private key files
have owner-only permissions. Windows deployments need equivalent filesystem ACLs.

Defaults are server SANs `localhost`, `127.0.0.1`, and `::1`, with client CN
`tunward_client_1`. To generate another development bundle:

~~~sh
python3 scripts/generate_mtls.py --output certs/mTLS/development-device-001 \
  --dns tunnel.example.test --ip 192.0.2.10 --client-id device-001
~~~

Replace the example names with addresses under your control. Repeat `--dns`
and `--ip` for more SANs. Explicit SAN arguments replace the localhost defaults.
DNS inputs must be hostnames, not URLs, ports, or wildcard expressions. Client
identities accept 1..64 letters/digits with dots, underscores, or hyphens.

The generator verifies key matches, chain validity, server SANs, and
`serverAuth`/`clientAuth` purposes before copying the bundle to the output.
It does not prove that a firewall, DNS record, application restriction, or
certificate renewal process is configured correctly.

## Connect using the default bundle

See [the README quickstart](../README.md#quickstart-verified-local-mtls) for a
complete three-process example. From the repository root, assuming a target
service at server-side `127.0.0.1:3000`:

~~~sh
tunward server \
  --tls-certificate certs/mTLS/generated/certs/tunward-server.cert.pem \
  --tls-private-key certs/mTLS/generated/private/tunward-server.pem \
  --tls-client-ca-certs certs/mTLS/generated/certs/ca.cert.pem \
  --restrict-to 127.0.0.1:3000 wss://127.0.0.1:8443
~~~

In another terminal, on Linux/POSIX:

~~~sh
SSL_CERT_FILE="$PWD/certs/mTLS/generated/certs/ca.cert.pem" SSL_CERT_DIR= \
tunward client --tls-verify-certificate \
  --tls-certificate certs/mTLS/generated/certs/tunward-client-1.cert.pem \
  --tls-private-key certs/mTLS/generated/private/tunward-client-1.pem \
  -P tunward_client_1 \
  -L tcp://127.0.0.1:8088:127.0.0.1:3000 wss://127.0.0.1:8443
~~~

Server verification defaults to true. Configuring the server's
`--tls-client-ca-certs` does not automatically install that CA into the client's
trust store. Configure trust separately on each participating platform.
`--tls-verify-certificate=false` is only an explicit opt-out for isolated
development; it removes server authentication.

For HTTP/2 use `https://` on the client with the same TLS server. For
WebTransport enable `--enable-webtransport` on a `wss://` server, or use
`wts://` for both peers. Make UDP reachable on that port as well as TCP.

## Application identity and path binding

With mTLS enabled, Tunward binds verified client certificate identities to the
requested HTTP upgrade path prefix across WSS, HTTP/2, and WebTransport.

By default, the server and client inspect the certificate Common Name (`--tls-client-identity-field cn`).
For modern PKI environments (e.g. SPIFFE, service meshes, or enterprise MDM profiles where CN is deprecated),
operators can configure `--tls-client-identity-field`:

- `--tls-client-identity-field cn` (Default): Requires exactly one nonempty Common Name on the verified leaf certificate.
- `--tls-client-identity-field san-uri`: Requires exactly one Subject Alternative Name URI (e.g., SPIFFE ID `spiffe://example.org/ns/prod/sa/device-01` or URN `urn:uuid:...`).
- `--tls-client-identity-field san-dns`: Requires exactly one Subject Alternative Name DNS Name (e.g., `device-01.corp.internal`).

The client automatically derives its HTTP upgrade path prefix from the verified leaf certificate using the configured `--tls-client-identity-field`. Explicit `-P` must agree with that identity; the implementation treats the default prefix value `v1` as the signal to auto-derive identity from the leaf certificate.

This is application authorization, separate from TLS server name validation.
Server DNS/IP verification uses SANs. A `--client-id` or `--device-id` value
is a caller-controlled registry label and cannot grant access or establish
device ownership.

## Destination and reverse-listener policy

`--restrict-to` builds forward-destination restrictions. A supplied
`--restrict-config` file replaces those CLI-generated rules; include all
required forward and reverse permissions in that YAML.

For the default development identity, this example allows one forward target
and loopback reverse TCP binds on ports 0 and 9000. It is not a tenant or quota
policy. Save it in an operator-owned configuration file:

~~~yaml
restrictions:
  - name: Local development client
    match:
      - !PathPrefix '^tunward_client_1$'
    allow:
      - !Tunnel
        protocol: [Tcp]
        host: '^127[.]0[.]0[.]1$'
        port: ["3000"]
        cidr: [127.0.0.1/32]
      - !ReverseTunnel
        protocol: [Tcp]
        port: ["0", "9000"]
        cidr: [127.0.0.1/32]
~~~

A `!Tunnel` rule matches a literal IP destination against `cidr`. A domain
destination must match `host`, and when `cidr` constrains addresses (anything
except an empty list or one covering both `0.0.0.0/0` and `::/0`), the server
also resolves the domain and allows it only at its resolved addresses inside
`cidr`. It then connects to those checked addresses without resolving again, so
a DNS answer that changes in between cannot redirect the tunnel. Omitting `host`
keeps the default `^.*$`: a rule listing only `cidr` admits any name that
resolves into it, and nothing else. `cidr: []` authorizes names by `host` alone,
as `--restrict-to HOST:PORT` does. IPv4-mapped IPv6 addresses such as
`::ffff:10.0.0.1` are matched as their IPv4 address, for forward and reverse
rules. A domain that cannot be resolved does not match a constraining rule. With
the server's `--http-proxy`, a checked domain is sent to the proxy as its first
allowed address.

Earlier builds allowed a domain matching `host` whatever it resolved to, even
when `cidr` excluded that address. If a rule relied on that, list the
destination's addresses in `cidr`, or authorize the name explicitly with a
`host` pattern and `cidr: []`.

Use `--restrict-config /path/to/your-restrictions.yaml` instead of
`--restrict-to` in the server example. Then a client can use
`-R tcp://127.0.0.1:0:127.0.0.1:3000` with its existing TLS options.
The reverse destination is reached from the client. Port zero requests an
OS-assigned listener; lifecycle and observation limits are described in the
[README](../README.md#fleet-observation-api).

For persistent observations keyed by verified device CN, enable the separate
[fleet inventory](FLEET_INVENTORY.md) with `--fleet-inventory FILE`. The database
records certificate observations; it does not enroll devices, authorize access,
or store their private keys. Keep CNs unique within the server's trusted-issuer
scope and stable during routine certificate/key renewal.

The repository's [restrictions.yaml](../restrictions.yaml) demonstrates the
schema and contains broad examples. Review each rule before adapting it; do not
assume it is a restrictive deployment policy. Forward rule fields include
protocol, port, host regex, and CIDR; reverse rules include protocol, bind CIDR,
ports/mappings, and Unix path regex. Device quotas use a separate
[quota configuration](DEVICE_QUOTAS.md), enabled with `--device-quota-config`;
they do not grant or replace destination access.

For several groups on one server, use [tenant authorization](TENANT_ISOLATION.md)
with `--tenant-config` and uniquely named restriction rules. It adds verified
CN membership, tunnel roles, and reserved reverse endpoint scope; client labels
cannot choose a tenant. Tenant mode allocates port-zero listeners from its own
reserved pools instead of the OS ephemeral range.

## Production ownership and renewal

Provision server certificates for the domain/IP devices actually use. The
server's public certificate may come from a public CA while device certificates
come from a private CA. These are independent trust relationships.

Keep the CA signing key outside tunnel servers and client devices. Deploy only:

- On the server: its own key/certificate and the trusted client CA bundle.
- On a device: its own key/certificate and the server trust anchor as needed.
- At the issuer: the CA key and issuance state, with an appropriate backup and
  access-control policy.

Generate a distinct device key and an identity mapped to its intended access
policy. Preserve that identity during ordinary key/certificate renewal. A CA
change requires an explicit overlap and trust-bundle migration; it is not
required for every binary deployment or certificate renewal.

Certificate/key/CA file reload paths exist, and invalid server replacements
retain the last usable configuration. Existing sessions can survive server
certificate rotation. Reloading does not establish revocation of active
sessions, automatic CN remapping, or a complete CA migration. Qualify your exact
file replacement layout, reconnect behavior, and trust updates before rollout.

The client verifier has no configurable X.509 CRL/OCSP input. Removing a CA
changes trust for subsequent handshakes after reload, not automatically the
authorization of every existing stream. Use the separate
[live revocation policy](DEVICE_REVOCATION.md) to block a leaf-certificate
fingerprint or verified device CN and terminate its active work. It requires
`--device-revocation-config FILE` and applies across the three TLS transports.
Session/tunnel, attempt-rate, and directional payload quotas can
be configured using the [verified CN quota guide](DEVICE_QUOTAS.md); the
development certificate generator does not configure them.

Use the [deployment lifecycle runbook](DEPLOYMENT.md) for certificate candidate
validation, renewal, issuer migration, canary rollout, and rollback. The example
systemd service uses direct, service-readable TLS files and an acknowledged
managed reload command. Older units using `LoadCredential` must migrate or
restart to replace their start-time snapshots. See the runbook for permissions
and the distinction between new-handshake trust and active-session revocation.

## Git, images, and private key handling

Only `certs/mTLS/.gitignore`, `README.md`, and `openssl.cnf` belong in Git in
that directory. Generated material, including local backups and CA databases,
is ignored. The whole directory is excluded by the root `.dockerignore`.
Custom output directories need equivalent exclusions.

A CA certificate is public; a CA private key is secret. Never put server,
device, or CA private keys in a public repository, image layer, issue, or test
artifact. Keep runtime keys in operator-controlled mounts or a secret store.
A read-only runtime mount prevents container writes; it does not make a key
unreadable to the process that must use it.

The advertised branch history was rewritten on 2026-10-21 to remove the old
committed development keys. Old clones, hosted caches, or downloaded copies may
still contain them. Treat any published key as exposed and replace it anywhere
it was deployed. The [publication guide](PUBLICATION.md) records the cutover,
fresh-clone instructions, and remaining host/copy cleanup.

## Verification and references

~~~sh
python3 scripts/qualify_identity.py --output target/qualification/identity-review
~~~

This checks application identity/path/destination behavior with disposable
certificates. Quotas are deliberately disabled in that identity suite, so its
quota row is `not_run`, not a quota pass. Verify configured enforcement separately:

~~~sh
python3 scripts/qualify_quotas.py --output target/qualification/quota-review
~~~

- [OpenSSL requests](https://docs.openssl.org/master/man1/openssl-req/)
- [OpenSSL CA signing](https://docs.openssl.org/master/man1/openssl-ca/)
- [OpenSSL certificate verification](https://docs.openssl.org/master/man1/openssl-verification-options/)
- [Rustls client trust and CRLs](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)
- [Docker context exclusions](https://docs.docker.com/build/concepts/context/#dockerignore-files)

