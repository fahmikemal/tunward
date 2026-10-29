# Security policy

## Scope and versions

The current workspace version is `0.1.0-beta`. This source tree uses tunnel
protocol v2 and requires compatible client/server peers. Record both binaries'
versions and commits in a report; a matching package version alone does not
identify a particular working tree or establish wire compatibility.

This beta does not document an LTS maintenance window or an enterprise
certification. Report security problems affecting the current source or a
published release, identifying the exact affected artifact.

## Private vulnerability reporting

Send reports to **fahmi@kemal.id**, the contact listed in the package metadata.
If GitHub private vulnerability reporting is enabled for the repository, that
channel can also be used. Do not place an undisclosed vulnerability, customer
data, or credentials in a public issue.

Include:

- Affected client/server versions, commits or binary hashes, OS, and transport.
- The trust boundary involved: TLS identity, mTLS CN/path, restrictions, proxy
  credentials, management API, or reverse-listener allocation.
- A minimal local reproduction using synthetic targets and disposable identities.
- Expected/observed behavior, impact, and relevant sanitized logs.
- Any suspected fix and how it was tested.

Use networks/devices you own or are authorized to test. Coordinate disclosure
with maintainers; this document does not promise a fixed response or patch SLA.

## Current trust boundaries

Server certificate verification is enabled by default in the CLI. Disabling it
removes server authentication. Use a server certificate whose SANs match the
domain/IP and configure the client trust store. Cleartext `ws://` and
`http://` provide no transport confidentiality.

With `--tls-client-ca-certs`, a client must authenticate with a certificate
from a trusted issuer. The application then requires exactly one nonempty,
readable client CN and binds it to the path prefix on WSS, HTTP/2, and
WebTransport. A missing/ambiguous CN is rejected. Destination and reverse-bind
rules still need explicit configuration. A destination rule whose `cidr`
constrains addresses confines domain destinations to their resolved addresses
inside it, and those checked addresses are the ones dialed.

The v2 routing envelope is unsigned routing metadata. It is not an
authentication token. `--client-id`, `--device-id`, and their headers are
caller-controlled observation labels, not verified device identities. A path
secret alone does not establish a complete authorization policy.

A fixed reverse tunnel (`-R tcp://`, `udp://`, or `unix://`) connects only to
the target configured on the client and ignores any destination the server names
for it. A reverse SOCKS5 or HTTP proxy takes each destination from the server
side by design, so whoever controls the server can reach the client's network
through it; expose one only to a server you trust that far.

`X-Forwarded-For` is caller-controlled. The server ignores it unless the
connection's peer is a configured `--trusted-proxy`, and then takes the
rightmost entry that is not a trusted proxy as the client address recorded in
logs and fleet records and sent to targets in PROXY protocol headers. Trusting
`0.0.0.0/0` or `::/0` lets every client choose that address; the server warns
about it at startup.

The management API accepts loopback binds only and has no built-in API
authentication. Local processes able to reach it can read its observation data.
Remote exposure requires an authenticated TLS gateway and appropriate network
policy. A healthy API response does not prove tunnel or device health.

## Known implementation limits

Optional [device quotas](docs/DEVICE_QUOTAS.md) enforce session/tunnel admission,
attempt rate, and directional payload shaping against verified mTLS CNs. They
are disabled by default and scoped to one Server instance, with no persistent
usage or cross-replica coordination. Caller labels cannot select a quota account.
Quota-enabled retained reverse resources remain charged and their reuse is
identity-scoped. Quotas do not perform enrollment or grant tenant roles. Fleet connection/tunnel accounting is shared across all
transports; caller labels remain unverified and can group unrelated devices.
The optional [SQLite inventory](docs/FLEET_INVENTORY.md) stores observed verified
CNs independently of labels. It is not enrollment or an access-control source.
Protect database/state directories and backups; they contain device identities
and certificate metadata. Inventory-enabled new connections fail when their
observations cannot be committed. Existing forwarding is not terminated by a
storage failure. API access remains loopback-only without built-in authentication.

Optional [tenant authorization](docs/TENANT_ISOLATION.md) requires verified
mTLS membership, explicit tunnel roles, tenant-scoped named restrictions, and
reserved reverse endpoints. Reverse listener reuse is scoped to Server instance
and verified device even when tenant policy is disabled. Tenant files load at
startup; urgent termination uses live revocation. Tenant mode blocks direct
forwarding to the management port, but does not create management API RBAC,
OS/network isolation, or distributed enforcement. Protect policy files and use
separate host/process/network boundaries where required.

The optional [live revocation policy](docs/DEVICE_REVOCATION.md) denies verified
device CNs or leaf-certificate SHA-256 fingerprints and cancels their sessions,
forwarding, and reverse resources. It requires end-to-end mTLS and fails closed
on an unreadable or invalid policy. Cancellation remains sticky for existing
sessions even if a later policy restores access. Protect the file and its parent
directory: replacing this policy is an access-control operation.

The Rustls trust verifier has no configurable X.509 CRL/OCSP input. The local
denylist is checked after TLS authentication, before application processing;
it does not prevent TLS handshake resource use. Replicas need their own policy
delivery. CA reload alone is not active-session revocation or a complete PKI
lifecycle. Bytes already delivered cannot be recalled.

Proxy handler/queue limits, QUIC stream credit, and process resource controls
have narrower scopes than device quotas. TLS handshakes are bounded by
`--tls-handshake-timeout` and `--max-pending-tls-handshakes`, on the TCP listener
and separately on the WebTransport listener, where a connection stays pending
until it sends its session request. Peers that never authenticate therefore
cannot exhaust descriptors or memory, but while a handshake flood lasts it can
still delay new sessions. Tunward deliberately has no per-address limit: devices
behind carrier-grade NAT share addresses and reconnect together after an outage.
Rate-limit new connections per source in the network instead, for example with
nftables `ct count`/`meter` rules, a load balancer, or a DDoS-protection service,
covering both the TCP port and, for WebTransport, the UDP port. Local tests, successful authentication,
and container execution do not establish production capacity or certification.
See [qualification](docs/STAGING_QUALIFICATION.md) for coverage and open limits.

## Keys and public distribution

Each operator must own its deployment CA/keys. The
[development generator](scripts/generate_mtls.py) creates a new local bundle and
refuses overwrite; it is not a production certificate lifecycle service.

The CA certificate is public trust material. CA signing keys and server/device
private keys must not be published or embedded in deployment images. The CA key
belongs with the issuer; distribute only the identity and trust files each
participant needs. Use the [mTLS guide](docs/using_mtls.md) for placement.

Generated `certs/mTLS` material is excluded from Git and Docker build contexts.
This does not erase old commits, downloaded copies, or previously built layers.
Treat any key that was public as exposed: replace it wherever deployed.
The advertised branch history was rewritten on 2026-10-21; old clones must not
reintroduce it. The [publication guide](docs/PUBLICATION.md) records the known key
findings, cutover, and remaining host/copy cleanup. A branch rewrite does not
revoke keys or prove that hosted caches have been erased.
Use [deployment candidate validation](docs/DEPLOYMENT.md) before activation.

Review evidence before sharing it. Logs may contain addresses, device labels,
path prefixes, or custom headers even where specific credential structures are
redacted. Never attach private PEMs, proxy passwords, Authorization values,
TLS key logs, or an unreviewed environment dump.
