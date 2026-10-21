# Live device and certificate revocation

The optional local revocation policy denies verified device identities or
individual leaf certificates and terminates their existing work. It requires
end-to-end mTLS at tunward and is disabled unless configured.

This is an application access denylist. It does not ingest signed X.509 CRLs,
query OCSP, run a certificate authority, or synchronize replicas. TLS trust and
signature verification still happen before this policy is consulted.

## Enable

Start with [the example](../device-revocations.example.yaml):

~~~yaml
version: 1
blocked_devices: []
blocked_cert_sha256: []
~~~

Add the policy to the [mTLS server recipe](using_mtls.md):

~~~sh
tunward server \
  --tls-certificate certs/mTLS/generated/certs/tunward-server.cert.pem \
  --tls-private-key certs/mTLS/generated/private/tunward-server.pem \
  --tls-client-ca-certs certs/mTLS/generated/certs/ca.cert.pem \
  --device-revocation-config device-revocations.example.yaml \
  --restrict-to 127.0.0.1:3000 wss://127.0.0.1:8443
~~~

`TUNWARD_DEVICE_REVOCATION_CONFIG` is the corresponding environment variable.
Embedded users set `ServerConfig.device_revocation_config` to a policy path;
`None` preserves the disabled behavior. Invalid startup configuration or missing
mTLS fails before listening. Quotas can be enabled alongside revocation but are
not required for it.

## Choose the scope

`blocked_devices` contains exact, case-sensitive verified client certificate
CNs. For example, blocking `device-001` blocks that device's old and renewed
certificates if both preserve that CN. As with quotas, device CNs must be unique
within the server's trusted-issuer scope. Two trusted issuers assigning the same
CN create one policy identity.

`blocked_cert_sha256` contains the SHA-256 digest of the entire DER-encoded leaf
certificate. It accepts 64 hex digits, with optional colons and either case.
Obtain the value from the certificate file, without access to its private key:

~~~sh
openssl x509 \
  -in certs/mTLS/generated/certs/tunward-client-1.cert.pem \
  -noout -fingerprint -sha256
~~~

Copy only the hexadecimal value after `=` into a quoted YAML list entry.
A different certificate with the same CN has a different fingerprint and
remains usable unless its CN is also blocked. Fingerprint denial is appropriate
for retiring an old certificate after renewal; CN denial disables the device
across all its keys.

Client labels, forwarded headers, source addresses, and claimed URL paths cannot
select the identity used here. A policy entry grants no access: mTLS identity,
path agreement, and destination restrictions still apply. Denying an unknown
CN/fingerprint is valid and takes effect if that identity later connects.

## Publish and recover

The server polls the configured path every second, comparing file contents.
Publish a complete replacement in the same directory, on the same filesystem.
For example, after preparing a valid `device-revocations.next.yaml`:

~~~sh
mv -- device-revocations.next.yaml device-revocations.example.yaml
~~~

Protect the policy and parent directory with operator-only write access. This
file authorizes access restoration as well as denial. Keep it outside writable
application upload/cache directories. Each server/replica must receive the
intended policy; a local update does not distribute it to other hosts.

The next successful reload cancels every registered session matching either
list and rejects later admissions. Normally this begins on the next one-second
poll; executor scheduling, filesystem latency, and transport delivery prevent a
hard one-second end-to-end guarantee. Monitor the `Applied device revocation
policy` event and its `healthy`/`cancelled_sessions` fields.

An unreadable, missing, oversized, or invalid policy fails closed: all registered
authenticated sessions are cancelled and new admissions are denied. The last
policy is not treated as permission to continue while the configured file is
unavailable. A later valid file restores admission under that file's policy.
Cancellation is sticky for old sessions, including work that had not started
waiting yet; restoring access permits new sessions without reviving old work.

Unknown fields, unsupported versions, empty CNs, invalid fingerprints, more than
10000 entries, and files larger than 1 MiB are rejected. Empty lists are valid
and impose no extra denial. Removal of a denial is an explicit access-restoring
operation. On restart the configured file is read again; there is no separate
in-memory revocation history or rollback protection for policy versions.

## Connections and retained resources

All three TLS transports use the same manager within one Server instance:

| Work | Revocation behavior |
| --- | --- |
| Idle authenticated TCP TLS connection | Drops the HTTP connection and socket |
| WSS upgrade and active forwarding | Cancels setup/upgrade and forwarding, including detached tasks |
| HTTP/2 streams | Drops the connection and cancels separately spawned forwarding |
| WebTransport session | Closes with code 403 and cancels pending/active streams |
| Pending destination/reverse setup | Cancels the setup future |
| Reverse listener | Drops its owning listener task and pending/queued resources |
| Bandwidth wait | Cancels the waiter and releases its resource leases |

Reverse cache keys include the verified mTLS device CN and Server-instance ID
independently of quota, revocation, or tenant policy configuration. A retained listener follows its creating session's
revocation guard. Denying that creator's certificate closes the listener;
another certificate sharing the CN may need to reconnect/recreate its reverse
allocation. Ordinary idle cleanup and network-loss detection remain separate.

Resource leases release when the cancelled future is dropped. Already queued or
delivered bytes cannot be recalled; remote peers learn closure through their
transport. There is no global network kill switch or per-device fair scheduler.

Denied TCP sessions close after TLS authentication, before HTTP processing.
WebTransport session requests can receive HTTP 403. TLS handshakes still consume
resources, so retain normal handshake/network controls. Resumed sessions also
pass current application admission using the peer certificate identity supplied
by TLS; absence of the required verified identity/certificate fails closed.

## Verify and operate

~~~sh
cargo build --release --locked -p tunward-cli
python3 scripts/qualify_revocation.py --output target/qualification/revocation-review
~~~

Use a new output directory. The bounded Linux loopback runner covers fingerprint
versus CN denial across WSS/HTTP2/WebTransport, key rotation, unchanged caller
labels, idle TLS, reverse resources, policy failure/recovery, cancellation during
shaping, quota release, and observed TLS 1.2 resumption. Unit tests cover sticky
cancellation, late waiters, independent identities, invalid policy, and weak
session reclamation. Other TLS resumption modes, external certificate managers,
replica policy delivery, and production MDM workloads need deployment testing.

Integrate policy publishing with the organization's issuance/incident process.
Retain certificate fingerprints and stable device identities in that process,
audit policy changes, deliver them to every replica, and verify new connection
denial plus active closure. The [fleet API](FLEET_INVENTORY.md) separates caller
labels from a persistent inventory of observed verified identities. It does not
provide enrollment, complete certificate issuance history, or a revocation-control API.

## Documentation contracts

- [Rustls client certificate verification and CRLs](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)
- [Tokio watch current-value waits](https://docs.rs/tokio/latest/tokio/sync/watch/struct.Receiver.html#method.wait_for)
- [Tokio watch sticky value replacement](https://docs.rs/tokio/latest/tokio/sync/watch/struct.Sender.html#method.send_replace)
- [OpenSSL certificate fingerprint and digest options](https://docs.openssl.org/master/man1/openssl-x509/)
