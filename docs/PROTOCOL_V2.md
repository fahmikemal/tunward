# Tunnel protocol v2

This document describes the wire behavior in the current source tree. The
workspace package version is `0.1.0-beta`; record a commit or binary hash as
well when comparing builds.

## Compatibility and migration

Protocol v2 is incompatible with older routing metadata and data framing. There
is no silent fallback. Upgrade both peers together, or run a separate v2 listener
while migrating clients. Rollback must restore a compatible client/server pair
and configuration.

WebSocket selects subprotocol `v2`. WebSocket and HTTP/2 clients require
`x-tunward-version: 2` in the server response. WebTransport checks that version
header in its HTTP/3 session CONNECT. Incompatible requests must not be treated
as a successful tunnel or proxy handshake.

A private-CA trust migration and a wire-protocol migration are different
operations. Plan both when a rollout changes identity and framing.

## Routing envelope

The routing value is `v2.` followed by unpadded base64url JSON, limited to
8192 bytes at the decoder. Its fields are:

| Field | Meaning |
| --- | --- |
| `v` | Required protocol revision, 2 |
| `id` | Request identifier, generated from a UUID by the client |
| `p` | Serialized destination/reverse protocol |
| `r` | Host or destination descriptor |
| `rp` | Port |

This is unsigned routing metadata, not a signed identity or an authentication
credential. Some Rust identifiers still contain `jwt` for source continuity;
their names do not imply JWT signature verification.

The server validates path, authorization rules, and destination/reverse
permissions before opening the requested target/listener. WebTransport carries
destination metadata per stream because one session multiplexes different
tunnels. Its length-prefixed preamble is also bounded to 8 KiB.

## Identity and authorization

Keep client-side server certificate verification enabled. Use a server
certificate whose SANs match the connection domain/IP and install the appropriate
trust anchor. Plain `ws://` and `http://` have no transport confidentiality.
The embedded server certificate is a development fallback, not an operator-owned
deployment identity.

Enabling `--tls-client-ca-certs` requires a trusted client certificate.
Application identity then requires exactly one nonempty, readable CN on the
verified client leaf certificate. The server binds that CN to the requested
path on WSS, HTTP/2, and WebTransport. Missing, multiple, or unusable CN values
are rejected instead of falling back to unrestricted path choice.

The client normally derives the path from its certificate CN; a manual `-P`
must agree. SAN-only client authorization is not implemented. Server SAN
verification and client CN-to-path authorization serve different purposes.

`--client-id`, `--device-id`, and their header values are caller-controlled
registry labels. They are not authentication credentials, quota keys, or proof
that two records belong to distinct physical devices.

Restriction rules authorize destinations. Optional
[device quotas](DEVICE_QUOTAS.md) separately enforce atomic session/tunnel
admission, attempt rate, and aggregate directional payload shaping by verified CN.
They are disabled by default, require mTLS, and share accounting across the
three TLS transports in one Server instance. Counts/token buckets are not
persistent and are not coordinated across replicas. This adds no tenant RBAC.
The optional [live revocation policy](DEVICE_REVOCATION.md) denies verified CNs
or leaf-certificate SHA-256 fingerprints and terminates their sessions and
retained resources. It requires mTLS and polls a local file. The TLS trust
verifier still has no configurable X.509 CRL/OCSP input or replica distribution.

See [mTLS configuration and ownership](using_mtls.md) and
[the security policy](../SECURITY.md).

## Ordered data and directional FIN

Each direction carries these records after transport setup:

| Field | Encoding |
| --- | --- |
| Type | One byte: 0 = DATA, 1 = FIN |
| Length | Four-byte unsigned big-endian integer |
| Payload | Exactly Length bytes |

DATA payload length is 1..65536 bytes. FIN has length zero. Unknown types,
invalid lengths, and data after FIN are protocol errors. Empty UDP datagrams
are not supported.

A DATA record preserves one local read. For UDP this preserves a datagram even
if HTTP/2 or QUIC fragments receive chunks. TCP remains a byte stream; DATA
boundaries do not turn TCP writes into application messages. The framed reader
validates length before reading the body and buffers one record at a time;
other transport/library buffers have their own bounds.

FIN shuts down the corresponding local writer only. The opposite direction
continues until its own FIN. Fatal forwarding errors cancel the paired task.
WebSocket Close happens after both directions finish; control traffic continues
to be handled after a directional FIN. An EOF and a complete application
response are different observations.

HTTP/2 uses bounded outgoing body queues. After closing its outbound body it
drains peer END_STREAM, with a ten-second deadline, before releasing the
connection driver. Enqueueing the final record alone does not prove delivery.

## Tunnel readiness

TCP target establishment and restriction validation precede a successful
tunnel acknowledgement. The local SOCKS5 or HTTP CONNECT handler reports success
only after tunnel setup succeeds. A rejected/unreachable target must not receive
an optimistic local proxy-success response.

WebTransport writes routing metadata before awaiting the server reply, making a
new QUIC stream visible to the peer. The reply is a length-prefixed routing
envelope sent after the destination is connected or a reverse visitor accepted.
It also carries the destination for dynamic reverse proxies. A rejected stream
is reset while other session streams can remain usable.

Normal acknowledgement and idle reverse-request waiting use distinct deadlines.
A WebTransport acknowledgement timeout invalidates the cached session so later
requests can reconnect.

## Pools, liveness, and limits

TCP-based transports use a connection pool capped at 1000. WebTransport uses one
multiplexed session; requested minimum-idle values above one are clamped to one.
QUIC advertises credit for at most 1024 bidirectional streams, including pending
reverse requests. These limits are per client/transport, not authenticated
per-device quotas across processes.

`--connection-retry-max-backoff` currently configures pool acquisition timeout
(default 5m, nonzero). The underlying connect timeout is separate, with a
ten-second default in the client/server construction paths. Reverse reconnects
use randomized capped backoff controlled by
`--reverse-tunnel-connection-retry-max-backoff` (default 1s).
WebSocket heartbeat frequency defaults to 30s and accepts zero to disable.

Server WebTransport certificate reload checks run on an independent one-second
tick, rather than waiting for a successful handshake to trigger acceptance.
Reloading a file does not by itself replace established TLS/QUIC sessions or
migrate every client's trust store.

## Proxies and reverse listeners

The HTTP proxy uses Hyper for streaming parsing/forwarding. Authentication is
checked for each request. Proxy credentials and hop-by-hop fields are consumed
before origin forwarding. CONNECT readiness follows tunnel readiness. Header
handling has a ten-second deadline and a 32 KiB buffer limit.

SOCKS5 has at most 256 pending negotiation handlers. UDP ASSOCIATE has a dedicated
relay bound to its control connection, checks the TCP peer IP, and constrains
the UDP source port or pins the first valid source. Closing the control
connection invalidates its relay streams. Unsupported UDP fragments are dropped,
and congested destination queues drop datagrams rather than block other queues.

Reverse listener keys include a unique Server-instance ID, verified device CN
when available, trusted tenant ID when configured, and the socket/Unix endpoint.
Verified device ownership does not depend on quotas or revocation being enabled.
A quota-enabled listener retains its creating quota lease until cleanup; a
revocation-enabled listener follows its creator's cancellation guard.
Unauthenticated legacy operation has no verified device boundary. Port zero
allocates a new endpoint: the OS selects it by default, while optional
[tenant policy](TENANT_ISOLATION.md) samples up to 32 distinct ports from its
reserved address/pool. Tenant role and rule scope also constrain tunnel requests;
this does not change wire protocol v2.

Cleanup depends on receiver/waiter lifecycle and an idle timer. Ephemeral
listeners use checks capped at five seconds by the configured idle timeout;
fixed listeners use the configured interval. Quota-enabled unused listeners
instead check at intervals capped at one second by that timeout. Transport
teardown must be observed before reclaim, so do not promise immediate release
on every disconnect. Validate cleanup and reconnection for the intended workload.
An explicit policy revocation cancels its creator's listener independently of
that idle timer after the updated policy is applied.

## Fleet observation

The management API accepts loopback binds and only the documented GET routes.
WebSocket, HTTP/2, and WebTransport share connection and admitted-tunnel leases.
Pending setup is visible; failure, cancellation, and completed forwarding release
the corresponding tunnel record. Reverse listener records have a separate kind
and lifetime. Connection records carry the actual socket peer and verified mTLS
identity when available. Client labels remain untrusted metadata.

A single `assigned_port` value or session count is not a port-ownership guarantee
or cluster-wide quota record. Live records remain in memory. The optional
[persistent fleet inventory](FLEET_INVENTORY.md) separately commits verified CN,
certificate fingerprint, and authentication observation metadata to SQLite.
It does not persist live sessions or perform enrollment. See the
[README API section](../README.md#fleet-observation-api) for routes and usage.

## Verification

Build and run bounded checks against a particular binary:

~~~sh
cargo build --release --locked -p tunward-cli
python3 scripts/qualify.py --sections protocols,security,extended,isolation,lifecycle,rotation
python3 scripts/qualify_identity.py --output target/qualification/identity-v2
python3 scripts/qualify_pool_timeout.py --output target/qualification/pool-v2
python3 scripts/qualify_revocation.py --output target/qualification/revocation-v2
~~~

Use new output paths. Results cover measured cases; they do not establish
production capacity or certification. The
[qualification guide](STAGING_QUALIFICATION.md) distinguishes loopback,
container, WAN, and endurance evidence.

## Implementation and external contracts

Repository sources: [framing](../tunward/src/tunnel/transport/io.rs),
[routing envelope](../tunward/src/tunnel/transport/jwt.rs),
[server validation](../tunward/src/tunnel/server/server.rs),
[client CN checks](../tunward/src/protocols/tls/utils.rs), and
[reverse lifecycle](../tunward/src/tunnel/server/reverse_tunnel.rs).

- [Tokio directional shutdown](https://docs.rs/tokio/latest/tokio/io/fn.copy_bidirectional.html)
- [Quinn stream visibility](https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.open_bi)
- [Rustls client trust/CRLs](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)
- [HTTP proxy credentials, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.2)
- [SOCKS5 UDP association, RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html#section-7)
- [WebSocket close handshake, RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html#section-7.1.2)
