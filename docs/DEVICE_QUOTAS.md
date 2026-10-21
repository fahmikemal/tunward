# Authenticated device quotas

Device quotas are optional and disabled unless the server receives
`--device-quota-config FILE`. They require verified mTLS. They cover authenticated
transport sessions, admitted/pending tunnel work, tunnel-attempt rate, and
aggregate upload/download application payload rates.

One CLI server shares the same accounting across WSS, HTTP/2, and WebTransport.
Server clones share state. Separate Server instances, processes, and replicas do
not coordinate quotas. Counters and token buckets reset on server restart;
this is not durable billing or a distributed quota service.

## Enable

Generate the local bundle using the [mTLS guide](using_mtls.md), then add the
quota file to the README server recipe:

~~~sh
tunward server \
  --tls-certificate certs/mTLS/generated/certs/tunward-server.cert.pem \
  --tls-private-key certs/mTLS/generated/private/tunward-server.pem \
  --tls-client-ca-certs certs/mTLS/generated/certs/ca.cert.pem \
  --device-quota-config device-quotas.example.yaml \
  --restrict-to 127.0.0.1:3000 wss://127.0.0.1:8443
~~~

The [example configuration](../device-quotas.example.yaml) contains starting
values for qualification, not universal production sizing recommendations:

~~~yaml
version: 1
max_tracked_devices: 10000
default:
  max_sessions: 16
  max_tunnels: 64
  requests_per_second: 20
  request_burst: 40
  upload_bytes_per_second: 1048576
  download_bytes_per_second: 1048576
  bandwidth_burst_bytes: 65536
devices:
  device-001:
    max_tunnels: 128
    download_bytes_per_second: 2097152
~~~

The file is loaded and validated at startup. With [managed reload](DEPLOYMENT.md#managed-reload),
edited limits can be activated without restarting. Existing session/tunnel
counts and depleted token credit are preserved, including across a no-op reload.
Lower caps keep active work counted and reject new admissions until usage drops;
existing stream shapers observe new rates, with blocked waits rechecking within
100 ms. Default mode still requires restart to change quota limits. Changing the
startup quota file path also requires restart. The CLI accepts
`TUNWARD_DEVICE_QUOTA_CONFIG`. Configuring quotas on cleartext or without the
client-CA verifier fails before the server listens.

Unknown fields, unsupported versions, zero limits, burst-only configurations,
and an entirely empty limit policy are rejected. Device overrides inherit omitted
fields from `default`; omission/null cannot disable an inherited limit. An
omitted default limit is unlimited. At least one effective limit must be present.
Choose and qualify all limits required by your workload.

## Identity

The key is the exact, case-sensitive CN from the verified client certificate,
not `--client-id`, `--device-id`, an IP address, a URL path supplied by the client,
or a forwarded certificate header. mTLS path/CN agreement and destination rules
remain mandatory; a quota profile grants no additional access.

CNs must be unique for devices within the server's trusted-issuer scope.
Certificates from different trusted issuers with the same CN deliberately share
one account. Ordinary key/certificate rotation should preserve the device's
stable CN. A new key with the same CN, reconnecting, changing labels, or changing
transport does not create a new budget. Changing the actual verified identity is
an issuance/policy operation, not a client-controlled rename.

Quota enforcement needs end-to-end client mTLS at tunward. A proxy header is
not a replacement for verified peer identity.

## Limits and accounting

| Field | Scope and behavior |
| --- | --- |
| `max_sessions` | Authenticated TCP TLS connections and accepted WebTransport sessions; idle/prewarmed sessions count |
| `max_tunnels` | Admitted tunnel work, including pending setup/reverse waits and retained reverse allocations |
| `requests_per_second` | Token refill rate for authenticated tunnel attempts |
| `request_burst` | Attempt bucket capacity; defaults to `requests_per_second` |
| `upload_bytes_per_second` | Aggregate device-to-target application payload refill rate |
| `download_bytes_per_second` | Aggregate target-to-device application payload refill rate |
| `bandwidth_burst_bytes` | Capacity of each configured directional bucket; defaults to 65536 |
| `max_tracked_devices` | Maximum cached identity accounts, not an enrollment allowlist or configured device quota |

Session/tunnel admission is atomic. A rejection occurs before opening a target or
allocating a reverse listener. A tunnel slot is released on failed validation or
setup, completed forwarding, or cancellation when the last owning resource
drops. A session slot remains charged while work created by that session still
owns quota-bearing resources. One cloned permit retains one allocation rather
than counting another allocation.

Requests consume attempt tokens even when subsequently rejected for an invalid
request, forbidden target, failed setup, or concurrent-work limit. The attempt
limit concerns the tunnel protocol, not each HTTP request carried inside a
stream, management API access, TLS handshakes, or transport control packets.
WebTransport reserves before waiting for per-stream routing metadata.

Inactive account entries are reclaimed only after their buckets refill and all
resource leases release. Reconnecting cannot obtain a fresh full bucket by
dropping the last session. If the table is full and no entry can be reclaimed,
new identities are rejected rather than growing the table without a bound.

## Bandwidth shaping

Each direction has its own token bucket shared by all the device's tunnels and
transports. The example rate is 1 MiB/second per direction, with an initial
64 KiB burst. After idle time, the available burst remains capped at the
configured capacity.

Shaping counts payload at the server forwarding boundary before target delivery
on upload and transport enqueue on download. It excludes routing/framing,
TLS/QUIC overhead, retransmissions, and control traffic. It is not an exact
wire-rate cap or a network-wide QoS policy. Downstream buffering and network
scheduling can change observed packet timing.

Accounting uses integer credit and monotonic time. Waiting is asynchronous;
mutexes are not held while sleeping. Cancelling a wait does not reserve future
credit. Once admitted, bytes can remain charged even if later delivery fails.

The burst must be at least 65536 bytes so a maximum tunnel record can receive
credit in one operation. UDP datagrams are delayed as whole records instead of
being truncated/split to fit a small read budget. WebSocket output control work
can continue while its payload waits for credit.

This is aggregate device shaping, not a fair scheduler between that device's
individual streams. Very low rates can conflict with application/protocol
timeouts; qualify both together.

## Reverse resources and disconnects

With quotas enabled, a reverse listener retains its creating tunnel's permit
until listener cleanup as well as any active stream use finish. Subsequent
pending requests also need their own admission. This prevents cancelled reverse
requests from releasing quota while leaving uncharged listeners behind.

Reverse keys include the verified mTLS identity and Server-instance ID even
when quotas are disabled. Another identity cannot reuse that device's cached
listener, even with the same caller label. The OS enforces conflicting binds.
Optional [tenant authorization](TENANT_ISOLATION.md) separately adds membership,
tunnel roles, named rule scope, and reserved reverse endpoints. Quota accounts
do not themselves grant any tenant role.

Unused quota-enabled listeners are checked at intervals capped at one second by
the server idle timeout. Cleanup begins only after transport teardown/cancellation
is observed. TCP EOF and QUIC peer loss have different detection times.
WebTransport idle timeout is derived as three times the configured heartbeat
interval; the default 30-second interval therefore permits a 90-second detection
window. A zero interval disables that QUIC idle timeout. Keep a finite heartbeat
when bounded dead-peer recovery is required.

The separate [live revocation policy](DEVICE_REVOCATION.md) can cancel sessions
and retained reverse resources after a policy reload, independently of that
network-loss detection window. It can be enabled with or without quotas.

Do not promise immediate slot recovery after a power loss or network partition.
Idle pools also consume session slots; size `--connection-min-idle`, session
limits, retry deadlines, and heartbeat intervals together.

## Rejections and operations

WSS/HTTP2 tunnel requests return HTTP 429 with `Cache-Control: no-store`.
Request-rate responses include rounded-up `Retry-After` seconds. WebTransport
session admission can return 429; rejected bidirectional streams reset with the
429 code. TCP session admission over its limit closes the authenticated
connection before protocol processing.

The local SOCKS5/HTTP CONNECT client receives a failure rather than optimistic
success when tunnel admission fails. Existing retry/backoff options still apply;
clients do not automatically tune their pools or policies to server quotas.

The fleet API is not the quota accounting source. Label-grouped clients remain
unverified. Its [connection/device records](FLEET_INVENTORY.md) expose verified
identities and live work observations, but those counts have different lifetimes
from retained quota resources. The API does not edit quotas or export their
token-bucket balances.
Monitor rejection/error behavior and the underlying process/network metrics;
configure alert thresholds from measured workload and service objectives.

## Verify

~~~sh
cargo build --release --locked -p tunward-cli
python3 scripts/qualify_quotas.py --output target/qualification/quota-review
~~~

Use a new output directory. The loopback runner checks cross-transport admission,
idle sessions, independent identities, label/key-rotation behavior, failed setup,
rate recovery, aggregate directional payload shaping, proxy/UDP integrity,
reverse cancellation/ownership, and rejection of cleartext configuration.
Unit tests cover concurrent admission, shared leases, cache retention, virtual
time, cancelled waits, and pending writes without double charging.

These checks do not qualify distributed enforcement, physical-device fleets,
privileged TProxy, or sustained production capacity. Run
[the broader regression/capacity profiles](STAGING_QUALIFICATION.md) on the exact
binary and deployment environment.

## Contracts

- [Tokio asynchronous wakeups and reads](https://docs.rs/tokio/latest/tokio/io/trait.AsyncRead.html)
- [Tokio pinned timers](https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html)
- [Rustls verified client certificates](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)
- [HTTP 429 and Retry-After, RFC 6585 section 4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4)
- [Token-bucket models, RFC 3290 appendix A](https://www.rfc-editor.org/rfc/rfc3290.html#appendix-A)
