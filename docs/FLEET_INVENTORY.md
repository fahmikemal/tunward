# Fleet records and persistent device inventory

Tunward records connections and admitted tunnel work through the same lifecycle
leases on WebSocket, HTTP/2, and WebTransport. The optional SQLite inventory
persists observations of verified mTLS device CNs across server restarts.

The inventory is an observation database. It does not enroll devices, grant
access, establish physical MDM ownership, synchronize replicas, or persist quota
usage. Keep authorization, quotas, and revocation configured separately.

## Enable persistence

Use a private directory on a persistent local filesystem:

~~~sh
mkdir -m 700 state
tunward server \
  --tls-certificate certs/mTLS/generated/certs/tunward-server.cert.pem \
  --tls-private-key certs/mTLS/generated/private/tunward-server.pem \
  --tls-client-ca-certs certs/mTLS/generated/certs/ca.cert.pem \
  --fleet-inventory state/devices.sqlite3 \
  --fleet-inventory-max-devices 10000 \
  --management-api 127.0.0.1:8081 \
  --restrict-to 127.0.0.1:3000 wss://127.0.0.1:8443
~~~

Use the [mTLS guide](using_mtls.md) to generate local development certificates.
Configure production trust/keys through the organization's issuance process.
Inventory configuration requires actual TLS with a client-CA verifier; cleartext
or missing client authentication fails before listening. Management API exposure
is optional: inventory can be recorded without an HTTP management listener.

The equivalent environment variables are `TUNWARD_FLEET_INVENTORY` and
`TUNWARD_FLEET_INVENTORY_MAX_DEVICES`. Embedded users configure
`ServerConfig.fleet_inventory` and its positive `fleet_inventory_max_devices`.
The default maximum is 10000. Omit the inventory path to keep live registration
without persistence when the management API is enabled.

Rust embedders using struct literals must supply the new ServerConfig fields
and the added SessionRecord metadata fields. Serialized session fields are
additive and deserialize older records with empty/absent metadata. Tunnel wire
version remains v2; an older client without consistent label headers can still
appear through its verified connection identity.

The state directory is excluded from Git and image build contexts. Mount a
persistent local volume when running Docker/Podman. Database, WAL, shared-memory,
and lock files belong to runtime state; do not package them in a public image.

## Identity and persisted fields

The primary key is the exact case-sensitive CN extracted from a verified client
certificate. Caller labels, request paths, forwarded headers, and IP addresses
cannot create verified identities. Client CNs must be unique within the server's
trusted-issuer scope; identical CNs from different trusted issuers share one
inventory row, as they do for quotas and CN revocation.

| Field | Meaning |
| --- | --- |
| `id` | Verified client certificate CN |
| `first_seen_at` | Unix seconds of the first committed authentication observation |
| `last_seen_at` | Latest committed observation time, without moving backward |
| `last_certificate_sha256` | Latest observed leaf-certificate DER fingerprint |
| `last_transport` | Latest observed authenticated connection transport |
| `observed_connections` | Committed observations, saturating at SQLite's signed integer maximum |
| `active_connections` | Current process's owned connection contexts; computed in memory |
| `active_tunnels` | Current process's admitted pending/ready tunnel work; computed in memory |

A renewed certificate with the same CN updates the existing row and its latest
fingerprint. A different CN creates another row. Certificate issuance history,
all old fingerprints, private keys, caller labels, and transport sessions are
not stored in this table. Tenant membership and roles are also not persisted;
configure them through the separate [tenant policy](TENANT_ISOLATION.md).

Observation is committed after TLS identity and initial connection admission,
before application tunnel processing. An authenticated connection can therefore
be observed even if it later requests a forbidden destination, sends no tunnel,
is cancelled, or loses access during setup. These timestamps are authentication
observations, not continuous heartbeat/last-packet measurements or an audit log
of successful business operations.

Existing identities can reconnect at capacity. A new identity is denied when
the configured maximum stored rows is reached. No automatic eviction deletes
offline devices. Raising the limit requires restart. Lowering it below the
stored row count still permits existing identities but prevents new rows.

## Live records and counts

`--client-id` / `--device-id` remain untrusted labels. All three clients send
them consistently, and the server groups active labelled tunnel work under
`/api/v1/clients`. Two devices can share a label; one device can change its label.
Empty labels or labels exceeding 256 bytes are ignored for fleet grouping.
Header-file overrides retain their existing precedence over the CLI label.

`/api/v1/connections` lists unique connection IDs, actual socket peer addresses,
transport, verified device CN/fingerprint when available, and the latest observed
caller label. With tenant policy enabled, connections also expose trusted
`tenant_id` and `roles`; tunnel/listener records expose `tenant_id`. Unknown
tenant identities are denied before observation. The management API remains
global across tenants. TLS transport values are `wss`, `https`, and `wts`. Cleartext records
start as `tcp`, then become `ws` or `http` when a valid tunnel identifies the
protocol. Cleartext/unauthenticated connections never become verified devices.

`/api/v1/sessions` distinguishes `kind: tunnel` from `kind: reverse_listener`.
A tunnel appears after destination authorization and admission, while setup may
still be pending. `state: forwarding` means destination setup completed and the
forwarding/upgrade lifecycle owns the record. Failed setup, close, cancellation,
and revocation release the tunnel lease. Clones retain the same record rather
than incrementing it. Reverse listener records have a separate `listening`
lifetime; they can outlive the tunnel request that created them until cleanup.
They use unique IDs rather than port numbers as global keys.
For a tunnel, `bind_addr` identifies the control connection's socket peer; for
a reverse listener it is the actual listening endpoint. `target_port` records
the requested port, while `assigned_port` is updated when setup resolves it.

Connection records survive while their context or separately spawned forwarding
still owns a lease, including WebSocket upgrades. A retained reverse listener
does not itself retain a connection count. A connection record is not proof
that every underlying network path or physical device is currently reachable.

Health exposes `active_connections`, `active_tunnels`, and distinct verified
`active_devices`. Legacy `active_clients` counts label groups; `active_sessions`
includes both tunnel and listener records. A client's single `assigned_port` is
the latest observation, not a reservation or a complete list of owned ports.
Counts are live snapshots, not a transactionally frozen cross-endpoint view or
the quota engine's retained-resource counters.

## Read API

All routes require GET and remain loopback-only without built-in authentication.
Use an authenticated gateway for remote operators.

~~~sh
curl --fail http://127.0.0.1:8081/api/v1/connections
curl --fail http://127.0.0.1:8081/api/v1/sessions
curl --fail 'http://127.0.0.1:8081/api/v1/devices?limit=100'
curl --fail http://127.0.0.1:8081/api/v1/devices/device-001
~~~

The device list returns `devices` and `next_cursor`. Pass the returned cursor as
the percent-encoded `after` parameter to fetch the next page. Ordering is the
exact CN's SQLite binary text order. The default page size is 100, with an
allowed range of 1–1000. Inserts during pagination can change subsequent pages;
this is not a snapshot export. Unknown/duplicate query parameters or invalid
page sizes return 400. A missing device returns 404. Device reads return 503
when persistent inventory is disabled or unavailable. Responses use `no-store`.

There are no enrollment, record-deletion, runtime quota editing, or revocation
mutation routes. Read access to inventory does not grant tunnel access.

## Storage and failure behavior

Rusqlite 0.40.2 uses bundled SQLite. The database has an application ID and schema
version 1; foreign databases and unsupported future versions are rejected
without replacing their contents. One process owns a database through a sibling
`.lock` file. Do not remove/replace that lock while a server is running. Each
replica needs its own inventory and an external aggregation/distribution design.

SQLite runs on a dedicated thread with a 256-command queue. Network tasks await
acknowledgements without doing database I/O on the forwarding executor. Queue
overload rejects a request; callers have a five-second response deadline.
SQLite's lock wait is one second. Cancelling/timing out a caller does not recall
an observation already queued or being committed.

WAL mode and `synchronous=FULL` are required. New connection admission with
inventory enabled waits for its observation commit; a write failure prevents
that connection from opening targets. Existing forwarding continues. Reads do
not clear a previous write failure. `/healthz` exposes `inventory_enabled` and
`inventory_healthy`, returning 503 when the worker reports failure. A successful
later observation restores that status; it is an observed worker-health signal,
not a continuous disk-capacity probe. Investigate admission/reload logs as well.

Keep the directory writable only by trusted operators/the service account.
New files use owner-only permissions on Unix; existing database/lock files with
group/other permissions or final-component symlinks are rejected there. Parent
directories and Windows ACLs remain deployment responsibilities. The database
is not encrypted by this feature; apply the storage protection required for
device identifiers and certificate metadata.

Use a local filesystem with SQLite WAL support, not a shared network filesystem.
For live backups, use SQLite's online backup mechanism. Do not copy just the
main database while its WAL is active. For offline file backups, stop the server
and preserve its complete state coherently. Test restoration before relying on
it. Schema downgrades are not automatic; retain a compatible binary and tested
backup for rollout/rollback. Offline retention maintenance needs an operator
procedure; this implementation does not silently prune or rewrite identities.

## Verify

~~~sh
cargo build --release --locked -p tunward-cli
python3 scripts/qualify_fleet.py --output target/qualification/fleet-review
~~~

The Linux loopback suite checks transport/label parity, separate verified devices,
pending/reverse records, cancellation cleanup, abrupt process restart, stable-CN
key rotation, pagination/capacity, database lock failure/recovery, cleartext
labels, single ownership, and preservation of a foreign database. Unit tests
cover concurrent parameterized writes, capacity/pagination, schema rejection,
and cloned lease lifetimes. These checks do not qualify physical MDM inventory,
cluster consistency, every filesystem/OS, or production endurance.

## Documentation contracts

- [Rusqlite connection and parameterized queries](https://docs.rs/rusqlite/0.40.2/rusqlite/)
- [SQLite WAL constraints and operation](https://www.sqlite.org/wal.html)
- [SQLite synchronization settings](https://www.sqlite.org/pragma.html#pragma_synchronous)
- [SQLite online backup](https://www.sqlite.org/backup.html)
