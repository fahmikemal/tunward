# Certificate lifecycle, rollout, and rollback

Use a separate staging environment and a release manifest containing binary hash,
source revision, policy versions, certificate fingerprints, inventory schema,
and the matching [qualification evidence](STAGING_QUALIFICATION.md). Deployment
is not completed by a healthy process or one successful tunnel.

## Decisions and ownership

Choose the actual address devices will use, such as `tunnel.example.com`.
The server certificate must cover that DNS name or IP. Public server certificates
may use the organization's ACME service; device certificates can use a separate
private CA. The CA signing key stays with the issuer, outside tunnel servers.
The repository's development generator does not issue production identities or
configure automatic renewal.

Assign an owner for server renewal, device issuance/revocation, trust distribution,
policy rollout, incident response, and backup restoration. Keep device CNs unique
within all trusted issuers and stable during ordinary key renewal. Inventory
observations are not enrollment approval. Review
[tenant grants](TENANT_ISOLATION.md), [quotas](DEVICE_QUOTAS.md), and
[live revocation](DEVICE_REVOCATION.md) together.

For example, use root-owned configuration under `/etc/tunward`, versioned binaries
under `/opt/tunward/releases`, and private persistent inventory under
`/var/lib/tunward`. Server/device private keys and signing state are runtime or
issuer secrets, never release artifacts. Keep a distinct disposable staging CA.

## Validate server configuration before activation

Run the candidate binary with the intended server arguments and add `-t` or
`--test-config`, as shown in the [README](../README.md#check-server-configuration).
Use the service account and the same environment and readable candidate files.
The check returns `0` on success, `1` for invalid configuration, or `2` for CLI
usage errors. It validates policy syntax/values/references, TLS key matching and
client trust parsing, and transport/mTLS prerequisites through the startup readers.
Unknown restriction fields and descending port ranges now fail validation and
startup; review configurations that previously relied on ignored fields.

The check does not bind listeners, resolve addresses, contact peers, start
watchers, open/create the inventory database, or write TLS key logs. It does not
validate database permissions/schema, OS capabilities, port availability, remote
reachability, or certificate deployment trust/expiry. Check the certificate bundle
separately below, then run a canary using the intended runtime environment.
Keep each candidate file immutable between validation and activation: validation
does not lock a set of files or commit a configuration transaction.

This command does not reload a running process. Restrictions and revocations
retain their existing automatic reload behavior; quotas and tenant policy still
need a restart. Listener/startup changes also need a restart. Full graceful
configuration reload and `systemctl reload tunward` are not implemented.

## Validate certificates before activation

The checker accepts a PEM server leaf followed by intermediate certificates,
its matching private key, and the issuer trust bundle used by clients. It checks
the chain, server purpose, SAN name (rejecting CN-only fallback), key match, and validity through the given
future horizon. POSIX checks reject other-user key access and group write access.

~~~sh
python3 scripts/check_tls_bundle.py \
  --certificate /etc/tunward/candidate/server.pem \
  --private-key /etc/tunward/candidate/server.key \
  --issuer-ca /etc/tunward/candidate/server-issuers.pem \
  --server-name tunnel.example.com --minimum-valid-days 30
~~~

This performs no issuance, revocation lookup, activation, live handshake, or
remote permission changes. Run it as an account that can legitimately read the
key. The minimum horizon is an operator policy; check it against actual renewal
and outage budgets. Monitor certificate expiry and issuer renewals independently
of the tunward process, and alert well before the remaining validity falls below
the renewal/recovery budget. A renewal failure must leave the current valid
bundle intact and alert its owner.

Publish a new certificate and matching key as one versioned candidate. Validate
before replacing any live path. Native file reload exists, including a five-minute
poll fallback for symlink changes, but independent file updates can briefly
produce a mismatched pair. Invalid TLS rebuilds retain the active acceptor;
that is recovery behavior, not an atomic multi-file deployment transaction.
Prove successful fresh handshakes after activation on every enabled transport.

For a server issuer migration, distribute overlapping old/new trust to clients
first, then switch the server certificate, then remove old trust only after
qualification and the agreed migration window. Existing sessions can remain on
their original handshake. For a device issuer migration, similarly expand the
server's client trust bundle before rolling out devices; use explicit revocation
when active sessions must close. Do not roll back an intentional revocation to
restore service or reintroduce an exposed key.

## Linux systemd example

The [service template](../deploy/tunward.service) assumes a dedicated `tunward`
user/group, an installed binary at `/opt/tunward/current/tunward`, and reviewed
policy files in `/etc/tunward`. It enables mTLS, tenant policy, quotas, revocation,
persistent inventory, TCP TLS and QUIC on port 8443, and a loopback management API.
Adapt the [restriction](../tenant-restrictions.example.yaml),
[tenant](../tenant-policy.example.yaml), [quota](../device-quotas.example.yaml),
and [revocation](../device-revocations.example.yaml) examples before installation.
Do not deploy the example CNs/grants as an enrollment policy.

`LoadCredential` snapshots server identity and client trust when the service
starts. Renewal in this layout requires a controlled restart to load new
credentials; it does not rely on live source-path watching. Unit specifier `%d`
is the private credentials directory. Keep the original key root-readable only.
The template uses unprivileged ports and grants no capabilities. TProxy belongs
in a separately qualified client/routing setup, not this server unit.

`ExecStartPre` runs the offline configuration check before each start and prevents
`ExecStart` when validation fails. Keep its arguments identical to `ExecStart`,
apart from `--test-config`. This uses the credentials made available to the unit;
it does not validate a future replacement credential snapshot or keep sessions
alive during a restart. The template has no `ExecReload`.

The service restricts filesystem writes to its managed state and private temporary
directory. Configure any Unix reverse paths inside permitted private runtime/state
directories and align tenant path scopes accordingly. Size process/FD/memory
limits from measurement; the template's FD/task limits are not a capacity promise.
Verify systemd feature support and the exact service sandbox on the deployment OS.
The template has not been activated on a production service by this repository task.

## Rollout

1. Preserve the approved binary, policy files, certificate/trust versions, and a
   consistent inventory backup. Use the [SQLite backup procedure](FLEET_INVENTORY.md)
   or stop its sole owner; copying only a live WAL database file is insufficient.
2. Stage a new immutable release directory and verify its checksum. Test its
   `--version` and CLI options against the intended configuration. Protocol v2
   requires compatible peers; older wire versions need a separate listener.
3. Start a canary on a separate approved port/host with independent inventory and
   disjoint reverse pools. Never attach two owners to the same SQLite database.
4. Run verified forward/reverse traffic, policy denials, quotas, revocation,
   management/inventory checks, and reconnect tests with representative devices.
   A local `/healthz` response alone is insufficient. Review error/latency/resource
   budgets and require the intended endurance duration to finish.
5. Switch the reviewed binary/configuration and restart the service, or migrate
   devices through an explicitly designed load-balancer/drain plan. A plain
   restart closes active sessions; client backoff and reserved endpoint recovery
   must be included in the maintenance budget. Existing reverse listeners do not
   migrate between processes or replicas automatically.
6. Repeat fresh handshake/data/denial probes on WSS, HTTP/2, and WebTransport;
   verify the expected certificate and binary fingerprints, policies, inventory
   health, and alert delivery before widening the rollout.

## Rollback

Define rollback triggers before rollout, including excessive handshake failures,
forwarding errors, quota/revocation failures, unhealthy inventory, or recovery
time exceeding the maintenance budget. Preserve failed evidence before switching.

Restore the last approved binary and compatible policy/certificate bundle, then
restart and repeat the same data and denial probes. Keep revocations that protect
against compromised identities. Validate certificate validity and issuer trust
again; an old binary does not make an expired or compromised certificate safe.
If a release changes the inventory schema, verify downgrade support explicitly
or restore the consistent pre-upgrade backup with its matching binary while
the database owner is stopped. Do not allow old code to silently write a newer
schema. This version rejects unsupported inventory schemas.

The [PKI runner](../scripts/qualify_pki.py) validates candidate rejection, distinct
server key/issuer renewal, denial of old-only trust, and rollback on all three
TLS transports. It also checks that established tunnels survive the certificate
switch. These are disposable loopback tests, not proof of public CA issuance,
ACME automation, a production load-balancer cutover, or an inventory-schema downgrade.

~~~sh
python3 scripts/qualify_pki.py --output target/qualification/pki-review
~~~

## Contracts

- [systemd credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredential=ID:PATH)
- [OpenSSL certificate verification](https://docs.openssl.org/master/man1/openssl-verification-options/)
- [ACME protocol, RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html)
