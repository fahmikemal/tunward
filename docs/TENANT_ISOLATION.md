# Device ownership and tenant authorization

`--tenant-config FILE` enables verified tenant membership and roles for
verified mTLS device identities. It applies to WSS, HTTP/2, and WebTransport.
It is disabled by default and requires both actual mTLS and `--restrict-config`.
Unknown devices are denied even when their certificates have a trusted issuer.

## Enable

Generate the local certificates using the [mTLS guide](using_mtls.md). Run the
README target service on port 3000, then use this server command instead of its
`--restrict-to` recipe:

~~~sh
tunward server \
  --tls-certificate certs/mTLS/generated/certs/tunward-server.cert.pem \
  --tls-private-key certs/mTLS/generated/private/tunward-server.pem \
  --tls-client-ca-certs certs/mTLS/generated/certs/ca.cert.pem \
  --restrict-config tenant-restrictions.example.yaml \
  --tenant-config tenant-policy.example.yaml \
  wss://127.0.0.1:8443
~~~

The README client command continues to work: its verified CN `tunward_client_1`
belongs to tenant `alpha`, which permits the loopback destination on port 3000.
The example's `beta` tenant permits port 4000 and requires a separately issued
certificate with CN `device-beta-001`. Merely changing a client label cannot
select that membership. Adapt all identities, addresses, ports, and grants before
deployment; the examples are local development policy.

Use the [tenant policy](../tenant-policy.example.yaml) together with its
[named restriction rules](../tenant-restrictions.example.yaml). The equivalent
environment variable is `TUNWARD_TENANT_CONFIG`; Rust embedders set
`ServerConfig.tenant_config`. Struct literals must supply this new optional field.
There is no tunnel wire-version change.

## Authorization model

Each accepted request must satisfy all of these conditions:

1. Verified client CN agrees with the request path under the existing mTLS rules.
2. That exact case-sensitive CN has a configured tenant and at least one role.
3. A role grants the requested action.
4. A matching named restriction belongs to the tenant's configured scope.
5. The existing path/authentication/destination rule permits the request.
6. Reverse requests also satisfy the tenant's effective bind or Unix-path scope.

Restriction scope is filtered before choosing a matching rule. A broad rule for
another tenant cannot win by appearing earlier in the shared restriction file.
The example uses `match: [Any]` within this model; mTLS identity/path checks and
tenant scope still apply. Do not reuse those rules on a server without tenant
policy and expect the same device separation.

Roles contain only explicit permissions; there is no wildcard or implicit admin
role. Multiple roles combine their action grants within the device's one tenant.

| Permission | Controlled request |
| --- | --- |
| `forward_tcp` | TCP forwarding, including destinations requested through local SOCKS5/HTTP/stdio/Unix/TProxy ingress |
| `forward_udp` | UDP forwarding, including local UDP proxy/TProxy ingress |
| `reverse_tcp` | Server TCP listener |
| `reverse_udp` | Server UDP listener |
| `reverse_socks5` | Server SOCKS5 listener |
| `reverse_http_proxy` | Server HTTP proxy listener |
| `reverse_unix` | Server Unix socket listener |

The example grants only forward TCP/UDP and reverse TCP/UDP. Enabling proxy or
Unix listeners also needs the corresponding restriction and resource scope.
RBAC controls who may create/use tunnel resources. Visitors connecting to a
reverse listener still need appropriate application authentication, proxy
credentials, and network access controls.

Membership uses the verified certificate CN, never `--client-id`, `--device-id`,
tenant/role headers, forwarded IP/certificate headers, or SQLite observations.
CNs must be unique across the server's trusted issuers. Renewing a certificate
with the same CN preserves membership and ownership, including with a new key.
Separate issuers with identical CNs do not create separate devices.

Unknown fields, unsupported versions, unknown roles/tenants/rule names, empty
grants, duplicate restriction names, and invalid reservations fail startup.
The policy is limited to 1 MiB, 10000 devices, 1000 roles, and 1000 tenants.
These are input bounds, not qualified device-capacity claims.

## Reverse ownership and reserved endpoints

Reverse cache keys always include a unique Server-instance ID, the verified
device CN when available, and the endpoint. Tenant mode adds the trusted tenant
ID. Device ownership applies with mTLS even when quotas, revocation, and tenant
policy are disabled. Another device cannot consume a cached listener by asking
for the same endpoint or choosing the same caller label. A conflicting bind
fails through the OS. Server clones share ownership; separate Server instances
have separate namespaces. Unauthenticated legacy operation has no verified
device boundary.

Each tenant's `reverse_bindings` reserves concrete IPs and positive port ranges
in policy. Reservations on the same IP cannot overlap, including across TCP and
UDP or within one tenant. Wildcard, multicast, and IPv4-mapped IPv6 aliases are
rejected. A reverse hostname is not a substitute for the reserved literal IP.
The actual port after any restriction `port_mapping` must belong to the tenant.
An empty/omitted binding list denies network reverse listeners.

With `allow_ephemeral: true`, requesting port zero selects up to 32 distinct
random candidates from that address's reserved pool. Bind retries occur only
for an address-in-use error. This can fail when sampled ports are busy even if
other pool ports are free. Without tenant policy, port zero retains the existing
OS-assigned behavior. Allocations are not durable and policy reservations do not
reserve sockets against other processes or coordinate replicas. Qualify actual
bind conflicts and align host/container port publication with the reserved pool.

`reverse_unix_paths` is an optional list of exact absolute paths. Parents must
already exist and be canonical, with no symlink aliases; dot/parent components
and duplicate path reservations are rejected. The parent is checked again on
each request. The reverse restriction's Unix regex must also allow the path.
Keep these directories private to trusted operators: this is not a filesystem
sandbox against local users who can change directories during a bind. A denied
request does not unlink another device's socket.

Ownership and authorization do not alter the existing asynchronous listener
cleanup, retained quota leases, or creator revocation guards. See
[quotas](DEVICE_QUOTAS.md) and [revocation](DEVICE_REVOCATION.md) for those
resource lifetimes.

## Management and observation boundaries

The management API remains a global operator interface on loopback. Tenant roles
do not grant API access and there are no per-tenant operator views or role-editing
endpoints. Protect remote access with an authenticated gateway. Label-grouped
`/clients` can still combine devices from different tenants sharing a label.

With tenant mode enabled, direct forward requests to the configured management
API port are denied for every destination address/hostname, even if a restriction
would permit them. This deliberately blocks aliases as well as literal loopback;
it also blocks legitimate remote services using that port. Choose a management
port outside required forwarding destinations. This is not a transitive egress
firewall against a permitted destination acting as another proxy.

Live connection records add `tenant_id` and `roles`; tunnel and reverse-listener
records add `tenant_id`. These fields come from the active policy. The additive
JSON fields default to absent/empty when reading older records. The
[SQLite inventory](FLEET_INVENTORY.md) schema is unchanged and does not persist
authoritative tenant membership or role history. Unknown tenant identities are
rejected before inventory observation.

## Policy operations and deployment limits

Tenant membership, roles, and reserved resources load at startup and support
[managed reload](DEPLOYMENT.md#managed-reload). A candidate is validated against
the candidate named restriction rules before either snapshot is activated.
Equivalent or expanded effective grants preserve sessions and update their
fleet metadata. Removing a device, moving it to another tenant, or reducing its
effective role/resource grants cancels its transport sessions and retained
reverse resources. This deliberately closes all sessions of the affected device,
including otherwise-permitted streams; other devices stay connected. New tunnel
requests on retained HTTP/2 and WebTransport sessions use the current tenant
policy. Default mode still requires restart for tenant changes. Changing the
startup tenant file path also requires restart. The independent live revocation
file remains the mechanism for urgent certificate/CN denial.

In managed mode, named restrictions switch with tenant policy through explicit
reload; default mode retains automatic restriction watching. Scope is
checked against the current rules for each new tunnel request. Changing a
restriction does not retroactively terminate admitted forwarding. Preserve
unique names and review shared-name grants when publishing restriction changes.
Protect both policy files and their parent directories as authorization state.

This implementation provides tunnel authorization and device-scoped reverse
ownership in one Server instance. It does not provide OS/process isolation,
network segmentation, per-tenant databases, physical enrollment, distributed
port allocation, management API RBAC, or enterprise certification. Hostname
restriction matching is not resolved-IP pinning. Use separate processes/hosts
and network policies where tenants require a stronger boundary.

## Verify

~~~sh
cargo build --release --locked -p tunward-cli
python3 scripts/qualify_tenants.py --output target/qualification/tenant-review
~~~

Use a new output directory. Eleven bounded scenarios cover WSS/HTTP2/WebTransport
forward scope and live metadata, trusted-but-unlisted CN denial, spoofed headers,
management-port protection, fixed/mapped reverse binds, same-tenant device
ownership with tenant policy both enabled and disabled, twelve combinations of
port-zero TCP/UDP/SOCKS5/HTTP reverse allocation, exact Unix paths, combined
quota/revocation/inventory operation, and invalid startup policy. Denials check
upstream observations or resource creation as appropriate, alongside successful
traffic from the permitted owner. Unit tests also cover policy validation and
bounded distinct port sampling. Run the broader
[qualification profiles](STAGING_QUALIFICATION.md) for deployment-specific gates.

The authorization design follows the default-deny, least-privilege, and
per-request checks described in the
[OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
and trusted tenant context guidance in the
[OWASP Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html).
Port sampling uses the locked rand 0.8 `SliceRandom::choose_multiple` contract;
its [0.8.8 API reference](https://docs.rs/rand/0.8.8/rand/seq/trait.SliceRandom.html#tymethod.choose_multiple)
is the relevant version rather than the renamed API in newer releases.
