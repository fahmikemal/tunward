# Tunward roadmap

This roadmap covers the whole tool: tunnels, proxies, transports, device
controls, fleet observations, and deployment. Planned items below are not
implemented guarantees. No delivery date or next version number is assigned.

## v0.1 beta scope

The `v0.1.0-beta` baseline includes protocol v2, forward and reverse tunnels over
WebSocket/HTTP2/WebTransport, verified-device quotas and revocation, tenant
permissions and reverse ownership, persistent fleet observations, offline
configuration validation, and managed graceful file reload.

That is a sufficient feature baseline for controlled beta evaluation. The next
work is safer defaults, defect investigation, and qualification of the intended
deployment. A beta tag or passing CI does not establish stable or production
readiness. See [current usage and limits](README.md) and the
[qualification gates](docs/STAGING_QUALIFICATION.md).

## Next milestone: secure defaults

All five items are **planned**. The current beta still requires operators to
enable the appropriate controls explicitly; the
[deployment template](deploy/tunward.service) does so. Its minimum CLI invocation
does not enforce the proposed public-listener policy.

| Priority | Planned change | Acceptance criteria |
| --- | --- | --- |
| 1 | Require secure public listeners | A non-loopback listener requires TLS (`wss://`/`wts://`), `--tls-client-ca-certs`, and `--restrict-config`. Missing prerequisites reject startup with actionable errors identifying the missing settings. Cover wildcard IPv4/IPv6 and LAN/public addresses; hostname handling must not bypass the check. |
| 2 | Make development exceptions explicit | Cleartext or unauthenticated listeners are limited to loopback unless the operator explicitly selects a development exception. A proposed `--allow-insecure-dev` flag must warn on every start. It must not implicitly allow all destinations or relax the management API's loopback requirement. The flag does not exist in the current beta. |
| 3 | Deny tunnel access without an explicit policy | Missing policy must not synthesize `Allow All`. Unmatched requests are denied. An explicitly configured missing, unreadable, or invalid restriction file rejects startup; a failed managed reload retains the previous active generation. Document loopback/development behavior and migration from existing restriction options. |
| 4 | Apply resource limits without an operator quota file | Provide finite initial session, tunnel, request-rate, and payload-bandwidth limits, plus global admission and pre-authentication connection/handshake limits. Operators can adjust them. Preserve verified-device accounting across transports and reload. Select and document numerical defaults from measured capacity; there is no universal quota suitable for every deployment. Tenant configuration remains optional. |
| 5 | Prove the defaults with negative and positive tests | Reject minimum-argument non-loopback startup, every missing prerequisite, and invalid policy/trust files. Cover IPv4, IPv6, development exceptions, denied destinations, default quota enforcement, and valid complete configurations. Enforce the same policy through `server -t`, startup, and the library API. Existing CI does not yet prove these proposed defaults. |

This milestone changes existing startup behavior. Ship it with README/CLI help,
a migration guide, updated examples, and regression checks for existing
transports, reverse resources, quotas, revocation, and reload. Development
exceptions must not disable unrelated protections.

The access-policy direction follows
[OWASP's deny-by-default guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
The resource-limit work follows
[OWASP's resource-consumption guidance](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/).
The proposed flags and exact startup rules are Tunward design decisions, not an
OWASP certification or a requirement that every deployment use the same limits.

## Qualification before stable or production claims

These gates remain separate from feature count:

- Investigate the historical WSS WAN timeout and the intermittent tenant
  ephemeral reverse-UDP-over-HTTP2 CI timeout. The latter passed an unchanged
  rerun and 180 targeted local repetitions, but its cause is not established.
  A successful rerun is not a demonstrated fix.
- Complete and review continuous 24–72 hour WAN evidence for the exact candidate
  binary and representative workloads. Test real MDM devices, sleep/reconnect,
  and network transitions separately from synthetic identities.
- Qualify required privileged/IPv6 TProxy, DNS/ECH/CDN behavior, and target OS
  runtimes. Do not treat a release build target as a runtime qualification.
- Validate the actual deployment's certificate issuer/domain, renewal,
  permissions, reload, monitoring, backup, rollout, and rollback. Define and
  measure latency, availability, capacity, and recovery objectives.
- Review dependency maintenance warnings and remaining publication/key-rotation
  follow-ups. Validate tagged artifacts and image digests before promotion.

Complete the relevant gates with retained evidence before changing stability
claims. They do not become complete merely by assigning a version number.

## Architectural limitations and future scope (v0.2+ / v0.3+)

The following architectural limitations are acknowledged in the v0.1 baseline, with future roadmap recommendations:

| Domain | Current limitation | Impact | Future architectural scope |
| --- | --- | --- | --- |
| **State distribution** | Process-local token bucket quotas and SQLite inventory without cross-replica consensus. | Multi-replica deployments behind L4 load balancers enforce limits per pod rather than globally across the fleet. | Provide an optional distributed quota and state adapter (e.g., Redis/Dragonfly backend via atomic token-bucket Lua scripts or etcd coordination). |
| **Identity extraction** | Strict x509 Common Name (CN) binding for verified mTLS device identity. | Modern PKI standards (RFC 5280) deprecate CN in favor of Subject Alternative Name (SAN) extensions, such as Hardware UUIDs (`otherName`) or SPIFFE/URI identifiers. | Add configurable identity extraction options (e.g., `--tls-client-identity-field [cn|san-uri|san-dns]`) to support modern MDM and service mesh certificate profiles. |
| **Revocation lifecycle** | Application-level file polling denylist (`device-revocations.yaml`) without native CRL or OCSP responder integration. | Operators managing dynamic CA certificate revocation lists must manually translate CRLs into Tunward's local revocation YAML. | Integrate dynamic X.509 CRL distribution point ingestion and OCSP stapling/checking into the Rustls verification pipeline. |
| **Fleet modularity & decoupling** | Monolithic binary compilation linking `rusqlite` unconditionally into the core binary; fleet registry coupled to in-process memory and local SQLite. | Bloats binary footprint and build times for embedded, IoT, or router targets (e.g., OpenWrt, microVMs) requiring lightweight data-plane forwarding only. | Decouple fleet observation into an optional Cargo feature (`features = ["fleet"]`) or distinct control-plane crate (`tunward-fleet`), enabling pure data-plane builds and pluggable remote backends (PostgreSQL, Redis). |


