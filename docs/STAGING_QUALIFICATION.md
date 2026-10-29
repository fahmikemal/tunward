# Qualification and deployment gates

Keep evidence tied to a binary hash, source/runner version, configuration,
workload, timeout budget, and environment. A successful loopback run is evidence
for that workload, not a maximum device count, production SLO, or enterprise
certification.

The examples use generic operator-owned staging paths and SSH aliases. They do
not provision a server, change firewall rules, or authorize tests against an
unrelated host.

## Runners and prerequisites

Build the binary:

~~~sh
cargo build --release --locked -p tunward-cli
~~~

Python runners need Python 3 and OpenSSL. Most profiles use Linux process/resource
interfaces. The separate `qualify_runtime.py` avoids those interfaces and Unix
sockets for native CI on Linux/macOS/Windows; it is a smoke profile, not complete
platform acceptance. Controlled DoH testing additionally needs the pinned test
dependencies in `scripts/requirements-qualification.txt`. Standalone generation has its own [platform notes](using_mtls.md).

| Runner | Scope |
| --- | --- |
| `scripts/qualify.py` | Protocols, fleet observations, security, lifecycle, local load, and soak |
| `scripts/qualify_identity.py` | Disposable mTLS identities, path/destination isolation, and labels with quotas disabled |
| `scripts/qualify_quotas.py` | Configured session/tunnel caps, rate/bandwidth, cross-transport identity, and reverse cleanup |
| `scripts/qualify_revocation.py` | Live fingerprint/CN denial, active and idle session termination, TLS resumption, reverse and quota cleanup |
| `scripts/qualify_fleet.py` | Shared transport records, verified inventory, abrupt restart/key rotation, capacity, pagination, and database failures |
| `scripts/qualify_tenants.py` | Tenant roles/rule scope, reverse ownership and reserved binds, header spoofing, Unix paths, and combined quotas/revocation |
| `scripts/qualify_pool_timeout.py` | Delayed TLS establishment versus pool acquisition deadline |
| `scripts/qualify_hardening.py` | Domain confinement to restriction CIDRs, DNS rebinding, refused UDP retries, TCP and WebTransport handshake bounds, and descriptor exhaustion |
| `scripts/qualify_wan.py` | Expiring staging agent, native WAN clients, direct mTLS control, per-stream traces and client/server TCP diagnostics |
| `scripts/qualify_wan_endurance.py` | Periodic native WAN probes over a declared 24–72 hour window; separate cycle reports |
| `scripts/verify_endurance.py` | Completion receipt/service-exit verification, actual duration, and resource observations |
| `scripts/verify_wan_endurance.py` | Periodic WAN receipt, binary/result hashes, complete native matrix, cycle exits, and duration verification |
| `scripts/qualify_tproxy.py` | Privileged IPv4 and IPv6 TCP/UDP interception inside three disposable Linux network namespaces |
| `scripts/qualify_dns.py` | Controlled UDP DNS/DoT/DoH, address fallback, resolver-name denial and ECH edge cases |
| `scripts/qualify_runtime.py` | Native cross-platform TCP/reverse TCP/UDP smoke checks with verified mTLS |
| `scripts/qualify_reload.py` | Unix acknowledged/SIGHUP reload, live streams, atomic rejection, preserved quotas, tenant cleanup, and TCP/QUIC trust rotation |
| `scripts/qualify_device_scale.py` | Up to 256 distinct synthetic CN sessions, tenant tags, quotas, inventory and disconnect cleanup |
| `scripts/qualify_pki.py` | Distinct server key/issuer renewal, old-only trust denial, and rollback |
| `Dockerfile.qualification` | Python/OpenSSL container environment for the local runner |

The runner snapshots the supplied executable. Rebuilding the original path
during a run does not change that snapshot. Output directories must be new.

For managed reload, use `python3 scripts/qualify_reload.py --output
target/qualification/reload-review`. On a Linux host with a running user service
manager, add `--systemd-user` to test a uniquely named disposable user unit. It
checks that successful, rejected, and recovered `systemctl reload` operations
retain the main PID and an active stream, then stops only that test unit.
This does not qualify the production system unit's user/group, filesystem sandbox,
real issuer, or file permissions. Native CI exercises the socket/SIGHUP suite on
Linux and macOS; Windows remains covered by the portable baseline runtime suite.
Keep `metadata.json`, `results.json`, logs, resource samples, and hashes.
Suite/resource rows are included in counts; they are not all independent tests.

A failed assertion returns failure. A `not_run` row is a coverage gap even when
the process exits successfully. Some synthetic transport tests explicitly opt
out of server certificate verification for a disposable development identity;
dedicated security/identity/WAN cases verify TLS and mTLS.

## Bounded local regression

~~~sh
python3 scripts/qualify.py \
  --sections protocols,fleet,security,extended,isolation,lifecycle,rotation \
  --devices 32 --idle 32 --hold 2
python3 scripts/qualify_identity.py --output target/qualification/identity-review
python3 scripts/qualify_pool_timeout.py --output target/qualification/pool-review
python3 scripts/qualify_quotas.py --output target/qualification/quota-review
python3 scripts/qualify_revocation.py --output target/qualification/revocation-review
python3 scripts/qualify_fleet.py --output target/qualification/fleet-review
python3 scripts/qualify_tenants.py --output target/qualification/tenant-review
python3 scripts/qualify_hardening.py --output target/qualification/hardening-review
~~~

The hardening runner checks, on WS and on mTLS WSS, HTTPS, and WebTransport, that a
domain is only reached at resolved addresses inside a constraining restriction
CIDR, over TCP and UDP, that IPv4-mapped destinations follow IPv4 rules, and that a
refused UDP tunnel is attempted once per datagram. A loopback DNS responder that
changes its answer shows the checked address is the one dialed (Linux only, as it
uses 127.0.0.2). It verifies the TLS handshake timeout and the pending-handshake
limit while an established session keeps forwarding, on the TCP listener and on
the WebTransport listener, where authenticated QUIC peers that never send their
session request are closed with QUIC's own idle timeout disabled. That
WebTransport part needs an OpenSSL 3.5+ `s_client -quic`, selected with
`--openssl PATH`; without one it is recorded as `not_run`, or fails with
`--require-quic`. CI builds a pinned, SHA-256-verified OpenSSL 3.5 LTS into its
own cached prefix for this test client only, leaving the runner's system OpenSSL
untouched, and passes `--require-quic`. Then descriptor exhaustion
of the tunnel, management, and reverse listeners and of a client listener: CPU and
accept warnings stay bounded and service recovers once descriptors are released.

The identity runner verifies the two valid device identities, wrong target/path
denial, missing certificate, missing CN, and multiple-CN denial on WSS, HTTPS,
and WebTransport. It also observes 32 held tunnels and caller-supplied registry
labels. Its quota-enforcement row is `not_run` because that suite deliberately
omits quota configuration. The separate quota runner enables mTLS and checks
configured limits, shared accounting across all three TLS transports, independent
devices, key/label changes, failed setup, rate recovery, directional payload
shaping, proxy/UDP integrity, and reverse cancellation/resource ownership.
See [the quota contract](DEVICE_QUOTAS.md) for resource lifetimes and limitations.

The [revocation runner](DEVICE_REVOCATION.md) separately enables the live local
denylist. It tests certificate/key rotation, verified CN rather than caller labels,
idle sessions, all three transports, reverse teardown despite a long idle timeout,
unreadable/invalid policy recovery, TLS 1.2 resumption, and cancellation while
waiting for bandwidth credit. It does not establish CRL/OCSP integration or
policy distribution across replicas.

The [tenant runner](TENANT_ISOLATION.md) checks eleven scenarios: scoped forwarding
and trusted metadata across all three transports, unknown membership and header
spoofing, management-port protection, fixed/mapped reverse resources, device
ownership with tenant mode on and off, twelve port-zero protocol/transport
combinations, exact Unix paths, combined quotas/revocation/inventory, and invalid
startup configuration. It does not qualify management API tenant authentication,
OS/network isolation, distributed reservations, or production endurance.

The pool control delays encrypted TLS establishment by four seconds on loopback
without terminating TLS. At a three-second acquisition deadline, four exchanges
are expected to close with EOF and emit four pool timeouts. At twenty seconds,
the four exchanges are expected to complete. Those expected outcomes are two
passing control assertions, not four unexpected release failures.

Lifecycle cases exercise delayed data after directional FIN across heartbeat
intervals. Server rotation cases change the server certificate/CA and reject
invalid replacement files while retaining the usable configuration. They do not
establish client enrollment/key rotation, active-session revocation, or every
certificate-manager symlink layout.

## Capacity and shorter endurance profiles

~~~sh
python3 scripts/qualify.py --sections capacity,soak \
  --transports ws,wss,http,https,wts --devices 128 --idle 128 \
  --capacity-levels 16,64,128,256 --soak-seconds 300 --sample-seconds 5
~~~

Capacity tests use 16/64/128/256 concurrent stream connections by default across
forward/reverse TCP, SOCKS CONNECT, HTTP CONNECT, and Unix variants. They use
two 64 KiB exchanges per stream. UDP/reverse UDP use separate bounded peer loads.
Connection-plus-exchange latency is not pure RTT. Report application payload
throughput separately from offered load and total wire traffic.

The soak profile spreads `--idle` stream connections across eight features on
**each selected transport**, periodically exchanges data, checks UDP both ways,
and churns proxies. Review RSS, FDs, CPU, task exits, corruption, lost connections,
and cleanup. Sampling can miss short peaks. RSS retention alone does not prove
a leak; a rising FD count or failed data exchange needs investigation even if
`/healthz` responds.

Argument limits are bounded: idle 1..512, devices 1..128, hold 1..120 seconds,
soak 5..259200 seconds, and sample interval 1..60 seconds. Capacity levels must
be increasing unique integers in 1..512. Start lower on shared hosts.

## Isolated 24-hour staging-local job

Use a dedicated staging account/directory. Assess other workloads and available
headroom first. The following limits are an example test guard, not production
sizing. Run from the staging checkout containing the built binary and scripts:

~~~sh
systemd-run --user --unit=tunward-qualification-24h \
  --working-directory="$PWD" \
  --property=CPUQuota=50% \
  --property=MemoryHigh=512M --property=MemoryMax=768M \
  --property=MemorySwapMax=0 --property=TasksMax=512 \
  --property=RuntimeMaxSec=90000 --property=Nice=10 \
  /usr/bin/python3 scripts/qualify.py --binary target/release/tunward \
  --sections soak --idle 64 --soak-seconds 86400 --sample-seconds 30 \
  --output target/qualification/endurance-24h
~~~

This requests 64 mixed stream connections for each of five transports, 320
streams total, plus reverse waiters and UDP/churn traffic. Targets are staging
loopback. It is not a physical-device test or a 24-hour WAN run.

Check account/session policy before depending on a user service surviving logout;
systemd linger is an operator decision. Avoid reusing the same unit/output names
for another run. Monitor on staging:

~~~sh
systemctl --user show tunward-qualification-24h \
  -p ActiveState -p Result -p ExecMainStatus -p MemoryCurrent -p MemoryPeak
journalctl --user -u tunward-qualification-24h -n 20 --no-pager
~~~

An active unit, initial passing rows, or `Result=success` while still running
does not establish completion. Completion requires the intended duration,
successful process termination, no failed cases, and reviewed resource trends.
Before the first progress sample is published, the verifier reports an active
service as running with `results_present=false`; without an active service,
missing results remain incomplete.
New local runs write `completion.json` with exit state, duration, binary hash, and
results hash. `results.json` is replaced atomically so live readers avoid partial
JSON. For older runs without a receipt, the verifier requires a completed service
exit together with final duration and per-transport cleanup/recovery rows.
A manual stop, runtime kill, OOM, or truncated report is incomplete. Preserve
evidence before removing the test directory.

Verify the finished local job, or inspect it while running:

~~~sh
python3 scripts/verify_endurance.py target/qualification/endurance-24h \
  --unit tunward-qualification-24h --minimum-seconds 86400 \
  --output target/qualification/endurance-verdict.json
~~~

Exit 0 means completed evidence; 2 means still running; 1 means incomplete/failed.
The verifier reports first/last/max RSS, FD and CPU observations for review. These
observations do not automatically diagnose a leak or replace workload-specific
thresholds. A shortened test only proves its requested shorter duration.

## Native WAN agent and client

Use only an approved staging address and an expiring, resource-limited agent.
Before running examples, set `STAGING_IP` to its reachable IP. The agent opens
the chosen tunnel port on TCP/UDP and a direct mTLS control on the next TCP port.
Keep both ports free; preserve existing applications and firewall rules.

On staging, from the checkout:

~~~sh
python3 scripts/qualify_wan.py --agent \
  --binary target/release/tunward --output target/qualification/wan-agent \
  --address "$STAGING_IP" --port 44443 --seconds 600
~~~

The agent requires a disposable client certificate and restricts access to its
synthetic targets. Duration defaults to a bounded 1..900 seconds. An explicit `--long-run` permits
an expiring agent up to 262800 seconds for a 72-hour client window plus cleanup
margin. Apply matching supervisor runtime/resource limits and preserve the
manifest's expiry; do not leave an unbounded test listener running. Run it within an appropriate
resource-limited supervisor if it shares the host. It changes no firewall rules.
Do not reuse its CA or keys for deployed devices.

On the local client machine, set `STAGING_ALIAS` to an existing SSH alias and
`STAGING_REPO` to the absolute checkout path on that host:

~~~sh
python3 scripts/qualify_wan.py --remote "$STAGING_ALIAS" \
  --directory "$STAGING_REPO/target/qualification/wan-agent" \
  --agent-script "$STAGING_REPO/scripts/qualify_wan.py" \
  --output target/qualification/wan-review
~~~

SSH fetches the disposable client trust/identity material and triggers the
reverse probe. The stream payload uses the native tunnel, not an SSH port
forward. SSH-trigger duration is not reverse tunnel RTT. Keep the output private:
it contains disposable test key material as well as diagnostic evidence.

The normal profile covers WSS, HTTPS, and WebTransport with TCP, UDP, local
SOCKS/HTTP/Unix ingress, and reverse TCP. It does not test every reverse protocol
over WAN. Compare the direct mTLS control with the tunnel cases.

For the two historical burst failures, add
`--investigate --repeats 3 --pool-timeout 3`, then repeat with a fresh output
directory and `--pool-timeout 20`. Both use a twenty-second exchange budget by
default. Runs are sequential, so network conditions differ; a later pass does
not establish that a timeout increase fixed the earlier failure.

The qualification `--pool-timeout` option sets the client's existing
`--connection-retry-max-backoff`, which currently supplies bb8's acquisition
deadline. It does not change the product's default. The client records exchange
stage, duration, received bytes, and random synthetic stream IDs. The agent
records echo events, per-second TCP `ss -tin` snapshots, and cgroup CPU counters.

TCP retransmissions and congestion-window collapse support a path-level
diagnosis but do not identify a failing hop. Cumulative socket counters must not
be summed across repeated snapshots.

## Replacing a staging host

Retire the old host's run as completed, failed, or incomplete according to its
actual evidence. Keep its endpoint, binary hash, timestamps, and reports. A
reused SSH alias may now resolve to a different machine; the alias alone does
not identify the host on which a result was measured.

Check the replacement host's SSH host key, actual resolved endpoint, OS,
architecture, available CPU/RAM/disk, clock synchronization, existing services,
and approved test ports before starting work. Record this baseline privately.
Verify batch SSH access for unattended probes. Keep passwords out of repository
files, shell arguments, logs, and reports; authorize the operator's SSH public
key with reviewed restrictions when needed. Native WAN probes require remote
commands, not SSH port forwarding.

Transfer the intended source snapshot and binary without Git history or issuer
private keys from previous runs. Compare binary SHA-256 hashes at both ends and
verify that the binary runs on the new OS. Use a fresh private output directory
and disposable CA. Repeat a bounded local baseline, native WAN smoke profile,
and the relevant quota/revocation/tenant/inventory checks before starting a new
long window. Check that the agent expiry covers the whole client window and
cleanup margin.

Use resource-limited supervisors sized for the replacement host; assess the
aggregate limits of concurrent jobs and leave headroom for SSH and existing
services. Verify the applied limits, account linger policy, and external port
reachability. A changed host or network path requires new observations; a pass
there does not retrospectively explain a timeout on the retired host. Do not
merge separate hosts' durations or reuse old completion receipts.
Keep the absolute output path short: the WAN runner creates Unix sockets inside
each `cycle-NNNN` directory. [Linux pathname sockets](https://man7.org/linux/man-pages/man7/unix.7.html) have a 107-byte pathname
budget; include that suffix and the socket filename when selecting the root.
An overlong path can stop the client before native checks start. Preserve that
failed run, choose a shorter path, and begin a new window.
The WAN verifier compares each cycle's complete agent manifest with the initial
manifest. A replacement endpoint or restarted agent cannot pass as part of the
same window merely because it uses the same binary.

For a dual run, keep the staging-local soak and the WAN client in separate
resource-limited services. The WAN client runs on another machine, which must
remain powered on and connected for its full window. User linger can preserve
services after logout; it does not keep a suspended or powered-off machine
online, and transient services do not survive a reboot automatically. Schedule
verdict collection after the expected end and retain each verifier's output and
exit code. A running service or a scheduled verdict timer is not a completed test.

## Unattended WAN client

Run the client and its verdict collector on a separate always-on host when the
operator's laptop cannot remain online. Bootstrap access from the laptop, then
verify the client authenticates directly to staging without a laptop-held SSH
agent, control socket, proxy jump, or forwarded session. Keep a short private
output path and preserve an interrupted laptop run separately.

Generate a dedicated SSH key on the client host. Pin the staging host key and
limit the temporary credential to the exact disposable manifest/certificate
export, reverse probe, and soak-evidence commands. Use an expiry covering the
window and verdict margin, and schedule cleanup of that key. Keep personal
private keys on the operator's machine.

A dedicated test host is preferred. When a shared production host is explicitly
approved as the client, leave its application services, containers, data,
firewall, and routing alone. Bound the complete test subtree, including its
helpers, and give it lower scheduling and OOM priority than normal workloads.
The current conservative profile uses 5% of one CPU, 192 MiB maximum memory,
no swap, 128 tasks, idle CPU/I/O scheduling, OOM score adjustment 1000, and
group-wide test termination on OOM. These are test constraints, not capacity
promises or a guarantee of application availability.

A resource guard should stop only the test child when the host loses headroom.
The current profile requires at least 3 GiB available RAM, load1 no greater than
2.0, and 5 GiB free disk. Crossing a guard threshold ends the test without an
automatic retry or limit increase; preserve the guard report and incomplete
evidence. A successful probe under this profile does not measure production
application health, and provider-to-provider traffic does not replace real MDM
network tests.

If a guard stops a shared-host trial, stop its test timers and revoke its
dedicated credential when retiring the run. Keep production services and data
intact. Continue staging-local endurance independently; a dedicated client host
is needed for a new uninterrupted WAN window. Resource limits reduce interference
but do not guarantee that applications sharing a host will remain available.

Schedule verification and evidence retention on the always-on hosts themselves.
The laptop can then shut down without stopping their jobs. A host reboot,
resource guard, OOM, or network failure still prevents a completed window.

## WAN endurance and diagnostics

After validating the short agent/client run, an operator can start a supervised
agent with `--long-run --seconds 90000` for a 24-hour client window. Keep the same
mTLS-only synthetic target policy and separate output directory. Start the agent
just before the client window; the controller rejects an agent whose recorded
expiry cannot cover that window plus a five-minute margin. On the client:

~~~sh
python3 scripts/qualify_wan_endurance.py --remote "$STAGING_ALIAS" \
  --directory "$STAGING_REPO/target/qualification/wan-long-agent" \
  --agent-script "$STAGING_REPO/scripts/qualify_wan.py" \
  --seconds 86400 --interval 900 \
  --output target/qualification/wan-endurance-review
~~~

Use a resource-limited supervisor that survives logout on the actual WAN client,
not a client on the same staging host: a public-IP hairpin is not a representative
WAN route. The runner snapshots its binary and child scripts, shares verified binary copies
through hard links after cycles finish, and repeats the native feature profile.
It preserves each
cycle's failures, results hash, and exit status. `completion.json` is written atomically
after the declared duration or interruption handling. SIGINT/SIGTERM requests
stop the active child (including its process group on POSIX), reap it, and record an interrupted receipt with a nonzero
exit code. A crash or SIGKILL may leave no receipt and must not pass. A period containing
failed cycles is reported as failed. Review missing/truncated cycles and service
exit state as well as duration. Probe intervals leave unobserved gaps; this is
periodic synthetic WAN evidence, not continuous device availability or an MDM SLO.
Client sleep/network loss is part of that run's observed outcome.

~~~sh
python3 scripts/verify_wan_endurance.py target/qualification/wan-endurance-review \
  --minimum-seconds 86400 \
  --output target/qualification/wan-endurance-verdict.json
~~~

Exit 0 means the recorded periodic profile completed; exit 1 means failed or
incomplete evidence. Verification requires all 30 native checks in each cycle,
matching binary and results hashes, successful cycle exits, an intact final
receipt, and the requested duration. SSH setup errors count as failed cycles
even when no native check ran. Missing cycle files, duplicate check names,
unexpectedly long sampling gaps, or changed evidence prevent completion.
Receipts are local evidence, not signed attestations or production certification.
Review the documented probe gaps and workload independently.

The earlier supervised window stopped after about 68 minutes with one successful
cycle and four SSH setup failures; it has no completion receipt and is not a
completed 24-hour run. The current TLS dependency updates produce a different
binary, so that historical window cannot qualify the updated build either.

A later cycle failed before native cases because its SSH setup timed out.
Independent TCP connection checks to the approved SSH, tunnel, and direct-mTLS
control ports also timed out. Record this as a staging/connectivity outage and
an orchestration failure, separately from measured native stream failures. It
does not establish why the host became unreachable or whether its supervised
processes stopped. Recheck server status and final receipts when access returns.

The operator subsequently confirmed that staging was powered off. This explains
the current SSH unavailability; it does not establish when earlier connectivity
failures began or the cause of the historical WSS stream timeout. Resume with a
fresh matching agent/client binary and a new evidence directory after staging
is available. Preserve the interrupted run instead of merging separate windows
into a supposed continuous 24-hour result.

Normal WAN stream tests now record stream IDs, operation stage, timing, received
bytes and errors, with client and agent TCP snapshots for correlation. The
historical WSS event lacks contemporaneous trace evidence; later successful
repeats cannot retrospectively identify its exact cause. Do not increase a
budget and call the old event fixed without comparing traces and direct controls.

## Additional controlled profiles

~~~sh
python3 -m venv target/qualification/dns-tools
target/qualification/dns-tools/bin/python -m pip install -r scripts/requirements-qualification.txt
target/qualification/dns-tools/bin/python scripts/qualify_dns.py --output target/qualification/dns-review
python3 scripts/qualify_runtime.py --output target/qualification/runtime-review
python3 scripts/qualify_device_scale.py --devices 200 --output target/qualification/device-scale-review
sudo python3 scripts/qualify_tproxy.py --output target/qualification/tproxy-review
~~~

The TProxy runner creates client/proxy/server network namespaces with veth peers
entirely inside them, applies nftables and policy routes only inside the proxy
namespace, keeps IP forwarding disabled, and removes its namespaces/processes
on ordinary completion or handled termination. It requires Linux root and the
kernel TProxy facilities. Preserve its metadata and check cleanup after an
unhandled kill. It exercises IPv4 and IPv6 original-destination routing and
reply-source integrity over all three TLS transports, with the tunnel itself over
IPv4; it does not qualify your host's firewall/routing, or every
capability-restricted container layout.
Root-owned output directories need an explicit operator-controlled ownership
handoff before non-root artifact collection; never broaden key readability.

Controlled DNS tests use UDP DNS, authenticated DoT and DoH, IPv4-only/dual-address
responses, NXDOMAIN, and resolver-name mismatch. A pre-fix WebTransport failure
was reproduced for all three resolvers when a stalled IPv6 attempt consumed the
short pool deadline before IPv4. The client now races up to four resolved
addresses with a 250 ms stagger inside the connection timeout; the same three
cases passed afterward. This is bounded fallback, not a claim of full RFC 8305
implementation or qualification of every real resolver/network.

ECH cases explicitly distinguish configuration lookup from successful encryption.
The current TCP option can fall back without ECH when an HTTPS record contains
no usable ECH configuration. Missing HTTPS data can fail initialization; WTS
rejects the ECH option. The controlled tests do not prove accepted ECH, SNI
privacy, or compatibility with a real CDN. Qualify the organization's own actual
CDN/domain, TLS termination model, mTLS propagation and streaming behavior before
using that route. A third-party TLS terminator cannot supply tunward's verified
client identity merely through forwarded headers.

The synthetic scale runner holds 200 distinct verified CN TLS sessions by default
and checks tenant metadata, one-session quota rejection, inventory, and cleanup.
It does not perform 200 WebSocket upgrades or application tunnels and does not
represent physical devices. Other profiles separately cover native application
features and stream capacity. Keep those workloads and counts separate.

Native Linux smoke results are available locally. CI/release now require the
portable runner on Linux, macOS and Windows; configuration alone is not a
successful remote run. Android, FreeBSD, architecture-specific runtimes, and
deployment-specific CDN/ECH remain separate gates.

The first beta CI run passed native Linux and Windows but failed on macOS while
loading the test client CA (`ExtensionValueInvalid`). The fixture combined
host-default extensions with `req -addext`; OpenSSL 1.1.1 can append duplicate
extensions instead of replacing them. The runner now uses its own explicit
`-config`/`-extensions` sections for the CA and CSRs and checks chains and
certificate purposes with `verify -x509_strict` before starting tunnels.
Metadata records the OpenSSL version, and preparation failures produce a
`runtime/setup` failure report. The native matrix also tests generation with
conflicting ambient OpenSSL extensions. A passing run on the corrected commit
is still required for each OS; the fixture fix does not qualify every feature.
See the [OpenSSL request options](https://docs.openssl.org/master/man1/openssl-req/)
for configuration and extension-section selection.

Native CI evidence is written under the runner temporary directory with a
run/attempt-specific name, outside the cached Cargo target tree. This avoids
`FileExistsError` after a build-cache restore and prevents new native fixture
keys/results from being saved in that cache. Local runners still refuse an
existing `--output` directory: choose a fresh path to preserve earlier evidence.
The Linux protocol/security qualification job likewise gives every profile a
fresh path under its run/attempt temporary root, including privileged TProxy.
CI removes the legacy `target/qualification` subtree after restoring Rust caches
so old fixture keys/results are not reused or saved again. This cleanup runs
only in disposable CI workspaces, not inside local qualification scripts.

Some hosts, including the macOS 14 CI runner, reject the 40000-byte UDP send
with `EMSGSIZE` before it enters the tunnel. Only for that explicit send error,
the runner retries with 8192 bytes and records the 40000-byte case as `not_run`
for that transport. Other errors still fail. A successful reduced-size exchange
proves bounded UDP forwarding, not large-datagram support on the restricted host;
the runner does not change system UDP limits.

## Physical-device working-hours acceptance

When devices are available, select representative OS/versions, network providers,
and MDM policies. Issue distinct per-device identities and use a disposable
staging tenant with measured limits. Inventory must match verified CNs, with
caller labels treated only as labels. Record actual device count separately
from processes, sessions, tunnels, and synthetic identities.

For each enabled transport and feature, verify data integrity and policy denial,
then test sleep/wake, Wi-Fi/mobile changes, NAT expiry, reconnect bursts, server
restart, certificate/key renewal, live revocation and quota recovery. Include
battery/background restrictions and MDM rollout/rollback. Increase participation
in measured stages, retaining latency/error/resource evidence and an agreed
stop threshold. Complete the intended 24–72 hours before signing off; a scheduled
job or one business-hours smoke run does not establish endurance.

## Container feature checks

`Dockerfile.qualification` is a test environment, separate from the product
Dockerfile. Build with an empty context and mount the exact binary/scripts
read-only. The host output path must be writable by container UID 1000:

~~~sh
docker build -t tunward-qualification - < Dockerfile.qualification
mkdir -p target/qualification/docker
docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --user 1000:1000 \
  --memory=512m --memory-swap=512m --cpus=0.5 --pids-limit=256 \
  --mount "type=bind,src=$PWD/target/release/tunward,dst=/tunward,readonly" \
  --mount "type=bind,src=$PWD/scripts,dst=/scripts,readonly" \
  --mount "type=bind,src=$PWD/target/qualification/docker,dst=/output" \
  tunward-qualification --binary /tunward --output /output/container-run \
  --sections protocols,security,extended,isolation,lifecycle,rotation,soak \
  --idle 32 --hold 1 --soak-seconds 15
~~~

For Podman, adapt runtime permissions, UID mapping, and API setup as appropriate;
see [contributing](../CONTRIBUTING.md#docker-and-podman-integration-tests).
Do not change key files to world-readable as a workaround for UID mismatches.

This profile exercises the container's own loopback network. It does not
establish host port publication, runtime secret delivery, image reproducibility,
or restart/rotation behavior with a different mount layout. Keep image IDs and
installed package versions with the evidence.

## Recorded investigation and unresolved work

The 2026-10-20 follow-up reproduced the historical HTTPS EOF pattern using the
three-second pool deadline and delayed TLS control. Twelve targeted WAN bursts
completed 192/192 exchanges, including 96 WSS and 96 HTTPS exchanges. Direct mTLS
was also slow and TCP diagnostics showed retransmission. The historical single
WSS twenty-second timeout was not reproduced or conclusively explained; do not
label it fixed solely because later runs passed.

The same follow-up verified the CN fail-closed patch with 25 passing
identity/observation rows and one unsupported quota row. These counts describe
that binary and workload, not a standing certification for subsequent builds.
Reports and binary/source hashes are local qualification artifacts under
`target/qualification/`; they are not bundled private staging configuration.
No completed 24-hour WAN result is established by these measurements.

Before wider deployment, define latency, availability, error, and recovery
objectives; measure on the intended network/hardware with headroom; complete and
review endurance; and qualify real-device reconnect/sleep behavior. Resolve the
required identity mapping and revocation semantics. Qualify the optional
[tenant roles and reserved resources](TENANT_ISOLATION.md) against each group
and deploy stronger host/network boundaries where needed. Configure
and qualify the optional device quotas for the intended workload; they do not
coordinate replicas or persist accounting across restart. Registry counters are
not those verified-identity quota accounts.

Privileged TProxy, deployment-specific DNS/ECH/CDN behavior, non-Linux runtime
coverage, and certificate-manager-specific layouts need separate qualification.
Do not equate a supported parser option or release target with a completed test.

## Reference contracts

- [bb8 acquisition deadline](https://docs.rs/bb8/0.9.1/bb8/struct.Builder.html#method.connection_timeout)
- [Rustls client verification and CRLs](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)
- [Quinn server configuration replacement](https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.set_server_config)
- [systemd resource limits](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
- [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)
- [Testcontainers Docker/Podman configuration](https://github.com/testcontainers/testcontainers-rs/blob/main/docs/features/configuration.md)
