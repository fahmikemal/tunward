# Measuring core forwarding performance

Use `scripts/profile_core.py` for bounded Linux loopback measurements of the
existing TCP, SOCKS5, HTTP CONNECT and UDP paths. It uses disposable, verified
mTLS identities on WSS, HTTP/2 and WebTransport, checks the returned payload,
and records CPU, RSS, descriptors, threads, cgroup CPU throttling and latency.
It changes no firewall rules and contacts no external targets.

~~~sh
cargo build --release --locked -p tunward-cli
python3 scripts/profile_core.py --output target/qualification/performance-core --direct
python3 scripts/profile_core.py --output target/qualification/performance-proxies \
  --modes forward-socks,forward-http,reverse-tcp,reverse-socks,reverse-http \
  --levels 1,16 --seconds 3 --repeats 2
python3 scripts/profile_core.py --output target/qualification/performance-udp \
  --modes forward-udp,reverse-udp --levels 1,16,64 --seconds 3 --repeats 2 --direct
~~~

Output directories must be new. The runner snapshots the supplied executable,
binds its source/helper hashes at startup, and fails if those files change
during measurement. Review a completed exit-zero `completion.json`, its binary
and result hashes, all result rows and the host configuration together. A failed
payload or connection assertion fails the run; poor throughput is recorded
rather than silently converted into a passing performance guarantee.

The default profile uses one I/O worker per tunward process, a one-second
heartbeat, no idle connection pool, and **disabled device quotas** to observe
the forwarding path without admission/bandwidth ceilings. TLS verification,
client authentication and explicit loopback destination restrictions stay on.
Persistent inventory is not enabled. Choose `--workers 2` for a separate worker
sensitivity run. Keep these settings in the report; changing them changes the
workload, not just its presentation.

To measure the default quota policy separately:

~~~sh
python3 scripts/profile_core.py --output target/qualification/performance-default-quotas \
  --quotas default --levels 1 --seconds 5 --repeats 2
~~~

Default quotas deliberately limit sessions, request rate and payload bandwidth.
Do not mistake an enforced policy ceiling for a transport bottleneck. The
runner limits this profile to sixteen concurrent streams to avoid deliberately
exceeding the default admission limit.

## Reading the measurements

- Each connection performs an untimed first exchange before bulk measurement.
  Setup percentiles include proxy negotiation, transport establishment and that
  exchange. Bulk percentiles cover every later request/reply with nearest-rank
  quantiles; a low sample count cannot establish a tail-latency objective.
- The default stream payload is 64 KiB; UDP uses 1,200 bytes. Bulk roundtrip
  includes payload transfer and scheduling. It is not network RTT.
- Goodput counts verified application bytes in **one direction**. The echo
  returns the same bytes, so total application traffic in both directions is
  twice that number. It excludes TLS/QUIC/proxy overhead and is not wire rate.
- CPU percentages use 100% for one core. Record server, client and harness
  separately. A saturated generator or exhausted cgroup quota can limit the
  result. Direct TCP/UDP controls use the same Python echo harness.
- RSS/FD/thread peaks are sampled every 50 ms; shorter peaks may be missed.
  `peak_rss_kib` is the kernel's process-lifetime high-water mark, not a reset
  per-case peak. UDP mappings can remain until their configured idle timeout.
- Repeats rotate transport order. Compare medians and dispersion with controls,
  then reproduce an apparent bottleneck before changing runtime code.

These measurements describe a supplied binary and workload on a shared local
host. They do not establish WAN behavior, physical-device capacity, production
maximum throughput, a memory-leak result, or an availability/latency SLO. Keep
the existing protocol, security, cleanup and endurance qualification alongside
any optimization.
