# Production Observability and Prometheus Monitoring

Tunward provides built-in Prometheus and OpenMetrics telemetry through its loopback REST Management API.

## Endpoints

When Tunward is started with the management API enabled (for example `--management-api 127.0.0.1:8081`):

| Endpoint | Method | Format | Description |
| :--- | :--- | :--- | :--- |
| `/metrics` | `GET` | `text/plain` | Prometheus / OpenMetrics scrape endpoint |
| `/healthz` | `GET` | `application/json` | Health check probe (Kubernetes liveness/readiness) |
| `/api/v1/clients` | `GET` | `application/json` | Live active client registry list |
| `/api/v1/sessions` | `GET` | `application/json` | Live authenticated tunnel sessions |
| `/api/v1/connections` | `GET` | `application/json` | Live transport connections (WSS/H2/WTS) |
| `/api/v1/devices` | `GET` | `application/json` | Persistent fleet inventory observation query |

> [!IMPORTANT]
> The management API binds strictly to loopback (`127.0.0.1` or `::1`) by design. To scrape it from a remote Prometheus server, either run a node agent (such as Prometheus Agent, Grafana Alloy, Vector, or Datadog) on the host, or forward it through an authenticated reverse proxy (e.g. mutual TLS or WireGuard).

## Metrics Reference

The `/metrics` endpoint exports the following gauges and counters:

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `tunward_health_status` | Gauge | `1` if server is healthy, `0` if in degraded or error state |
| `tunward_uptime_seconds` | Counter | Total server process uptime in seconds |
| `tunward_active_clients` | Gauge | Current number of active client connections |
| `tunward_active_sessions` | Gauge | Current number of active authenticated tunnel sessions |
| `tunward_active_connections` | Gauge | Current number of active network transport connections |
| `tunward_active_tunnels` | Gauge | Current number of active forward and reverse tunnels |
| `tunward_active_devices` | Gauge | Current number of distinct active verified mTLS devices |
| `tunward_inventory_healthy` | Gauge | `1` if SQLite fleet inventory database is healthy and writable, `0` otherwise |
| `tunward_build_info` | Gauge | Build information with `version` label, always `1` |

## Example Prometheus Scrape Configuration

Add the following job to `/etc/prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'tunward'
    scrape_interval: 15s
    scrape_timeout: 5s
    static_configs:
      - targets: ['127.0.0.1:8081']
    metrics_path: '/metrics'
```

## Recommended Production Alerting Rules

Create `/etc/prometheus/rules/tunward_alerts.yml`:

```yaml
groups:
  - name: tunward_alerts
    rules:
      - alert: TunwardServerDown
        expr: up{job="tunward"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Tunward instance {{ $labels.instance }} is unreachable"
          description: "Prometheus cannot scrape Tunward management API."

      - alert: TunwardHealthDegraded
        expr: tunward_health_status == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "Tunward health status reported unhealthy on {{ $labels.instance }}"
          description: "Internal health check failed. Review server systemd logs immediately."

      - alert: TunwardInventoryFailure
        expr: tunward_inventory_healthy == 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Tunward device inventory database is degraded on {{ $labels.instance }}"
          description: "SQLite inventory write/lock failure detected. New verified devices cannot be recorded."

      - alert: TunwardHighTunnelCount
        expr: tunward_active_tunnels > 5000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Tunward high tunnel load on {{ $labels.instance }}"
          description: "Active tunnels exceeded 5000 (currently {{ $value }}). Verify file descriptor limits."
```
