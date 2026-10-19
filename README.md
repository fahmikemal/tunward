# Tunward

Fast and secure reverse and forward tunneling over WebSocket, HTTP/2, and WebTransport (QUIC), written in Rust.

[![CI](https://github.com/fahmikemal/tunward/actions/workflows/ci.yaml/badge.svg)](https://github.com/fahmikemal/tunward/actions/workflows/ci.yaml)
[![Release](https://github.com/fahmikemal/tunward/actions/workflows/release.yaml/badge.svg)](https://github.com/fahmikemal/tunward/actions/workflows/release.yaml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## Overview

When connecting systems across the internet or through restricted corporate networks, direct inbound TCP and UDP connections are frequently blocked by firewalls and NAT gateways. Standard web traffic over ports 80 and 443, however, is almost universally allowed.

Tunward encapsulates network traffic inside standard WebSocket, HTTP/2, or WebTransport protocols. It lets you forward ports, establish reverse proxies, route UDP packets, or spin up dynamic SOCKS5 proxies across restrictive network boundaries without needing VPN software or public IP addresses on the client machine.

### Key Capabilities

- **Multiple Transports:** WebSocket (recommended for maximum throughput), HTTP/2, and WebTransport (HTTP/3 over QUIC).
- **Static Forward Tunneling (`-L`):** Forward local ports to remote services (TCP, UDP, Unix sockets, Stdio).
- **Dynamic Forward Tunneling (`-L`):** Run local SOCKS5 proxies, HTTP CONNECT proxies, or transparent TProxy (Linux).
- **Reverse Tunneling (`-R`):** Expose local ports and services through the remote server (TCP, UDP, SOCKS5, HTTP proxy, Unix socket).
- **Authentication and Hardening:** Path prefix token verification, mutual TLS (mTLS) with live certificate reloading, and granular destination allowlists (`--restrict-to`, `restrictions.yaml`).
- **Stealth and Evasion:** Custom SNI overrides, Encrypted Client Hello (ECH), and proxy protocol support.
- **Single Static Binary:** Self-contained with zero runtime dependencies across Linux, macOS, Windows, Android, and FreeBSD.

---

## Installation

### Pre-built Binaries

Download pre-compiled binaries for your platform from the [Releases](https://github.com/fahmikemal/tunward/releases) page:

- **Linux:** `x86_64`, `aarch64`, `armv7`, `armv6`, `i686` (musl-based static binaries)
- **macOS:** `x86_64` (Intel), `aarch64` (Apple Silicon)
- **Windows:** `x86_64`, `aarch64`, `i686`
- **Android:** `aarch64`, `armv7` (usable via Termux or standalone shell)
- **FreeBSD:** `x86_64`, `i686`

### Docker Container

Official container images are available on GitHub Container Registry:

```bash
docker pull ghcr.io/fahmikemal/tunward:latest
```

### Build from Source

Ensure you have Rust 1.97 or later installed:

```bash
git clone https://github.com/fahmikemal/tunward.git
cd tunward
cargo build --release --bin tunward
./target/release/tunward --help
```

---

## Quickstart and Common Recipes

### 1. Reverse Web Tunnel (ngrok alternative)

Expose a web service running locally on port `3000` to a public server on port `8000`:

**On your public server:**
```bash
tunward server ws://0.0.0.0:8080
```

**On your local machine:**
```bash
tunward client -R tcp://0.0.0.0:8000:localhost:3000 ws://server.example.com:8080
```

Visitors connecting to `http://server.example.com:8000` will be forwarded directly to your local service on port 3000.

---

### 2. Dynamic SOCKS5 Proxy

Browse the internet through your remote server's network connection:

**On the remote server:**
```bash
tunward server wss://0.0.0.0:443
```

**On your local machine:**
```bash
tunward client -L socks5://127.0.0.1:1080 --connection-min-idle 5 wss://server.example.com:443
```

Configure your browser or application to use SOCKS5 proxy `127.0.0.1:1080` (ensure DNS resolution is set to resolve remotely).

---

### 3. SSH ProxyCommand

Use Tunward as a jump mechanism inside your `~/.ssh/config` to access servers hidden behind NAT:

```text
Host my-private-server
    User deploy
    ProxyCommand tunward client --log-lvl=off -L stdio://%h:%p ws://gateway.example.com:8080
```

Then connect normally:
```bash
ssh my-private-server
```

---

### 4. Obfuscate WireGuard UDP Traffic

Encapsulate WireGuard VPN traffic inside an HTTPS WebSocket connection to bypass restrictive firewalls:

**On your remote server (with WireGuard on port 51820):**
```bash
tunward server --restrict-to localhost:51820 wss://0.0.0.0:443
```

**On your local machine:**
```bash
tunward client -L "udp://51820:localhost:51820?timeout_sec=0" wss://server.example.com:443
```

In your WireGuard client configuration (`wg0.conf`), set `Endpoint = 127.0.0.1:51820`.

---

### 5. Securing the Server with Path Prefix Tokens

Protect your server endpoint so only authorized clients can initiate tunnels:

**On the server:**
```bash
tunward server --restrict-http-upgrade-path-prefix "K9x7vN2mP5qR" wss://0.0.0.0:443
```

**On the client:**
```bash
tunward client --http-upgrade-path-prefix "K9x7vN2mP5qR" -L socks5://127.0.0.1:1080 wss://server.example.com:443
```

Requests that do not supply the matching upgrade path prefix will be rejected immediately during the handshake.

---

### 6. WebTransport over QUIC (HTTP/3)

If TCP traffic is throttled or lossy, use WebTransport over UDP:

**On the server (opens UDP on the specified port):**
```bash
tunward server wts://0.0.0.0:8080
```

**On the client:**
```bash
tunward client -L socks5://127.0.0.1:1080 wts://server.example.com:8080
```

*Note: WebTransport requires UDP traffic to be reachable end-to-end and mandates TLS 1.3.*

---

## CLI Reference

### Client Syntax

```text
Usage: tunward client [OPTIONS] <ws[s]|http[s]|wts://server[:port]>
```

| Option | Description |
| :--- | :--- |
| `-L, --local-to-remote <SPEC>` | Forward local listener to remote target (`tcp://`, `udp://`, `socks5://`, `http://`, `stdio://`, `unix://`). |
| `-R, --remote-to-local <SPEC>` | Listen on server and forward incoming traffic to local machine. |
| `-p, --http-proxy <URL>` | Connect to server through an intermediate HTTP CONNECT proxy. |
| `-P, --http-upgrade-path-prefix <TOKEN>` | Custom path prefix used during upgrade request (authentication secret). |
| `-c, --connection-min-idle <INT>` | Maintain idle connection pool to accelerate tunnel setup. |
| `--tls-verify-certificate` | Enable strict TLS certificate validation (off by default for self-signed setups). |
| `--tls-certificate / --tls-private-key` | Client certificate and key for mutual TLS (mTLS) authentication. |
| `--tls-sni-override <DOMAIN>` | Override SNI hostname during TLS handshake. |
| `--log-lvl <LEVEL>` | Set log verbosity (`TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, `OFF`). |

### Server Syntax

```text
Usage: tunward server [OPTIONS] <ws[s]|wts://0.0.0.0[:port]>
```

| Option | Description |
| :--- | :--- |
| `--enable-webtransport` | Also listen on UDP for WebTransport (HTTP/3) clients on the same port. |
| `-r, --restrict-http-upgrade-path-prefix <TOKEN>` | Require matching path prefix secret before accepting tunnels. |
| `--restrict-to <HOST:PORT>` | Restrict destinations clients are allowed to connect to. |
| `--restrict-config <FILE>` | Path to YAML file defining fine-grained access rules. |
| `--tls-certificate / --tls-private-key` | Custom TLS certificates (auto-reloads on file change). |
| `--tls-client-ca-certs <FILE>` | CA bundle to enforce mTLS client certificate verification. |
| `--websocket-ping-frequency <DUR>` | Keepalive ping interval (default: `30s`). |

---

## License

Tunward is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.
