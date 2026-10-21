---
name: Bug report
about: Report reproducible behavior with sanitized evidence
title: ''
labels: bug
---

<!-- For vulnerabilities, use SECURITY.md instead of a public issue. Never attach private keys or credentials. -->

## Observed behavior

Describe the failure and the operation that triggers it.

## Expected behavior

Describe the expected result.

## Reproduction

Provide minimal steps using synthetic services. Include sanitized client/server
commands, listener and target locations, and whether this is forward or reverse.
Replace credentials, secret path prefixes, and device/customer identifiers.

## Versions and environment

- Client version, commit or binary SHA256:
- Server version, commit or binary SHA256:
- OS/architecture for both:
- Transport URL scheme: ws / wss / http / https / wts
- Container runtime, if any: Docker / Podman / other
- Reverse proxy, VPN, NAT, or relay:
- TCP/UDP reachability relevant to the chosen transport:

## TLS and restrictions

- Server verification enabled:
- Server certificate SAN matches the connection domain/IP:
- mTLS enabled; sanitized client CN/path relationship:
- Relevant restriction rules, without secrets:
- For WebTransport, UDP port published/reachable:

Do not attach CA, server, or device private keys.

## Evidence

Paste a short sanitized log excerpt and the exact error. DEBUG logs can contain
metadata: review them first. For qualification results include the binary hash,
case name, timeouts, concurrency, and pass/fail/not_run status. State whether the
problem reproduces on a fresh run; do not report an active endurance job as a pass.

## Additional context

Describe recent certificate, network, configuration, or binary changes.
