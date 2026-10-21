---
name: Need help
about: Ask for help after checking the current guides
title: ''
labels: help wanted
---

Read the [README](../../README.md),
[mTLS guide](../../docs/using_mtls.md), and
[qualification guide](../../docs/STAGING_QUALIFICATION.md) first. This source
tree requires protocol-v2-compatible peers.

## Goal

Describe what you want to connect and which machine hosts the listener, tunnel
server, and final destination. Include forward/reverse direction and URL scheme.

## Commands and versions

Provide sanitized client/server commands, versions/commits, and OS/architecture.
If containerized, identify Docker or Podman and the relevant port mappings.
Remove credentials, secret path prefixes, private keys, and customer identifiers.

## What happens

Include the exact error and a short reviewed log excerpt. Explain whether the
problem occurs during TLS, proxy negotiation, target connection, data transfer,
or cleanup. State what already works without the tunnel.

## Checks already performed

- Both peers implement the same wire protocol.
- The target is reachable from the correct side of the tunnel.
- The server SAN matches the domain/IP used by the client and its CA is trusted.
- For mTLS, client CN and path prefix agree and restrictions permit the request.
- For WebTransport, UDP is reachable on the server port as well as TCP.
- If tests use Podman, DOCKER_HOST points to that user's active Podman API socket.
- With WireGuard/VPN routing, the tunward server remains reachable outside the
  tunnel to avoid routing recursion.

A reachable management /healthz endpoint proves only that API response, not
end-to-end tunnel or device health. Do not disable certificate verification as a
production fix.
