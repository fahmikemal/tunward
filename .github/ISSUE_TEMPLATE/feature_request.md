---
name: Feature request
about: Propose a concrete capability and its expected behavior
title: ''
labels: enhancement
---

## Problem

Describe the task that cannot be completed with the current behavior.

## Proposed behavior

Give a concrete input/configuration and expected output or lifecycle. Identify
the relevant transports, local protocols, and supported OS targets.

## Current alternatives

Describe existing options you tried and why they do not meet the need.

## Scope and acceptance criteria

List the behavior that would demonstrate success. For fleet features distinguish
a caller-supplied label from authenticated device identity. For quotas specify
the unit, per-device/global scope, admission and release behavior, and whether
limits must hold across server replicas.

For performance changes specify the workload, concurrency, duration, error
budget, and latency/throughput target. Avoid a device-count target without a
workload and hardware/network description.

## Compatibility and security

Describe migration, rollback, trust/authorization changes, and effects on
existing client/server pairs. Use SECURITY.md for undisclosed vulnerabilities.
Do not include private keys, credentials, or customer identifiers.
