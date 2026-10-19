# Contributing to Tunward

Thank you for your interest in contributing to Tunward. This document outlines development setup, quality checks, and contribution workflows.

## Prerequisites

- **Rust toolchain:** Rust 1.97 or later (Rust 2024 edition).
- **Test runner:** [cargo-nextest](https://nexte.st) (`cargo install cargo-nextest --locked`).
- **TOML formatter:** [taplo-cli](https://taplo.tamasfe.dev) (`cargo install taplo-cli --locked`).
- **Docker:** Optional, needed only for integration tests that spin up proxy fixtures (e.g. mitmproxy).

## Task Runners

The repository includes configuration for both `just` and `mise`. You can use either tool:

### With `just`
```bash
just fmt          # Formats Rust code (cargo fmt) and TOML files (taplo fmt)
just test         # Runs test suite with cargo nextest
just linter_fix   # Runs cargo clippy --fix
```

### With `mise`
```bash
mise run test         # Runs test suite
mise run linter-fix   # Runs cargo clippy --fix, followed by cargo fmt
```

## Local Validation Checklist

Our CI enforces formatting, static analysis, security audits, and tests on every push and pull request. Run these commands locally before submitting a PR:

```bash
# 1. Format check
cargo fmt --all -- --check
taplo fmt --check

# 2. Static analysis and lints
cargo clippy --all --all-features --locked -- -D warnings

# 3. Test suites (tested separately per crypto provider)
cargo nextest run --locked
cargo nextest run --locked --no-default-features --features ring
```

### Crypto Provider Testing Note

The test suite runs once for each crypto provider:
- `aws-lc-rs` (default): Used on x86_64 and aarch64 Linux, macOS, and Windows.
- `ring`: Used on armv7, armv6, FreeBSD, and 32-bit Windows targets.

Do not run tests with `--all-features`. Passing `--all-features` activates both `aws-lc-rs` and `ring` simultaneously, which causes runtime panics because the underlying token libraries treat them as mutually exclusive.

## Secret Scanning

Tunward uses Gitleaks in CI to prevent credential leaks. If your changes add configuration or test fixtures, verify locally that they pass without triggering false positives:

```bash
gitleaks detect --source=. --config=.gitleaks.toml
```

Any intentional mock certificates or non-sensitive test keys must be added to `.gitleaks.toml`.

## Git and Release Workflow

- **Branching:** Base all feature branches and bugfixes on `main`.
- **Commit Messages:** Follow [Conventional Commits](https://www.conventionalcommits.org/) (for example: `feat(transport): add ...`, `fix(server): resolve ...`, `chore(deps): update ...`).
- **Releases:** Releases are automated via GitHub Actions and trigger only when version tags (`v*`) are pushed. Regular branch pushes only run CI checks and scans.

## Reporting Issues

Please file bug reports and feature requests using our [issue templates](.github/ISSUE_TEMPLATE). Include complete reproduction steps, client/server flags, operating system, and relevant logs.
