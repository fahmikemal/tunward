# Contributing

Use this guide with the source version you are changing. The workspace is
`0.1.0-beta`, and tunnel protocol v2 is incompatible with older peers.
Keep documentation, client/server behavior, and migration instructions together.

## Environment

CI pins Rust 1.97 and uses edition 2024. No separate minimum supported Rust
version is declared in the manifests. Install the native toolchain/build
dependencies required by your target and TLS provider; the Linux container build
installs CMake and libclang.

The workspace contains the `tunward` library and `tunward-cli` binary crate:

~~~sh
cargo build --release --locked -p tunward-cli
./target/release/tunward --version
./target/release/tunward client --help
./target/release/tunward server --help
~~~

Python 3 and OpenSSL are required for certificate generation and qualification
scripts. Container-backed Rust integration fixtures require a Docker-compatible
API, access to the chosen engine, and available fixture images.

## Docker and Podman integration tests

With Docker, use its running daemon and socket. You do not need a second Docker
daemon when your environment already supplies a working compatible Podman API.

On Linux with rootless Podman and a systemd user session:

~~~sh
systemctl --user enable --now podman.socket
export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
cargo test --workspace --locked
~~~

Check `XDG_RUNTIME_DIR` and the socket path for the user actually running the
tests. An absent `docker.sock` does not establish a test failure when
`DOCKER_HOST` correctly points to Podman. A CLI `--version` check alone does
not prove API access or container-fixture behavior.

See [Testcontainers configuration](https://github.com/testcontainers/testcontainers-rs/blob/main/docs/features/configuration.md).
The Python loopback qualification runner does not need Docker; the explicit
container qualification profile does.

## Checks

Install the tools used by CI when needed:

~~~sh
cargo install cargo-nextest --locked
cargo install taplo-cli --locked
~~~

Run:

~~~sh
cargo fmt --all -- --check
taplo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --locked
cargo nextest run --workspace --locked --no-default-features --features ring
~~~

`cargo test --workspace --locked` is an alternative to nextest. Test providers
separately: default `aws-lc-rs`, then `ring` with default features disabled.
Do not use all-feature runtime tests as a substitute; they enable both TLS
providers. All-feature Clippy compiles code and is a separate check.

For protocol, authentication, lifecycle, or resource changes, build the release
binary and run the relevant executable qualification sections:

~~~sh
cargo build --release --locked -p tunward-cli
python3 scripts/qualify.py --sections protocols,fleet,security,extended,isolation,lifecycle,rotation
python3 scripts/qualify_identity.py --output target/qualification/identity-review
python3 scripts/qualify_pool_timeout.py --output target/qualification/pool-review
python3 scripts/qualify_quotas.py --output target/qualification/quota-review
python3 scripts/qualify_revocation.py --output target/qualification/revocation-review
python3 scripts/qualify_fleet.py --output target/qualification/fleet-review
python3 scripts/qualify_tenants.py --output target/qualification/tenant-review
python3 scripts/qualify_pki.py --output target/qualification/pki-review
python3 scripts/qualify_runtime.py --output target/qualification/runtime-review
python3 scripts/check_publication.py
~~~

Output directories must be new. Preserve failures, `metadata.json`,
`results.json`, logs, and binary hashes. A `not_run` row is not coverage.
Use the [qualification guide](docs/STAGING_QUALIFICATION.md) for bounded capacity,
container, WAN, and endurance profiles. Historical results do not qualify a new
binary automatically.

## Task runners and legacy scripts

`mise.toml` defines `test`, `linter-fix`, dependency maintenance, benchmark,
and release tasks. For example:

~~~sh
mise run test
~~~

Read maintenance/release tasks before using them: some update dependencies or
commit, tag, and push. This checkout does not contain a `justfile`; the direct
commands above are the reference.

`scripts/bench.sh` is a separate iperf3/perf helper, not the qualification
runner. It needs its external tools and may generate substantial traffic.
Its `--dhat` mode refers to a `dhat-heap` feature that is not currently in the
manifests; do not present that mode as supported. Its comments also reference a
missing benchmarking guide. Prefer the maintained qualification profiles for
reproducible bounded checks until those legacy paths are repaired.

## Documentation and secrets

Update the [README](README.md), [mTLS guide](docs/using_mtls.md), and
[protocol guide](docs/PROTOCOL_V2.md) when changing options, identities, framing,
defaults, or compatibility. Check examples against the actual parser/CLI and
link to existing repository files.

Generate development certificates with:

~~~sh
python3 scripts/generate_mtls.py
~~~

Only the template, ignore file, and README under `certs/mTLS` belong in Git.
Never commit deployment CA, server, or device private keys. Gitleaks runs in CI,
but `.gitleaks.toml` has path allowlists, including development TLS material
and build output; a passing scan is not proof that a file is safe to publish.
Do not broaden an allowlist to hide a real credential. Old published keys must
be replaced even after current-tree removal.

Redact proxy credentials, Authorization headers, secret path prefixes, TLS key
logs, and device/customer identifiers before sharing evidence. Keep test output
and private keys out of release artifacts.

## CI and releases

[CI](.github/workflows/ci.yaml) runs for pushes to `main`/`draft`, pull
requests targeting `main`, and manual dispatch. Its jobs include Gitleaks,
Semgrep, formatting, Clippy, a RustSec audit, provider-specific Rust tests, and
local qualification.

The [release workflow](.github/workflows/release.yaml) runs on `v*` tags or
manual dispatch. Checks gate its configured build matrix before release
publishing. The matrix is a build configuration, not proof of hardware/runtime
qualification on every OS. Publishing binaries or images is a separate
maintainer operation; do not infer that the newest source is already released.

## Pull requests and reports

Keep changes focused and describe the concrete before/after behavior. Include
the relevant test command, result, binary/commit identifiers, and any untested
platform or transport. Protocol changes need a migration/rollback plan for both
peers. Avoid claims of enterprise readiness based only on a health counter or a
short local benchmark.

Use the [bug](.github/ISSUE_TEMPLATE/bug_report.md),
[feature](.github/ISSUE_TEMPLATE/feature_request.md), or
[help](.github/ISSUE_TEMPLATE/need-help.md) template. Report vulnerabilities
privately through [SECURITY.md](SECURITY.md).
