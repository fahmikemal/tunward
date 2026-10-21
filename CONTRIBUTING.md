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

The [release workflow](.github/workflows/release.yaml) runs only on pushed `v*`
tags. `scripts/check_release_tag.py` requires `vMAJOR.MINOR.PATCH[-prerelease]`
to match the version in both package manifests; build metadata (`+...`) is not
accepted as a container tag. Branches, PRs, and manual branch dispatch cannot
publish releases. Checks and the native runtime matrix gate binary builds.
The matrix is a build configuration, not proof of runtime qualification on
every OS.

Before pushing a release tag, create the Docker Hub repository
`oph1uchus/tunward`. In GitHub Settings → Secrets and variables → Actions, set:

- Repository variable `DOCKERHUB_USERNAME`: the Docker Hub login with write
  access to `oph1uchus/tunward` (normally `oph1uchus`).
- Repository secret `DOCKERHUB_TOKEN`: a Docker Hub access token with the required
  write permission. Enter it directly in GitHub, never in source or a chat.

The release preflight fails if either is missing. The Docker Hub job downloads
the workflow's Linux amd64/arm64 musl binary artifacts into a minimal image
context containing only those binaries, the runtime Dockerfile, and LICENSE.
It builds and smoke-tests both architecture images before registry login and
publication. Smoke checks cover version, help, and non-root image configuration,
not full networking, mounts, or ARM hardware qualification. QEMU provides the
arm64 smoke runtime on the amd64 runner. The versioned multi-platform image
includes build provenance and an SBOM; the job summary records its digest.
PR CI also checks the amd64 image packaging with its native Linux binary and
never logs in or pushes an image. Tagged release checks use the actual musl
artifacts on both image architectures.

Container tags exactly match the Git release tag, including `v` and any beta/RC
suffix. No `latest` or stable alias is automatically updated. Prefer deployment
by reviewed digest. GitHub release creation follows successful Docker Hub
publication; these two remote operations are not an atomic transaction. Inspect
the image digest and release assets before retrying a partial publication.
`GITHUB_TOKEN` gets contents-write permission only in the GitHub release job;
an optional existing `RELEASE_TOKEN` secret overrides it. No token is required
in pull requests. Do not infer that the newest source is already released.

### Recover a partial prerelease

Docker build-push uploads `*.dockerbuild` records as well as publishing an image.
These records must not be passed to a generic ZIP artifact downloader. Release
packaging selects only `tunward-*`, keeps target directories separate, verifies
the exact fourteen-binary set, and restores executable permissions lost during
artifact upload/download. Keep the artifact target list in
`scripts/check_release_artifacts.py` aligned with the build matrix; CI checks it.
`scripts/package_release.py` archives all fourteen original binaries directly,
including Android ARMv7, with normalized modes, ownership, and tag-commit
timestamps. It verifies each archived binary against its downloaded artifact
and emits archive checksums plus a manifest of binary hashes, source commit,
and run ID. Repeating packaging with identical input bytes and packaging runtime
is deterministic; this does not prove reproducibility of the Rust compilation.
The active workflow no longer uses the legacy Go placeholder build/hooks, which
omitted the Android ARMv7 archive. GitHub prereleases are marked explicitly and
publication never replaces an existing release or automatically marks it latest.
Docker's [build record guidance](https://github.com/docker/build-push-action#summaries)
describes the download-all failure.

An existing tag retains its original workflow when a job is rerun; changing
`main` does not patch that tagged run. After a partial publication, do not move
the tag or republish its image merely to rerun GitHub packaging. The
[recovery workflow](.github/workflows/release-recovery.yaml) runs manually from
`main` with an existing prerelease tag and the original Release run ID:

~~~sh
gh workflow run release-recovery.yaml --ref main \
  -f release_tag=v0.1.0-beta -f source_run_id=39564724170
~~~

The guard requires a completed failed tag-push run in this repository matching
the checked-out tag commit. Version checks, all native runtimes, fourteen binary
builds, and Docker publication must have succeeded; only the final Release job
may have failed. All binary artifacts must remain available and belong to that
commit. Recovery refuses an existing GitHub release, including drafts, rather
than silently replacing published assets. It packages the original tag source
and binaries; it does not rebuild Rust, push an image, or change the tag. The
`GITHUB_TOKEN` needs actions-read and contents-write only for that job.

Use the actual failed run ID, not an unrelated successful run. Build artifacts
currently expire after one day. Expired artifacts, failed prerequisites, or a
partially created release require operator review; this workflow refuses them.
After recovery, verify the prerelease flag, archive contents/executable modes,
checksums, and existing image digest. The original failed run remains as evidence;
a successful recovery does not turn its historical result green.

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
