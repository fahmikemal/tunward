#!/usr/bin/env python3
"""Fail when a Rust toolchain pin disagrees with the channel in rust-toolchain.toml."""
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    ".github/workflows/ci.yaml": r'^\s*RUST_VERSION:\s*"?([0-9][0-9.]*)"?\s*$',
    ".github/workflows/release.yaml": r'^\s*RUST_VERSION:\s*"?([0-9][0-9.]*)"?\s*$',
    ".github/workflows/runtime-qualification.yaml": r'^\s*RUST_VERSION:\s*"?([0-9][0-9.]*)"?\s*$',
    "Dockerfile": r"^FROM rust:([0-9][0-9.]*)-",
    # The documented version, so the prose cannot fall behind the pins.
    "README.md": r"CI currently uses Rust ([0-9][0-9.]*[0-9])\.",
    "CONTRIBUTING.md": r"CI pins Rust ([0-9][0-9.]*[0-9]) ",
}


def channel(root):
    return tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]


def problems(root=ROOT):
    expected = channel(root)
    found = []
    for name, pattern in SOURCES.items():
        versions = re.findall(pattern, (root / name).read_text(), re.MULTILINE)
        if not versions:
            found.append(f"{name}: no Rust toolchain pin found")
        found += [f"{name}: pins {version}, rust-toolchain.toml pins {expected}" for version in versions if version != expected]
    return found


def main():
    found = problems()
    for problem in found:
        print(problem, file=sys.stderr)
    if found:
        raise SystemExit(1)
    print(f"every Rust toolchain pin matches rust-toolchain.toml ({channel(ROOT)})")


if __name__ == "__main__":
    main()
