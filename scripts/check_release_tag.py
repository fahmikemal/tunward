#!/usr/bin/env python3
"""Require a version tag matching both Rust packages before publishing artifacts."""
import argparse
import os
from pathlib import Path
import re
import tomllib


TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def validate(ref, root):
    prefix = "refs/tags/"
    if not ref.startswith(prefix):
        raise ValueError("publishing requires a Git tag, not a branch or pull request")
    tag = ref.removeprefix(prefix)
    match = TAG.fullmatch(tag)
    if not match or len(tag) > 128:
        raise ValueError("use vMAJOR.MINOR.PATCH[-prerelease], at most 128 characters; build metadata is not supported")
    if match[4] and any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in match[4].split(".")):
        raise ValueError("numeric prerelease identifiers must not have leading zeroes")
    for manifest in ("tunward/Cargo.toml", "tunward-cli/Cargo.toml"):
        package = tomllib.loads((root / manifest).read_text())["package"]
        if package["version"] != tag[1:]:
            raise ValueError(f"{manifest} version must equal {tag[1:]}")
    return tag


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        tag = validate(args.ref, args.root)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, f"release tag rejected: {exc}\n")
    print(f"tag={tag}")
