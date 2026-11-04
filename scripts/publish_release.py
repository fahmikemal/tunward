#!/usr/bin/env python3
"""Publish the packaged release files with the provenance bundle that attests them."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess

from package_release import sha256


def attach_provenance(dist, bundle, tag):
    """Copy the bundle beside the files it attests, once it is known to name exactly those files."""
    lines = bundle.read_text().splitlines()
    if len(lines) != 1:
        raise ValueError(f"expected one attestation in {bundle.name}, found {len(lines)}")
    statement = json.loads(base64.b64decode(json.loads(lines[0])["dsseEnvelope"]["payload"]))
    attested = {subject["name"]: subject["digest"]["sha256"] for subject in statement["subject"]}
    packaged = {path.name: sha256(path) for path in dist.iterdir()}
    if attested != packaged:
        raise ValueError(f"attestation differs from the packaged files: {sorted(attested.items() ^ packaged.items())}")
    asset = dist / f"tunward_{tag[1:]}.intoto.jsonl"
    shutil.copyfile(bundle, asset)
    return asset


def publish(dist, bundle, tag, repository):
    asset = attach_provenance(dist, bundle, tag)
    # The check a user runs on a download; failing here leaves nothing published.
    subprocess.run(["gh", "attestation", "verify", str(dist / "checksums.txt"), "--bundle", str(asset),
                    "--repo", repository], check=True)
    command = ["gh", "release", "create", tag, *map(str, sorted(dist.iterdir())), "--repo", repository,
               "--verify-tag", "--latest=false",
               "--title", tag, "--generate-notes"]
    if "-" in tag:
        command.append("--prerelease")
    subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    args = parser.parse_args()
    try:
        publish(args.dist, args.provenance, args.tag, os.environ["GITHUB_REPOSITORY"])
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"release publication failed: {exc}\n")


if __name__ == "__main__":
    main()
