#!/usr/bin/env python3
"""Archive the original Rust binaries without a second compiler or placeholder builds."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

from check_release_artifacts import ARTIFACTS, TARGETS, verify_download
from check_release_tag import validate as validate_tag


SUFFIXES = ("linux_amd64", "linux_386", "linux_arm64", "linux_armv7", "linux_armv6",
            "freebsd_amd64", "freebsd_386", "android_arm64", "android_armv7",
            "darwin_amd64", "darwin_arm64", "windows_amd64", "windows_386", "windows_arm64")


def sha256(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def package(source, artifacts, output, tag, commit, epoch, run_id):
    validate_tag(f"refs/tags/{tag}", source)
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("source commit and numeric run ID are required")
    verify_download(artifacts)
    for name in ("README.md", "LICENSE"):
        if (source / name).is_symlink() or not (source / name).is_file():
            raise ValueError(f"missing source document: {name}")
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for target, suffix in zip(TARGETS, SUFFIXES, strict=True):
        artifact = f"tunward-{target}"
        binary = artifacts / artifact / ARTIFACTS[artifact]
        archive = output / f"tunward_{tag[1:]}_{suffix}.tar.gz"
        with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tf:
                for path in (binary, source / "LICENSE", source / "README.md"):
                    info = tf.gettarinfo(str(path), arcname=path.name)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    info.mode = 0o755 if path == binary else 0o644
                    with path.open("rb") as data:
                        tf.addfile(info, data)
        binary_digest = sha256(binary)
        with tarfile.open(archive) as tf:
            member = tf.getmember(binary.name)
            if member.mode != 0o755 or hashlib.sha256(tf.extractfile(member).read()).hexdigest() != binary_digest:
                raise ValueError(f"archived binary differs from original artifact: {target}")
        rows.append({"target": target, "artifact": artifact, "binary_sha256": binary_digest,
                     "archive": archive.name, "archive_sha256": sha256(archive)})
    manifest = {"tag": tag, "commit": commit, "source_run_id": run_id, "binaries": rows}
    (output / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    files = sorted(output.iterdir())
    (output / "checksums.txt").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files))
    return files + [output / "checksums.txt"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    try:
        validate_tag(f"refs/tags/{args.tag}", args.source)
        commit = subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip()
        tagged = subprocess.check_output(["git", "-C", str(args.source), "rev-parse", f"refs/tags/{args.tag}^{{commit}}"], text=True).strip()
        if tagged != commit:
            raise ValueError("source checkout must match the existing tag commit")
        epoch = int(subprocess.check_output(["git", "-C", str(args.source), "show", "-s", "--format=%ct", "HEAD"], text=True))
        files = package(args.source, args.artifacts, args.output, args.tag, commit, epoch, args.run_id)
        print(f"verified fourteen original binaries in archives; source commit {commit}", flush=True)
        if args.publish:
            command = ["gh", "release", "create", args.tag, *map(str, files), "--repo", os.environ["GITHUB_REPOSITORY"],
                       "--verify-tag", "--latest=false",
                       "--title", args.tag, "--generate-notes"]
            if "-" in args.tag:
                command.append("--prerelease")
            subprocess.run(command, check=True)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"release packaging failed: {exc}\n")


if __name__ == "__main__":
    main()
