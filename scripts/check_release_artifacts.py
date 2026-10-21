#!/usr/bin/env python3
"""Validate binary artifacts and eligibility for an existing prerelease recovery."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from check_release_tag import validate as validate_tag


TARGETS = (
    "x86_64-unknown-linux-musl", "i686-unknown-linux-musl", "aarch64-unknown-linux-musl",
    "armv7-unknown-linux-musleabihf", "arm-unknown-linux-musleabihf",
    "x86_64-unknown-freebsd", "i686-unknown-freebsd", "aarch64-linux-android",
    "armv7-linux-androideabi", "x86_64-apple-darwin", "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc", "i686-pc-windows-msvc", "aarch64-pc-windows-msvc",
)
ARTIFACTS = {f"tunward-{target}": "tunward.exe" if "windows" in target else "tunward" for target in TARGETS}


def verify_download(root):
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != set(ARTIFACTS):
        raise ValueError("download must contain exactly the fourteen release binary directories")
    binaries = []
    for name, filename in ARTIFACTS.items():
        directory = root / name
        binary = directory / filename
        if (directory.is_symlink() or not directory.is_dir() or
                {p.name for p in directory.iterdir()} != {filename} or
                binary.is_symlink() or not binary.is_file() or binary.stat().st_size == 0):
            raise ValueError(f"invalid binary artifact: {name}/{filename}")
        binaries.append(binary)
    # GitHub artifact extraction normalizes file modes; archives must retain runnable Unix binaries.
    for binary in binaries:
        binary.chmod(0o755)


def verify_recovery(run, jobs, artifacts, releases, repository, tag, commit):
    if (run.get("repository", {}).get("full_name") != repository or
            run.get("event") != "push" or run.get("path") != ".github/workflows/release.yaml" or
            run.get("head_branch") != tag or run.get("head_sha") != commit or
            run.get("status") != "completed" or run.get("conclusion") != "failure"):
        raise ValueError("source must be a completed failed tag-push Release run for this repository and commit")
    required = {
        "Validate release tag and publication credentials", "Check - format, lint & tests",
        "Publish Docker Hub image", "native-runtime / native (ubuntu-24.04)",
        "native-runtime / native (macos-14)", "native-runtime / native (windows-2022)",
    }
    prerequisites = [j for j in jobs if j["name"] in required or j["name"].startswith("Build - ")]
    if (len(prerequisites) != len(required) + len(TARGETS) or
            not required.issubset({j["name"] for j in prerequisites}) or
            len({j["name"] for j in prerequisites}) != len(prerequisites) or
            any(j.get("status") != "completed" or j.get("conclusion") != "success" for j in prerequisites)):
        raise ValueError("all checks, native runtimes, fourteen builds, and Docker publication must have succeeded")
    packaging = [j for j in jobs if j["name"] == "Release"]
    if (len(packaging) != 1 or packaging[0].get("conclusion") != "failure" or
            any(j.get("status") != "completed" or j.get("conclusion") != "success"
                for j in jobs if j["name"] != "Release")):
        raise ValueError("only a failed final Release job is eligible for recovery")
    selected = [a for a in artifacts if a["name"].startswith("tunward-")]
    if (len(selected) != len(ARTIFACTS) or {a["name"] for a in selected} != set(ARTIFACTS) or
            any(a.get("expired", True) or a.get("workflow_run", {}).get("head_sha") != commit for a in selected)):
        raise ValueError("source artifacts must be complete, unexpired, and from the tag commit")
    if any(r.get("tag_name") == tag for r in releases):
        raise ValueError("a GitHub release already exists; inspect it instead of replacing assets")


def api(repository, endpoint, collection=None):
    pages = json.loads(subprocess.check_output(
        ["gh", "api", "--paginate", "--slurp", f"repos/{repository}/{endpoint}"], text=True))
    if collection:
        return [row for page in pages for row in page[collection]]
    return [row for page in pages for row in page]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--run-id")
    args = parser.parse_args()
    try:
        if args.artifacts:
            verify_download(args.artifacts)
            print("verified fourteen release binaries and restored executable permissions")
            return
        if not args.source or not args.tag or not args.run_id or not re.fullmatch(r"[0-9]+", args.run_id):
            raise ValueError("recovery requires --source, --tag, and a numeric --run-id")
        tag = validate_tag(f"refs/tags/{args.tag}", args.source)
        if "-" not in tag:
            raise ValueError("manual recovery is limited to prerelease tags")
        commit = subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip()
        repository = os.environ["GITHUB_REPOSITORY"]
        run = json.loads(subprocess.check_output(
            ["gh", "api", f"repos/{repository}/actions/runs/{args.run_id}"], text=True))
        verify_recovery(run,
                        api(repository, f"actions/runs/{args.run_id}/jobs?per_page=100", "jobs"),
                        api(repository, f"actions/runs/{args.run_id}/artifacts?per_page=100", "artifacts"),
                        api(repository, "releases?per_page=100"), repository, tag, commit)
        print(f"eligible prerelease recovery: {tag}, source run {args.run_id}, commit {commit}")
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"release artifacts rejected: {exc}\n")


if __name__ == "__main__":
    main()
