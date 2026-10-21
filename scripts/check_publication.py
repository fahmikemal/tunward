#!/usr/bin/env python3
"""Report PEM private-key material in indexed files or reachable Git history, without printing secrets."""
import argparse
import json
from pathlib import Path
import re
import subprocess


MARKER = re.compile(rb"(?m)^-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?$")


def audit(repository, history=False):
    def git(*args, **kwargs):
        return subprocess.check_output(["git", "-C", str(repository), *args], **kwargs)
    findings = []
    if history:
        objects = git("rev-list", "--objects", "--all").decode().splitlines()
        candidates = {}
        for item in objects:
            oid, _, path = item.partition(" ")
            candidates.setdefault(oid, path)
        process = subprocess.Popen(["git", "-C", str(repository), "cat-file", "--batch"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        scanned = 0
        try:
            for oid, path in candidates.items():
                process.stdin.write((oid + "\n").encode())
                process.stdin.flush()
                header = process.stdout.readline().decode().split()
                size = int(header[2])
                data = process.stdout.read(size)
                assert len(data) == size
                assert process.stdout.read(1) == b"\n"
                if header[1] == "blob":
                    scanned += 1
                    if MARKER.search(data):
                        findings.append({"object": oid, "path": path, "kind": "PEM private key"})
        finally:
            process.stdin.close()
            process.stdout.close()
            process.wait(timeout=10)
    else:
        paths = git("ls-files", "--cached", "-z").decode().split("\0")
        scanned = 0
        for name in filter(None, paths):
            path = repository / name
            if path.is_file():
                scanned += 1
                if MARKER.search(path.read_bytes()):
                    findings.append({"path": name, "kind": "PEM private key"})
    return {"scope": "all reachable Git blobs" if history else "indexed working-tree files",
            "scanned_files_or_blobs": scanned, "findings": findings,
            "status": "fail" if findings else "pass",
            "limitation": "PEM marker check; not a general credential scanner, unreachable-object purge, issuer revocation, or hosted-fork/cache cleanup."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit(args.repository.resolve(), args.history)
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    raise SystemExit(report["status"] != "pass")


if __name__ == "__main__":
    main()
