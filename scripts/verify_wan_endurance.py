#!/usr/bin/env python3
"""Verify complete periodic WAN evidence; this does not certify production readiness."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import time


EXPECTED_CHECKS = {f"wan/control/direct-mtls-{n}" for n in (1, 4, 16)} | {
    f"wan/{transport}/{case}" for transport in ("wss", "https", "wts")
    for case in ("tcp/concurrent-1", "tcp/concurrent-4", "tcp/concurrent-16",
                 "socks/concurrent-16", "http/concurrent-16", "unix/concurrent-16",
                 "udp-1200", "udp-40000", "reverse-tcp")
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect(directory, minimum_seconds=86400):
    issues, failed_cycles = [], []
    metadata = json.loads((directory / "metadata.json").read_text())
    progress_path = directory / "progress.json"
    cycles = json.loads(progress_path.read_text()) if progress_path.exists() else []
    receipt_path = directory / "completion.json"
    receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else None
    binary_hash = metadata["binary_sha256"]
    if digest(directory / "tunward-under-test") != binary_hash:
        issues.append("binary snapshot hash mismatch")
    if metadata["seconds"] < minimum_seconds:
        issues.append("requested window shorter than minimum")
    if metadata["agent"]["binary_sha256"] != binary_hash:
        issues.append("agent and client binary hashes differ")
    if metadata["agent"]["expires_at_unix"] < metadata["started_at_unix"] + metadata["seconds"] + 300:
        issues.append("agent lifetime does not cover window and five-minute margin")
    previous = 0
    for number, cycle in enumerate(cycles):
        folder = directory / f"cycle-{number:04d}"
        elapsed = cycle["elapsed_seconds"]
        if not math.isfinite(elapsed) or elapsed < previous or elapsed - previous > metadata["interval"] + 600:
            issues.append(f"cycle {number}: invalid timing or excessive gap")
        previous = elapsed
        if cycle["cycle"] != number:
            issues.append(f"cycle {number}: sequence mismatch")
        if cycle["exit_code"] != 0 or cycle["failed"] or not cycle["passed"]:
            failed_cycles.append(number)
        try:
            results_path = folder / "results.json"
            rows = json.loads(results_path.read_text())
            child = json.loads((folder / "metadata.json").read_text())
            if digest(results_path) != cycle["results_sha256"]:
                issues.append(f"cycle {number}: results hash mismatch")
            names = [row["name"] for row in rows]
            if len(names) != len(EXPECTED_CHECKS) or set(names) != EXPECTED_CHECKS:
                issues.append(f"cycle {number}: incomplete or duplicate native check matrix")
            if any(row["status"] != "pass" for row in rows):
                failed_cycles.append(number)
            if sum(row["status"] == "pass" for row in rows) != cycle["passed"]:
                issues.append(f"cycle {number}: pass count mismatch")
            if child["binary_sha256"] != binary_hash or child["agent"]["binary_sha256"] != binary_hash:
                issues.append(f"cycle {number}: binary metadata mismatch")
            if child["agent"] != metadata["agent"]:
                issues.append(f"cycle {number}: agent changed during qualification window")
        except (OSError, ValueError, KeyError, TypeError) as error:
            issues.append(f"cycle {number}: missing or invalid evidence ({type(error).__name__})")
    if not cycles:
        issues.append("no completed cycles")
    receipt_ok = bool(receipt and receipt.get("state") == "completed" and receipt.get("exit_code") == 0
                      and receipt.get("binary_sha256") == binary_hash
                      and receipt.get("cycles") == len(cycles)
                      and progress_path.exists() and receipt.get("progress_sha256") == digest(progress_path))
    if not receipt_ok:
        issues.append("missing or invalid successful completion receipt")
    if receipt:
        duration = receipt["elapsed_seconds"]
        if (not math.isfinite(duration) or duration < max(minimum_seconds, metadata["seconds"])
                or receipt["finished_at_unix"] - metadata["started_at_unix"] < minimum_seconds
                or previous > duration or duration - previous > metadata["interval"]):
            issues.append("incomplete duration or final sampling gap")
    if failed_cycles or (receipt and (receipt.get("state") != "completed" or receipt.get("exit_code") != 0)):
        state = "failed"
    else:
        state = "incomplete" if issues else "completed"
    return {"checked_at_unix": time.time(), "state": state, "directory": str(directory),
            "minimum_seconds": minimum_seconds, "binary_sha256": binary_hash,
            "cycles": len(cycles), "failed_cycles": sorted(set(failed_cycles)), "issues": issues,
            "completion_receipt_valid": receipt_ok,
            "scope": "periodic synthetic WAN probes; not continuous availability, physical-device acceptance, or production certification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--minimum-seconds", type=int, default=86400)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.minimum_seconds < 1:
        parser.error("minimum duration must be positive")
    try:
        report = inspect(args.directory, args.minimum_seconds)
    except (OSError, ValueError, KeyError, TypeError) as error:
        report = {"state": "incomplete", "issues": [f"Cannot verify evidence: {type(error).__name__}: {error}"]}
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    raise SystemExit(0 if report["state"] == "completed" else 1)


if __name__ == "__main__":
    main()
