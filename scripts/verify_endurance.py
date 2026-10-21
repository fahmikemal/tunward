#!/usr/bin/env python3
"""Inspect endurance evidence without treating progress or an active unit as a pass."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import time


def inspect(directory, unit=None, minimum_seconds=86400):
    metadata = json.loads((directory / "metadata.json").read_text())
    results_path = directory / "results.json"
    result_bytes = results_path.read_bytes() if results_path.exists() else None
    rows = json.loads(result_bytes) if result_bytes is not None else []
    props = {}
    if unit:
        output = subprocess.check_output([
            "systemctl", "--user", "show", unit, "-p", "ActiveState", "-p", "SubState",
            "-p", "Result", "-p", "ExecMainStatus", "-p", "ExecMainExitTimestamp",
            "-p", "MemoryPeak", "-p", "CPUUsageNSec"], text=True)
        props = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    completion_path = directory / "completion.json"
    completion = json.loads(completion_path.read_text()) if completion_path.exists() else None
    failures = [row for row in rows if row["status"] == "fail"]
    transports = metadata["args"]["transports"].split(",")
    durations, resources, missing = {}, {}, []
    for scheme in transports:
        final = next((r for r in rows if r["name"] == f"soak/{scheme}/keepalive-and-cleanup"), None)
        suite = next((r for r in rows if r["name"] == f"soak/{scheme}/suite"), None)
        recovery = next((r for r in rows if r["name"] == f"soak/{scheme}/server-restart-recovery"), None)
        progress = [r["latest"] for r in rows if r["name"].startswith(f"soak/{scheme}/progress-")]
        samples = final.get("samples", []) if final else progress
        durations[scheme] = final["duration_seconds"] if final else max((s["elapsed_seconds"] for s in samples), default=0)
        if not final or not suite or not recovery or durations[scheme] < minimum_seconds:
            missing.append(scheme)
        pids = {pid for sample in samples for pid in sample.get("processes", {})}
        resources[scheme] = {}
        for pid in pids:
            values = [s["processes"][pid] for s in samples if pid in s.get("processes", {}) and s["processes"][pid]]
            resources[scheme][pid] = {
                "samples": len(values),
                **{key: {"first": values[0].get(key), "last": values[-1].get(key),
                         "maximum": max(v.get(key, 0) for v in values)} for key in ("rss_kib", "fds", "cpu_seconds")}
            } if values else {"samples": 0}
    receipt_ok = bool(result_bytes is not None and completion and completion["state"] == "completed" and completion["exit_code"] == 0
                      and completion["binary_sha256"] == metadata["binary_sha256"]
                      and completion["results_sha256"] == hashlib.sha256(result_bytes).hexdigest())
    service_ok = bool(props.get("ActiveState") == "inactive" and props.get("Result") == "success"
                      and props.get("ExecMainStatus") == "0" and props.get("ExecMainExitTimestamp"))
    if failures or (completion and completion["state"] != "completed") or props.get("ActiveState") == "failed":
        state = "failed"
    elif props.get("ActiveState") in ("active", "activating", "deactivating"):
        state = "running"
    elif not missing and (receipt_ok or service_ok):
        state = "completed"
    else:
        state = "incomplete"
    return {"checked_at_unix": time.time(), "state": state, "directory": str(directory),
            "binary_sha256": metadata["binary_sha256"], "minimum_seconds": minimum_seconds,
            "counts": dict(Counter(r["status"] for r in rows)), "failures": failures,
            "duration_seconds_by_transport": durations, "missing_final_evidence": missing,
            "completion_receipt_valid": receipt_ok, "service": props, "resource_observations": resources,
            "results_present": result_bytes is not None,
            "scope": "synthetic staging-local mixed features; not WAN or physical-device evidence",
            "resource_review": "First/last/max are observations, not an automatic memory-leak verdict."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--unit")
    parser.add_argument("--minimum-seconds", type=int, default=86400)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.minimum_seconds < 1:
        parser.error("minimum duration must be positive")
    report = inspect(args.directory, args.unit, args.minimum_seconds)
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    raise SystemExit(0 if report["state"] == "completed" else 2 if report["state"] == "running" else 1)


if __name__ == "__main__":
    main()
