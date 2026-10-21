#!/usr/bin/env python3
"""Periodic native WAN checks against an operator-started expiring mTLS agent."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/tunward"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--remote", required=True)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--agent-script", required=True)
    parser.add_argument("--seconds", type=int, default=86400)
    parser.add_argument("--interval", type=int, default=300)
    args = parser.parse_args()
    if not (5 <= args.seconds <= 259200 and 1 <= args.interval <= 3600):
        parser.error("duration 5..259200 and interval 1..3600 seconds")
    manifest = json.loads(subprocess.check_output([
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", args.remote,
        shlex.join(["cat", f"{args.directory}/agent.json"])], timeout=20, text=True))
    if manifest.get("expires_at_unix", 0) < time.time() + args.seconds + 300:
        parser.error("agent expires before the requested client window plus five-minute margin; start a fresh longer-lived agent")
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    if manifest.get("binary_sha256") != binary_hash:
        parser.error("agent and client binary hashes differ; qualify matching builds")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    binary = args.output.resolve() / "tunward-under-test"
    shutil.copy2(args.binary, binary)
    runner = args.output.resolve() / "runner"
    runner.mkdir(mode=0o700)
    for name in ("qualify_wan.py", "qualify.py"):
        shutil.copy2(Path(__file__).with_name(name), runner / name)
    started = time.time()
    start = time.monotonic()
    metadata = {"started_at_unix": started, "seconds": args.seconds, "interval": args.interval,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "periodic synthetic WAN native TCP/UDP/proxy/reverse checks; no physical MDM devices",
                "remote": args.remote, "directory": args.directory,
                "agent": manifest, "child_runner_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in runner.iterdir()}}
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    cycles = []
    state, exit_code = "interrupted", 130
    stop_signal = None
    error = None

    def request_stop(signum, _frame):
        nonlocal stop_signal
        stop_signal = signum

    handlers = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        while stop_signal is None and time.monotonic() - start < args.seconds:
            cycle_start = time.monotonic()
            folder = args.output / f"cycle-{len(cycles):04d}"
            with (args.output / f"cycle-{len(cycles):04d}.log").open("w") as log:
                process = subprocess.Popen([
                    sys.executable, str(runner / "qualify_wan.py"),
                    "--binary", str(binary), "--output", str(folder), "--remote", args.remote,
                    "--directory", args.directory, "--agent-script", args.agent_script,
                    "--pool-timeout", "20", "--exchange-timeout", "20"], stdout=log, stderr=subprocess.STDOUT,
                    start_new_session=os.name == "posix")
                try:
                    deadline = time.monotonic() + 600
                    while True:
                        if stop_signal is not None:
                            raise KeyboardInterrupt
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(process.args, 600)
                        try:
                            result = process.wait(timeout=min(1, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                except BaseException:
                    def stop_child(signum):
                        try:
                            if os.name == "posix":
                                os.killpg(process.pid, signum)
                            elif signum == signal.SIGTERM:
                                process.terminate()
                            else:
                                process.kill()
                        except ProcessLookupError:
                            pass

                    stop_child(signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if os.name == "posix":
                            stop_child(signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait()
                    finally:
                        if os.name == "posix":
                            stop_child(signal.SIGKILL)
                    raise
            snapshot = folder / "tunward-under-test"
            if snapshot.exists() and hashlib.sha256(snapshot.read_bytes()).hexdigest() == metadata["binary_sha256"]:
                shared = folder / ".binary-snapshot-link"
                shared.hardlink_to(binary)
                shared.replace(snapshot)
            rows = json.loads((folder / "results.json").read_text()) if (folder / "results.json").exists() else []
            cycles.append({"cycle": len(cycles), "elapsed_seconds": round(time.monotonic() - start, 3),
                           "exit_code": result, "passed": sum(r["status"] == "pass" for r in rows),
                           "failed": [r for r in rows if r["status"] != "pass"],
                           "results_sha256": hashlib.sha256((folder / "results.json").read_bytes()).hexdigest() if rows else None})
            temporary = args.output / "progress.next.json"
            temporary.write_text(json.dumps(cycles, indent=2) + "\n")
            temporary.replace(args.output / "progress.json")
            remaining = args.seconds - (time.monotonic() - start)
            wake = time.monotonic() + max(0, min(remaining, args.interval - (time.monotonic() - cycle_start)))
            while stop_signal is None and time.monotonic() < wake:
                time.sleep(min(1, max(0, wake - time.monotonic())))
        if stop_signal is None:
            exit_code = int(not cycles or any(c["exit_code"] or c["failed"] or not c["passed"] for c in cycles))
            state = "failed" if exit_code else "completed"
    except KeyboardInterrupt:
        pass
    except Exception as failure:
        state, exit_code = "failed", 1
        error = f"{type(failure).__name__}: {failure}"
        raise
    finally:
        if stop_signal is not None:
            state, exit_code = "interrupted", 128 + stop_signal
        receipt = args.output / "completion.next.json"
        receipt.write_text(json.dumps({
            "state": state, "exit_code": exit_code, "stop_signal": stop_signal, "error": error, "elapsed_seconds": round(time.monotonic() - start, 3),
            "finished_at_unix": time.time(), "cycles": len(cycles),
            "binary_sha256": metadata["binary_sha256"],
            "progress_sha256": hashlib.sha256((args.output / "progress.json").read_bytes()).hexdigest() if cycles else None,
            "note": "Periodic probes do not measure continuous per-device availability or sleep/reconnect behavior."
        }, indent=2) + "\n")
        receipt.replace(args.output / "completion.json")
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
