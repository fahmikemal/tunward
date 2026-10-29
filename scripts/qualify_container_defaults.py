#!/usr/bin/env python3
"""Run a tunward image with its own default command: it serves with the documented files mounted
and refuses to start, naming the missing file, without them."""
import argparse
import asyncio
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from qualify_wan import certificates

ROOT = Path(__file__).resolve().parents[1]
LISTENING = "Starting tunward server listening"


def docker(*args, timeout=30):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def mounts(out):
    """The documented layout: a TLS directory and a restriction policy, both read-only."""
    certs = out / "certificates"
    tls = out / "etc-tunward" / "tls"
    tls.mkdir(parents=True)
    tls.chmod(0o755)
    for source, target in (("server.pem", "server.pem"), ("server.key", "server.key"), ("ca.pem", "client-ca.pem")):
        shutil.copy(certs / source, tls / target)
        # A disposable test key, readable by the image's non-root user whatever its UID.
        (tls / target).chmod(0o644)
    policy = out / "etc-tunward" / "restrictions.yaml"
    shutil.copy(ROOT / "restrictions.yaml", policy)
    policy.chmod(0o644)
    return ["-v", f"{tls}:/etc/tunward/tls:ro", "-v", f"{policy}:/etc/tunward/restrictions.yaml:ro"]


def serves_with_mounts(image, volumes):
    name = f"tunward-defaults-{uuid.uuid4().hex[:8]}"
    started = docker("run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL", *volumes, image)
    assert started.returncode == 0, started.stderr
    try:
        logs = ""
        for _ in range(100):
            state = docker("inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", name).stdout.split()
            logs = docker("logs", name).stdout + docker("logs", name).stderr
            if LISTENING in logs:
                break
            assert state[0] == "true", f"the container exited with {state[1]}: {logs[-800:]}"
            time.sleep(0.1)
        assert LISTENING in logs, f"the server did not start listening: {logs[-800:]}"
        time.sleep(1)
        state = docker("inspect", "--format", "{{.State.Running}}", name).stdout.strip()
        assert state == "true", f"the server stopped after starting: {logs[-800:]}"
        return {"listening": True, "read_only_root": True, "capabilities": "none"}
    finally:
        docker("rm", "-f", name)


def refuses_without_mounts(image):
    result = docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", image, timeout=30)
    output = result.stdout + result.stderr
    assert result.returncode != 0, f"the server started without its files: {output[-800:]}"
    assert "/etc/tunward/tls/server.pem" in output, f"the error does not name the missing file: {output[-800:]}"
    return {"exit_code": result.returncode, "names_missing_file": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    asyncio.run(certificates(out / "certificates", "127.0.0.1"))
    volumes = mounts(out)
    results = []
    for name, check in (("container/default-command-serves-with-mounted-files", lambda: serves_with_mounts(args.image, volumes)),
                        ("container/default-command-refuses-without-files", lambda: refuses_without_mounts(args.image))):
        start = time.monotonic()
        try:
            row = {"name": name, "status": "pass", **check()}
        except Exception as error:  # noqa: BLE001 - report every failure
            row = {"name": name, "status": "fail", "error": f"{type(error).__name__}: {error}"}
        row["elapsed_seconds"] = round(time.monotonic() - start, 3)
        results.append(row)
        print(json.dumps(row), flush=True)
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    raise SystemExit(any(row["status"] == "fail" for row in results))


if __name__ == "__main__":
    main()
