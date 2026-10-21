import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(os.name == "posix", "POSIX supervisor shutdown")
class SupervisorShutdownTests(unittest.TestCase):
    def test_sigterm_reaps_child_and_records_interruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "binary"
            binary.write_bytes(b"fixture")
            output, child_pid = root / "evidence", root / "child.pid"
            harness = '''
import hashlib, json, subprocess, sys, time
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import qualify_wan_endurance
real_popen = subprocess.Popen
child_code = """
import os, signal, subprocess, sys, time
from pathlib import Path
child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"])
def stop(_signum, _frame):
    child.wait(timeout=4)
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
Path(%r).write_text(str(os.getpid()))
Path(%r + ".grandchild").write_text(str(child.pid))
time.sleep(60)
""" % (sys.argv[4], sys.argv[4])
def child(*args, **kwargs):
    return real_popen([sys.executable, "-c", child_code], **kwargs)
manifest = json.dumps({"expires_at_unix": time.time() + 1000, "binary_sha256": hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()})
sys.argv = ["qualify_wan_endurance", "--binary", sys.argv[2], "--output", sys.argv[3],
            "--remote", "fixture", "--directory", "fixture", "--agent-script", "fixture", "--seconds", "60"]
with patch.object(subprocess, "check_output", return_value=manifest), patch.object(subprocess, "Popen", side_effect=child):
    qualify_wan_endurance.main()
'''
            parent = subprocess.Popen([sys.executable, "-c", harness, str(Path(__file__).resolve().parent),
                                       str(binary), str(output), str(child_pid)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 8
                while not child_pid.with_suffix(".pid.grandchild").exists() and parent.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(child_pid.exists(), "fixture child never started")
                parent.send_signal(signal.SIGTERM)
                _, error = parent.communicate(timeout=8)
                self.assertEqual(parent.returncode, 143, error)
                receipt = json.loads((output / "completion.json").read_text())
                self.assertEqual(receipt["state"], "interrupted")
                self.assertEqual(receipt["stop_signal"], signal.SIGTERM)
                self.assertEqual(receipt["cycles"], 0)
                for pid_file in (child_pid, child_pid.with_suffix(".pid.grandchild")):
                    with self.assertRaises(ProcessLookupError):
                        os.kill(int(pid_file.read_text()), 0)
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.communicate()
                for pid_file in (child_pid, child_pid.with_suffix(".pid.grandchild")):
                    if pid_file.exists():
                        try:
                            os.kill(int(pid_file.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()
