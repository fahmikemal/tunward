"""The internal root provisioning entry point must never become a host installer."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class SystemdGuardTests(unittest.TestCase):
    def invoke(self, optimize=False):
        if Path("/qualification/CONTAINER_ONLY").exists():
            self.skipTest("guard rejection requires a process outside the disposable fixture")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-be-created"
            command = [sys.executable] + (["-O"] if optimize else [])
            command += [str(Path(__file__).with_name("qualify_systemd.py")), "--inside-container",
                        "--binary", str(Path(directory) / "unused"), "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists(), "provisioning started before the guard")
            return result.stderr

    def test_internal_provisioning_refuses_host(self):
        self.assertIn("container fixture only", self.invoke())

    def test_optimized_python_cannot_disable_qualification_checks(self):
        self.assertIn("qualification requires Python assertions", self.invoke(optimize=True))


if __name__ == "__main__":
    unittest.main()
