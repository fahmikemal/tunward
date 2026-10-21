import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_wan_endurance import EXPECTED_CHECKS, inspect


class WanEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        binary = self.directory / "tunward-under-test"
        binary.write_bytes(b"qualification binary")
        self.binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.metadata = {"seconds": 86400, "interval": 900, "started_at_unix": 1000,
                         "binary_sha256": self.binary_hash,
                         "agent": {"binary_sha256": self.binary_hash, "expires_at_unix": 90000}}
        self.cycles = []
        for number, elapsed in enumerate(range(100, 86400, 900)):
            folder = self.directory / f"cycle-{number:04d}"
            folder.mkdir()
            data = json.dumps([{"name": name, "status": "pass"} for name in sorted(EXPECTED_CHECKS)]).encode()
            (folder / "results.json").write_bytes(data)
            (folder / "metadata.json").write_text(json.dumps({"binary_sha256": self.binary_hash,
                "agent": self.metadata["agent"]}))
            self.cycles.append({"cycle": number, "elapsed_seconds": elapsed, "exit_code": 0,
                "passed": 30, "failed": [], "results_sha256": hashlib.sha256(data).hexdigest()})
        self.receipt = {"state": "completed", "exit_code": 0, "elapsed_seconds": 86400,
                        "finished_at_unix": 87400, "cycles": len(self.cycles), "binary_sha256": self.binary_hash}

    def write(self, receipt=True):
        (self.directory / "metadata.json").write_text(json.dumps(self.metadata))
        data = json.dumps(self.cycles).encode()
        (self.directory / "progress.json").write_bytes(data)
        self.receipt["progress_sha256"] = hashlib.sha256(data).hexdigest()
        if receipt:
            (self.directory / "completion.json").write_text(json.dumps(self.receipt))

    def test_complete_window(self):
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "completed")

    def test_no_receipt_does_not_pass(self):
        self.write(receipt=False)
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_setup_failure_with_empty_failed_list_still_fails(self):
        self.cycles[1].update(exit_code=1, passed=0, failed=[], results_sha256=None)
        self.write()
        report = inspect(self.directory)
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["failed_cycles"], [1])

    def test_interrupted_receipt_fails(self):
        self.receipt.update(state="interrupted", exit_code=143)
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "failed")

    def test_changed_results_do_not_pass(self):
        self.write()
        (self.directory / "cycle-0000/results.json").write_text("[]")
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_duplicate_check_cannot_replace_missing_check(self):
        path = self.directory / "cycle-0000/results.json"
        rows = json.loads(path.read_text())
        rows[-1] = rows[0]
        path.write_text(json.dumps(rows))
        self.cycles[0]["results_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_missing_cycle_evidence_does_not_pass(self):
        (self.directory / "cycle-0000/metadata.json").unlink()
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_short_window_does_not_pass(self):
        self.receipt.update(elapsed_seconds=300, finished_at_unix=1300)
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_long_gap_does_not_pass(self):
        self.cycles[3]["elapsed_seconds"] += 601
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_different_agent_binary_does_not_pass(self):
        self.metadata["agent"]["binary_sha256"] = "different"
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_changed_binary_does_not_pass(self):
        self.write()
        (self.directory / "tunward-under-test").write_bytes(b"different binary")
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_replaced_agent_with_same_binary_does_not_pass(self):
        path = self.directory / "cycle-0001/metadata.json"
        child = json.loads(path.read_text())
        child["agent"]["address"] = "192.0.2.20"
        path.write_text(json.dumps(child))
        self.write()
        report = inspect(self.directory)
        self.assertEqual(report["state"], "incomplete")
        self.assertIn("cycle 1: agent changed during qualification window", report["issues"])

    def test_changed_progress_does_not_pass(self):
        self.write()
        with (self.directory / "progress.json").open("a") as stream:
            stream.write(" ")
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_failed_native_row_overrides_success_summary(self):
        path = self.directory / "cycle-0000/results.json"
        rows = json.loads(path.read_text())
        rows[0]["status"] = "fail"
        path.write_text(json.dumps(rows))
        self.cycles[0]["results_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "failed")


if __name__ == "__main__":
    unittest.main()
