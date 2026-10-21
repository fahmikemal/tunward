import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from verify_endurance import inspect


class CompletionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.metadata = {"binary_sha256": "expected-binary", "args": {"transports": "wss,wts"}}
        self.rows = [{"name": f"soak/{scheme}/{kind}", "status": "pass",
                      **({"duration_seconds": 86402, "samples": []} if kind == "keepalive-and-cleanup" else {})}
                     for scheme in ("wss", "wts")
                     for kind in ("keepalive-and-cleanup", "suite", "server-restart-recovery")]

    def write(self, receipt=True):
        (self.directory / "metadata.json").write_text(json.dumps(self.metadata))
        results = json.dumps(self.rows).encode()
        (self.directory / "results.json").write_bytes(results)
        if receipt:
            (self.directory / "completion.json").write_text(json.dumps({"state": "completed", "exit_code": 0,
                "binary_sha256": "expected-binary", "results_sha256": hashlib.sha256(results).hexdigest()}))

    def test_complete_duration_receipt_and_final_checks(self):
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "completed")

    def test_active_service_success_is_still_running(self):
        self.write()
        with patch("verify_endurance.subprocess.check_output", return_value="ActiveState=active\nResult=success\nExecMainStatus=0\n"):
            self.assertEqual(inspect(self.directory, "example")["state"], "running")

    def test_active_before_first_progress_is_running(self):
        (self.directory / "metadata.json").write_text(json.dumps(self.metadata))
        with patch("verify_endurance.subprocess.check_output", return_value="ActiveState=active\nResult=success\nExecMainStatus=0\n"):
            report = inspect(self.directory, "example")
        self.assertEqual(report["state"], "running")
        self.assertFalse(report["results_present"])
        self.assertFalse(report["completion_receipt_valid"])

    def test_missing_results_without_active_service_is_incomplete(self):
        (self.directory / "metadata.json").write_text(json.dumps(self.metadata))
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_progress_alone_never_completes(self):
        self.rows = [{"name": "soak/wss/progress-3000", "status": "pass", "latest": {"elapsed_seconds": 90000, "processes": {}}}]
        self.write(receipt=False)
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_final_rows_without_exit_evidence_are_incomplete(self):
        self.write(receipt=False)
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_changed_results_invalidate_receipt(self):
        self.write()
        self.rows.append({"name": "late-progress", "status": "pass"})
        (self.directory / "results.json").write_text(json.dumps(self.rows))
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_shortened_duration_is_not_24_hours(self):
        self.rows[0]["duration_seconds"] = 300
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_any_failed_check_prevents_completion(self):
        self.rows.append({"name": "data-integrity", "status": "fail"})
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "failed")

    def test_missing_transport_cleanup_prevents_completion(self):
        self.rows.pop()
        self.write()
        self.assertEqual(inspect(self.directory)["state"], "incomplete")

    def test_legacy_service_requires_actual_exit_timestamp(self):
        self.write(receipt=False)
        properties = "ActiveState=inactive\nResult=success\nExecMainStatus=0\n"
        with patch("verify_endurance.subprocess.check_output", return_value=properties):
            self.assertEqual(inspect(self.directory, "example")["state"], "incomplete")
        with patch("verify_endurance.subprocess.check_output", return_value=properties + "ExecMainExitTimestamp=completed\n"):
            self.assertEqual(inspect(self.directory, "example")["state"], "completed")


if __name__ == "__main__":
    unittest.main()
