import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from qualify_runtime import RuntimeChecks


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI required")
class RuntimeCertificateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        binary = self.root / "binary"
        binary.write_bytes(b"unused by certificate preparation")
        self.checks = RuntimeChecks(SimpleNamespace(binary=binary, output=self.root / "evidence"))

    async def test_certificate_generation_ignores_ambient_extensions(self):
        config = self.root / "ambient.cnf"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=conflicting_ca\n"
                          "req_extensions=conflicting_ca\n[dn]\nCN=Ambient CA\n"
                          "[conflicting_ca]\nbasicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,keyEncipherment\n")
        with patch.dict("os.environ", {"OPENSSL_CONF": str(config)}):
            await self.checks.prepare()
        ca = (await self.checks.command("openssl", "x509", "-in", self.checks.certs / "ca.pem",
                                       "-text", "-noout")).decode()
        self.assertEqual(ca.count("X509v3 Basic Constraints:"), 1)
        self.assertEqual(ca.count("X509v3 Key Usage:"), 1)
        self.assertIn("CA:TRUE", ca)
        self.assertTrue(self.checks.openssl_version)

    async def test_setup_failure_preserves_evidence(self):
        async def fail(*_args):
            raise RuntimeError("OpenSSL fixture failure")
        with patch.object(self.checks, "command", side_effect=fail):
            self.assertTrue(await self.checks.run())
        results = json.loads((self.checks.out / "results.json").read_text())
        self.assertEqual(results[0]["name"], "runtime/setup")
        self.assertEqual(results[0]["status"], "fail")
        self.assertIn("OpenSSL fixture failure", results[0]["error"])
        metadata = json.loads((self.checks.out / "metadata.json").read_text())
        self.assertIn("binary_sha256", metadata)


if __name__ == "__main__":
    unittest.main()
