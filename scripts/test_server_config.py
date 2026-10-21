"""Black-box tests for the offline server configuration check; require a built CLI."""
import asyncio
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from qualify_runtime import RuntimeChecks


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "release" / ("tunward.exe" if os.name == "nt" else "tunward")


@unittest.skipUnless(BINARY.is_file() and shutil.which("openssl"), "built release CLI and OpenSSL required")
class ServerConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.checks = RuntimeChecks(SimpleNamespace(binary=BINARY, output=cls.root / "fixtures"))
        asyncio.run(cls.checks.prepare())
        cls.certs = cls.checks.certs
        cls.env = {key: value for key, value in os.environ.items()
                   if not key.startswith("TUNWARD_") and key not in
                   ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "RUST_LOG", "NO_COLOR", "SSLKEYLOGFILE")}

    def invoke(self, *args, valid=True, env=None):
        result = subprocess.run([str(self.checks.binary), "server", *map(str, args)],
                                env=env or self.env, capture_output=True, text=True, timeout=10)
        if valid:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("configuration test is successful", result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("panicked at", result.stderr)
            self.assertNotIn("configuration test is successful", result.stderr)
        return result

    def tls(self):
        return ["--tls-certificate", self.certs / "server.pem", "--tls-private-key", self.certs / "server.key",
                "--tls-client-ca-certs", self.certs / "ca.pem"]

    def test_aliases_and_transports(self):
        for flag in ("-t", "--test-config"):
            for scheme in ("ws", "http", "wss", "wts"):
                with self.subTest(flag=flag, scheme=scheme):
                    self.invoke(flag, f"{scheme}://127.0.0.1:8443")
        self.invoke("-t", "--enable-webtransport", "wss://127.0.0.1:8443")

    def test_complete_policy_without_inventory_or_keylog_writes(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            directory = Path(directory)
            database, keylog = directory / "devices.sqlite3", directory / "keys.log"
            args = ["-t", *self.tls(), "--fleet-inventory", database]
            for option, filename in (("restrict-config", "tenant-restrictions.example.yaml"),
                                     ("tenant-config", "tenant-policy.example.yaml"),
                                     ("device-quota-config", "device-quotas.example.yaml"),
                                     ("device-revocation-config", "device-revocations.example.yaml")):
                args.extend([f"--{option}", ROOT / filename])
            self.invoke(*args, "wts://127.0.0.1:8443", env={**self.env, "SSLKEYLOGFILE": str(keylog)})
            self.assertEqual(list(directory.iterdir()), [])

    def test_does_not_bind_ports_or_resolve_listener(self):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp, socket.socket() as api:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen()
            endpoint = tcp.getsockname()[1]
            udp.bind(("127.0.0.1", endpoint))
            api.bind(("127.0.0.1", 0))
            api.listen()
            self.invoke("-t", *self.tls(), "--management-api", f"127.0.0.1:{api.getsockname()[1]}",
                        f"wts://127.0.0.1:{endpoint}")
        self.invoke("-t", "wss://no-such-listener.invalid:8443")

    def test_invalid_argument_combinations(self):
        cases = [(["--enable-webtransport", "ws://127.0.0.1:8443"], "requires TLS"),
                 (["--tls-certificate", self.certs / "server.pem", "wss://127.0.0.1:8443"], "supplied together"),
                 ([*self.tls(), "ws://127.0.0.1:8443"], "require a TLS listener"),
                 (["https://127.0.0.1:8443"], "use wss://"),
                 (["--management-api", "0.0.0.0:8081", "wss://127.0.0.1:8443"], "loopback"),
                 (["--restrict-to", "no-port", "ws://127.0.0.1:8443"], "HOST:PORT"),
                 (["--restrict-to", "host:65536", "ws://127.0.0.1:8443"], "Invalid --restrict-to port"),
                 (["--fleet-inventory", self.root / "never.sqlite3", "ws://127.0.0.1:8443"], "tls-client-ca-certs"),
                 (["--dns-resolver", "dns+tls://1.1.1.1", "ws://127.0.0.1:8443"], "sni"),
                 (["--dns-resolver", "dns://resolver.invalid", "ws://127.0.0.1:8443"], "IP address"),
                 (["--log-lvl", "[", "ws://127.0.0.1:8443"], "invalid")]
        for args, message in cases:
            with self.subTest(args=args):
                result = self.invoke("-t", *args, valid=False)
                self.assertIn(message, result.stderr)
        self.invoke("-t", "--dns-resolver", "dns+tls://1.1.1.1?sni=cloudflare-dns.com",
                    "--restrict-to", "[::1]:443", "wss://127.0.0.1:8443")

    def test_bad_policies_and_tenant_references(self):
        cases = [("restrict-config", "restrictions: [", "Cannot load restriction"),
                 ("restrict-config", "restrictions: []\nresrictions: []\n", "unknown field"),
                 ("restrict-config", "restrictions:\n- name: x\n  match: [Any]\n  allow:\n  - !Tunnel\n    protcol: [Tcp]\n", "unknown field"),
                 ("restrict-config", "restrictions:\n- name: x\n  match: [Any]\n  allow:\n  - !Tunnel\n    port: [\"200..100\"]\n", "Port range"),
                 ("device-quota-config", "version: 1\ndefault: {max_sessions: 0}\n", "nonzero"),
                 ("device-quota-config", "version: 1\ndefault: {max_sesions: 1}\n", "unknown field"),
                 ("device-revocation-config", "version: 1\nblocked_cert_sha256: [bad]\n", "fingerprint"),
                 ("device-revocation-config", "version: 1\nblocked_device: []\n", "unknown field"),
                 ("tenant-config", (ROOT / "tenant-policy.example.yaml").read_text().replace("alpha-forward", "missing-rule"), "missing-rule")]
        for option, content, message in cases:
            with self.subTest(option=option, message=message):
                policy = self.root / "invalid.yaml"
                policy.write_text(content)
                args = ["-t", *self.tls(), f"--{option}", policy]
                if option == "tenant-config":
                    args.extend(["--restrict-config", ROOT / "tenant-restrictions.example.yaml"])
                result = self.invoke(*args, "wss://127.0.0.1:8443", valid=False)
                self.assertIn(message, result.stderr)
        result = self.invoke("-t", "--restrict-config", self.root / "missing.yaml", "ws://127.0.0.1:8443", valid=False)
        self.assertIn("missing.yaml", result.stderr)

    def test_startup_rejects_the_same_invalid_restriction(self):
        policy = self.root / "startup-invalid.yaml"
        policy.write_text("restrictions: []\nresrictions: []\n")
        result = self.invoke("--restrict-config", policy, "ws://127.0.0.1:0", valid=False)
        self.assertIn("unknown field", result.stderr)

    def test_environment_policy_is_checked(self):
        result = self.invoke("-t", *self.tls(), "wss://127.0.0.1:8443", valid=False,
                             env={**self.env, "TUNWARD_DEVICE_QUOTA_CONFIG": str(self.root / "missing-quota.yaml")})
        self.assertIn("missing-quota.yaml", result.stderr)

    def test_error_exit_codes(self):
        invalid_file = self.invoke("-t", "--restrict-config", self.root / "missing.yaml",
                                   "ws://127.0.0.1:8443", valid=False)
        self.assertEqual(invalid_file.returncode, 1)
        invalid_usage = self.invoke("-t", "--unknown-option", "ws://127.0.0.1:8443", valid=False)
        self.assertEqual(invalid_usage.returncode, 2)

    def test_mtls_prerequisite_diagnostics(self):
        cases = [("device-quota-config", ROOT / "device-quotas.example.yaml", "device quotas require TLS"),
                 ("device-revocation-config", ROOT / "device-revocations.example.yaml", "device revocation requires TLS"),
                 ("tenant-config", ROOT / "tenant-policy.example.yaml", "tenant isolation requires TLS"),
                 ("fleet-inventory", self.root / "never-created.sqlite3", "fleet inventory requires TLS")]
        for option, path, message in cases:
            for flag in ([], ["-t"]):
                with self.subTest(option=option, validation=bool(flag)):
                    result = self.invoke(*flag, "--tls-client-ca-certs", self.certs / "ca.pem",
                                         "--restrict-config", ROOT / "tenant-restrictions.example.yaml",
                                         f"--{option}", path, "ws://127.0.0.1:0", valid=False)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(message, result.stderr)
        self.assertFalse((self.root / "never-created.sqlite3").exists())

    def test_systemd_prestart_uses_startup_arguments(self):
        lines = (ROOT / "deploy" / "tunward.service").read_text().replace("\\\n", "").splitlines()
        commands = {line.split("=", 1)[0]: line.split("=", 1)[1].split()
                    for line in lines if line.startswith(("ExecStart=", "ExecStartPre="))}
        prestart = commands["ExecStartPre"]
        self.assertEqual(prestart.count("--test-config"), 1)
        self.assertEqual([arg for arg in prestart if arg != "--test-config"], commands["ExecStart"])

    def test_invalid_tls_files_and_mismatched_key(self):
        result = self.invoke("-t", "--tls-certificate", self.certs / "server.pem", "--tls-private-key",
                             self.certs / "client.key", "wss://127.0.0.1:8443", valid=False)
        self.assertIn("invalid tls certificate or private key", result.stderr)
        for suffix in ("", "-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n",
                       "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"):
            with self.subTest(suffix=suffix):
                bundle = self.root / "bad.pem"
                bundle.write_text((self.certs / "ca.pem").read_text() + suffix if suffix else "")
                result = self.invoke("-t", "--tls-client-ca-certs", bundle, "wts://127.0.0.1:8443", valid=False)
                self.assertIn("Cannot load client CA", result.stderr)


if __name__ == "__main__":
    unittest.main()
