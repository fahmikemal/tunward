#!/usr/bin/env python3
"""Validate a server certificate/key/issuer bundle before renewal or deployment; never prints key material."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import time


def validate(certificate, private_key, issuer_ca, name, minimum_days=30):
    def openssl(*args):
        result = subprocess.run(["openssl", *map(str, args)], capture_output=True, timeout=15)
        if result.returncode:
            raise ValueError(result.stderr.decode(errors="replace").strip())
        return result.stdout
    if minimum_days < 0 or not name:
        raise ValueError("minimum validity must be nonnegative and server name must be supplied")
    if os.name == "posix":
        mode = stat.S_IMODE(private_key.stat().st_mode)
        if mode & 0o027:
            raise ValueError("private key must not be writable by its group or accessible to other users")
    # OpenSSL validates the complete chain at the required future deployment horizon.
    horizon = int(time.time()) + minimum_days * 86400
    try:
        ipaddress.ip_address(name)
        name_option = "-verify_ip"
    except ValueError:
        name_option = "-verify_hostname"
    san = openssl("x509", "-in", certificate, "-noout", "-ext", "subjectAltName").decode()
    required_san_type = "IP Address:" if name_option == "-verify_ip" else "DNS:"
    if required_san_type not in san:
        raise ValueError("server certificate needs an appropriate SAN; legacy CN-only matching is not accepted")
    openssl("verify", "-x509_strict", "-purpose", "sslserver", "-attime", horizon,
            "-CAfile", issuer_ca, "-untrusted", certificate, name_option, name, certificate)
    cert_public = openssl("x509", "-in", certificate, "-pubkey", "-noout")
    key_public = openssl("pkey", "-in", private_key, "-pubout", "-passin", "pass:")
    if cert_public != key_public:
        raise ValueError("server certificate and private key do not match")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    details = openssl("x509", "-in", certificate, "-noout", "-serial", "-dates", "-fingerprint", "-sha256").decode().strip()
    return {"status": "pass", "server_name": name, "minimum_valid_days": minimum_days,
            "certificate_file_sha256": hashlib.sha256(certificate.read_bytes()).hexdigest(),
            "issuer_bundle_sha256": hashlib.sha256(issuer_ca.read_bytes()).hexdigest(), "certificate_details": details,
            "scope": "current and future-horizon issuer chain, server purpose/name, key match and local permissions; no issuance, live probe, revocation lookup or activation"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--issuer-ca", type=Path, required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--minimum-valid-days", type=int, default=30)
    args = parser.parse_args()
    try:
        report = validate(args.certificate, args.private_key, args.issuer_ca, args.server_name, args.minimum_valid_days)
    except (OSError, ValueError, ssl.SSLError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"TLS bundle rejected: {exc}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
