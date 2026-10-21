#!/usr/bin/env python3
"""Create a development mTLS bundle without overwriting existing keys."""

import argparse
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def openssl(directory, *arguments):
    result = subprocess.run(["openssl", *arguments], cwd=directory, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def dns_name(value):
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise argparse.ArgumentTypeError("invalid DNS name") from exc
    labels = name.split(".")
    if len(name) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise argparse.ArgumentTypeError("use a DNS hostname without a scheme, port, or wildcard")
    return name


def client_identity(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
        raise argparse.ArgumentTypeError("client identity must be 1..64 URL-safe letters, digits, dots, underscores or hyphens")
    return value


def generate(args):
    os.umask(0o077)
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}; choose a new --output directory")
    if not shutil.which("openssl"):
        raise RuntimeError("OpenSSL is required")
    template = Path(__file__).resolve().parents[1] / "certs/mTLS/openssl.cnf"
    config = template.read_text()
    dns = args.dns or ([] if args.ip else ["localhost"])
    ips = args.ip or ([] if args.dns else [ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")])
    names = "\n".join([f"DNS.{i} = {name}" for i, name in enumerate(dns, 1)] +
                      [f"IP.{i} = {address}" for i, address in enumerate(ips, 1)])
    config, replacements = re.subn(r"(?ms)^\[ server_names \]\n.*?(?=^\[|\Z)",
                                    "[ server_names ]\n" + names + "\n\n", config)
    if replacements != 1:
        raise RuntimeError("OpenSSL template must contain exactly one server_names section")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".mtls-generate-", dir=output.parent) as temporary:
        stage = Path(temporary)
        for directory in ("certs", "csr", "private", "newcerts", "crl"):
            (stage / directory).mkdir(mode=0o700)
        (stage / "openssl.cnf").write_text(config)
        (stage / "index.txt").write_text("")
        (stage / "index.txt.attr").write_text("unique_subject = yes\n")
        (stage / "serial").write_text("1000\n")
        (stage / "crlnumber").write_text("1000\n")
        openssl(stage, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", "private/ca.key.pem")
        openssl(stage, "req", "-config", "openssl.cnf", "-key", "private/ca.key.pem", "-new", "-x509",
                "-days", "3650", "-sha256", "-extensions", "v3_ca", "-subj", "/O=tunward development/CN=tunward Development Root CA",
                "-out", "certs/ca.cert.pem")
        for stem, cn, extension in (("tunward-server", "tunward Development Server", "server_cert"),
                                    ("tunward-client-1", args.client_id, "client_cert")):
            key, csr, cert = f"private/{stem}.pem", f"csr/{stem}.csr.pem", f"certs/{stem}.cert.pem"
            openssl(stage, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", key)
            openssl(stage, "req", "-config", "openssl.cnf", "-key", key, "-new", "-sha256",
                    "-subj", f"/O=tunward development/CN={cn}", "-out", csr)
            openssl(stage, "ca", "-batch", "-config", "openssl.cnf", "-extensions", extension, "-days", "365",
                    "-notext", "-md", "sha256", "-in", csr, "-out", cert)
        for stem, key in (("ca", "ca.key"), ("tunward-server", "tunward-server"), ("tunward-client-1", "tunward-client-1")):
            openssl(stage, "pkey", "-in", f"private/{key}.pem", "-check", "-noout")
            public_cert = openssl(stage, "x509", "-in", f"certs/{stem}.cert.pem", "-pubkey", "-noout")
            if public_cert != openssl(stage, "pkey", "-in", f"private/{key}.pem", "-pubout"):
                raise RuntimeError(f"certificate/key mismatch: {stem}")
        for name in dns:
            openssl(stage, "verify", "-x509_strict", "-CAfile", "certs/ca.cert.pem", "-purpose", "sslserver",
                    "-verify_hostname", name, "certs/tunward-server.cert.pem")
        for address in ips:
            openssl(stage, "verify", "-x509_strict", "-CAfile", "certs/ca.cert.pem", "-purpose", "sslserver",
                    "-verify_ip", str(address), "certs/tunward-server.cert.pem")
        openssl(stage, "verify", "-x509_strict", "-CAfile", "certs/ca.cert.pem", "-purpose", "sslclient",
                "certs/tunward-client-1.cert.pem")
        shutil.copytree(stage, output)
    print(f"Created development bundle: {output}")
    print(f"Server SANs: {', '.join([*dns, *map(str, ips)])}")
    print(f"Client CN/path prefix: {args.client_id}")
    print("CA chain, certificate purposes, names, and private-key matches verified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("certs/mTLS/generated"))
    parser.add_argument("--dns", action="append", type=dns_name, help="server DNS SAN; repeat for multiple names")
    parser.add_argument("--ip", action="append", type=ipaddress.ip_address, help="server IP SAN; repeat for multiple addresses")
    parser.add_argument("--client-id", type=client_identity, default="tunward_client_1")
    args = parser.parse_args()
    try:
        generate(args)
    except (OSError, RuntimeError) as exc:
        parser.exit(1, f"Generation failed: {exc}\n")


if __name__ == "__main__":
    main()
