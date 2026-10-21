# Development mTLS material

This directory keeps the public OpenSSL template and instructions. Its
`.gitignore` excludes generated certificates, private keys, CSRs, CA databases,
serial counters, and backups. The root `.dockerignore` excludes the entire
directory from Docker build contexts.

From the repository root:

~~~sh
python3 scripts/generate_mtls.py
~~~

Output: `certs/mTLS/generated/`. The script requires Python 3 and OpenSSL and
refuses to overwrite an existing bundle. It verifies certificate/key matches,
server SANs, and server/client purposes. Existing local files directly under
`certs/mTLS` are preserved; they are not distributed as shared identities.

To choose development addresses and a client CN:

~~~sh
python3 scripts/generate_mtls.py --output certs/mTLS/development-device-001 \
  --dns tunnel.example.test --ip 192.0.2.10 --client-id device-001
~~~

Use your own names; explicit SANs replace the localhost defaults. Each new bundle
has its own CA. The generator does not renew an existing bundle or enroll devices
under an existing production CA.

Server/device certificates last 365 days, and the development CA lasts 3650 days.
Private keys are unencrypted and owner-only on POSIX; apply equivalent ACLs on
other platforms. Use operator-managed issuance and key storage for deployment.

A public CA certificate can be distributed to verifiers. Keep the CA signing
key with the issuer, the server key on its server, and each device key with that
device. Previously committed keys remain in history and must not be reused in
deployment.

See [the mTLS guide](../../docs/using_mtls.md) and
[the complete local quickstart](../../README.md#quickstart-verified-local-mtls).
