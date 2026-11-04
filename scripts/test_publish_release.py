import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from publish_release import publish


TAG = "v0.1.0-beta"
ASSET = "tunward_0.1.0-beta.intoto.jsonl"


def write_bundle(path, subjects, extra_lines=0):
    statement = {"subject": [{"name": name, "digest": {"sha256": digest}} for name, digest in subjects.items()]}
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    path.write_text((json.dumps({"dsseEnvelope": {"payload": payload}}) + "\n") * (1 + extra_lines))


class PublishReleaseTests(unittest.TestCase):
    def fixture(self, root):
        dist = root / "dist"
        dist.mkdir()
        for name in ("checksums.txt", "release-manifest.json", "tunward_0.1.0-beta_linux_amd64.tar.gz"):
            (dist / name).write_text(name)
        subjects = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in dist.iterdir()}
        return dist, subjects

    def test_the_bundle_verifies_and_is_published_beside_the_files_it_attests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist, subjects = self.fixture(root)
            write_bundle(root / "attestation.json", subjects)
            with mock.patch("subprocess.run") as run:
                publish(dist, root / "attestation.json", TAG, "owner/repo")
            self.assertEqual((dist / ASSET).read_bytes(), (root / "attestation.json").read_bytes())
            verify, create = (call.args[0] for call in run.call_args_list)
            self.assertEqual(verify[:3], ["gh", "attestation", "verify"])
            self.assertEqual(verify[3:], [str(dist / "checksums.txt"), "--bundle", str(dist / ASSET), "--repo", "owner/repo"])
            self.assertEqual(create[:4], ["gh", "release", "create", TAG])
            published = [Path(argument).name for argument in create[4:8]]
            self.assertEqual(published, sorted([*subjects, ASSET]))
            self.assertEqual(create[8:], ["--repo", "owner/repo", "--verify-tag", "--latest=false",
                                          "--title", TAG, "--generate-notes", "--prerelease"])
            for call in run.call_args_list:
                self.assertEqual(call.kwargs, {"check": True})

    def test_only_a_tag_with_a_prerelease_part_is_marked_prerelease(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist, subjects = self.fixture(root)
            write_bundle(root / "attestation.json", subjects)
            with mock.patch("subprocess.run") as run:
                publish(dist, root / "attestation.json", "v0.1.0", "owner/repo")
            self.assertTrue((dist / "tunward_0.1.0.intoto.jsonl").is_file())
            self.assertNotIn("--prerelease", run.call_args_list[-1].args[0])

    def test_refuses_a_bundle_that_does_not_cover_exactly_the_packaged_files(self):
        def missing(subjects):
            subjects.pop("release-manifest.json")

        def unexpected(subjects):
            subjects["other.tar.gz"] = "0" * 64

        def changed(subjects):
            subjects["checksums.txt"] = "0" * 64

        for tamper in (missing, unexpected, changed):
            with self.subTest(tamper.__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                dist, subjects = self.fixture(root)
                tamper(subjects)
                write_bundle(root / "attestation.json", subjects)
                with mock.patch("subprocess.run") as run, self.assertRaisesRegex(ValueError, "differs"):
                    publish(dist, root / "attestation.json", TAG, "owner/repo")
                run.assert_not_called()
                self.assertFalse((dist / ASSET).exists())

    def test_refuses_a_bundle_without_exactly_one_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist, subjects = self.fixture(root)
            (root / "empty.json").write_text("")
            write_bundle(root / "two.json", subjects, extra_lines=1)
            for bundle in ("empty.json", "two.json"):
                with mock.patch("subprocess.run") as run, self.assertRaisesRegex(ValueError, "expected one attestation"):
                    publish(dist, root / bundle, TAG, "owner/repo")
                run.assert_not_called()

    def test_a_failed_verification_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist, subjects = self.fixture(root)
            write_bundle(root / "attestation.json", subjects)
            failure = subprocess.CalledProcessError(1, "gh attestation verify")
            with mock.patch("subprocess.run", side_effect=failure) as run, self.assertRaises(subprocess.CalledProcessError):
                publish(dist, root / "attestation.json", TAG, "owner/repo")
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][:3], ["gh", "attestation", "verify"])


if __name__ == "__main__":
    unittest.main()
