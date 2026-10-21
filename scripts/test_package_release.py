import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from check_release_artifacts import ARTIFACTS
from package_release import package


class PackageReleaseTests(unittest.TestCase):
    def fixture(self, root):
        source, artifacts = root / "source", root / "artifacts"
        source.mkdir()
        for name in ("tunward", "tunward-cli"):
            directory = source / name
            directory.mkdir()
            (directory / "Cargo.toml").write_text('[package]\nversion = "0.1.0-beta"\n')
        (source / "README.md").write_text("Beta fixture\n")
        (source / "LICENSE").write_text("License fixture\n")
        artifacts.mkdir()
        for name, filename in ARTIFACTS.items():
            directory = artifacts / name
            directory.mkdir()
            (directory / filename).write_bytes(name.encode())
        return source, artifacts

    def test_all_fourteen_archives_match_original_bytes_and_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, artifacts = self.fixture(root)
            output = root / "dist"
            files = package(source, artifacts, output, "v0.1.0-beta", "a" * 40, 1700000000, "123")
            self.assertEqual(len(files), 16)
            manifest = json.loads((output / "release-manifest.json").read_text())
            self.assertEqual(len(manifest["binaries"]), 14)
            self.assertEqual(manifest["source_run_id"], "123")
            self.assertIn("android_armv7.tar.gz", " ".join(p.name for p in files))
            for row in manifest["binaries"]:
                binary_name = ARTIFACTS[row["artifact"]]
                with tarfile.open(output / row["archive"]) as tf:
                    self.assertEqual(set(tf.getnames()), {binary_name, "LICENSE", "README.md"})
                    member = tf.getmember(binary_name)
                    self.assertEqual((member.mode, member.uid, member.gid, member.mtime), (0o755, 0, 0, 1700000000))
                    self.assertEqual(tf.extractfile(member).read(), (artifacts / row["artifact"] / binary_name).read_bytes())
            for line in (output / "checksums.txt").read_text().splitlines():
                digest, filename = line.split("  ")
                self.assertEqual(hashlib.sha256((output / filename).read_bytes()).hexdigest(), digest)

    def test_repeated_packaging_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, artifacts = self.fixture(root)
            package(source, artifacts, root / "first", "v0.1.0-beta", "a" * 40, 1700000000, "123")
            package(source, artifacts, root / "second", "v0.1.0-beta", "a" * 40, 1700000000, "123")
            for path in (root / "first").iterdir():
                self.assertEqual(path.read_bytes(), (root / "second" / path.name).read_bytes())

    def test_rejects_wrong_version_or_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, artifacts = self.fixture(root)
            with self.assertRaises(ValueError):
                package(source, artifacts, root / "wrong", "v0.2.0-beta", "a" * 40, 1700000000, "123")
            self.assertFalse((root / "wrong").exists())
            output = root / "existing"
            output.mkdir()
            with self.assertRaises(FileExistsError):
                package(source, artifacts, output, "v0.1.0-beta", "a" * 40, 1700000000, "123")


if __name__ == "__main__":
    unittest.main()
