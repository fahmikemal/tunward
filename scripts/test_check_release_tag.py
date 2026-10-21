from pathlib import Path
import tempfile
import unittest

from check_release_tag import validate


class ReleaseTagTests(unittest.TestCase):
    def manifests(self, root, version):
        for name in ("tunward", "tunward-cli"):
            (root / name).mkdir(exist_ok=True)
            (root / name / "Cargo.toml").write_text(f'[package]\nversion = "{version}"\n')

    def test_release_and_prerelease_tags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for version in ("0.1.0-beta", "1.2.3", "2.0.0-rc.1"):
                with self.subTest(version=version):
                    self.manifests(root, version)
                    self.assertEqual(validate("refs/tags/v" + version, root), "v" + version)

    def test_rejects_non_tags_and_invalid_image_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.manifests(root, "0.1.0-beta")
            for ref in ("refs/heads/main", "refs/pull/1/merge", "refs/tags/0.1.0-beta",
                        "refs/tags/v01.0.0", "refs/tags/v1.0.0-rc.01", "refs/tags/v1.0.0+build",
                        "refs/tags/v1.0.0-", "refs/tags/v1.0.0-" + "x" * 128):
                with self.subTest(ref=ref), self.assertRaises(ValueError):
                    validate(ref, root)

    def test_both_package_versions_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.manifests(root, "0.1.0-beta")
            with self.assertRaises(ValueError):
                validate("refs/tags/v0.1.0", root)
            (root / "tunward-cli/Cargo.toml").write_text('[package]\nversion = "0.1.1-beta"\n')
            with self.assertRaises(ValueError):
                validate("refs/tags/v0.1.0-beta", root)


if __name__ == "__main__":
    unittest.main()
