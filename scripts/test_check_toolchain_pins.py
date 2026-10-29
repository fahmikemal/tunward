"""The toolchain pin check accepts matching pins and reports every mismatched or missing one."""
from pathlib import Path
import tempfile
import unittest

from check_toolchain_pins import SOURCES, problems


# How each source states a pin, and how it reads without one; workflows use the default.
TEMPLATES = {
    "Dockerfile": ("FROM rust:{}-trixie AS builder\n", "FROM debian:trixie-slim\n"),
    "README.md": ("CI currently uses Rust {}. The manifests use edition 2024.\n", "CI uses a recent Rust.\n"),
    "CONTRIBUTING.md": ("CI pins Rust {} and uses edition 2024.\n", "CI pins a recent Rust.\n"),
}
WORKFLOW = ('env:\n  RUST_VERSION: "{}"\n', "env: {}\n")


def tree(root, channel, pins):
    (root / "rust-toolchain.toml").write_text(f'[toolchain]\nchannel = "{channel}"\n')
    (root / ".github" / "workflows").mkdir(parents=True)
    for name in SOURCES:
        version = pins.get(name)
        pinned, unpinned = TEMPLATES.get(name, WORKFLOW)
        (root / name).write_text(pinned.format(version) if version else unpinned)


class ToolchainPinTests(unittest.TestCase):
    def test_matching_pins_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree(root, "1.97", {name: "1.97" for name in SOURCES})
            self.assertEqual(problems(root), [])

    def test_a_mismatched_pin_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree(root, "1.97", {**{name: "1.97" for name in SOURCES}, "Dockerfile": "1.96"})
            self.assertEqual(problems(root), ["Dockerfile: pins 1.96, rust-toolchain.toml pins 1.97"])

    def test_a_stale_documented_version_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree(root, "1.99", {**{name: "1.99" for name in SOURCES}, "README.md": "1.97"})
            self.assertEqual(problems(root), ["README.md: pins 1.97, rust-toolchain.toml pins 1.99"])

    def test_a_removed_pin_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pins = {name: "1.97" for name in SOURCES}
            del pins[".github/workflows/release.yaml"]
            tree(root, "1.97", pins)
            self.assertEqual(problems(root), [".github/workflows/release.yaml: no Rust toolchain pin found"])

    def test_the_repository_pins_agree(self):
        self.assertEqual(problems(), [])


if __name__ == "__main__":
    unittest.main()
