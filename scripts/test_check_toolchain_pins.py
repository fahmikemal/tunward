"""The toolchain pin check accepts matching pins and reports every mismatched or missing one."""
from pathlib import Path
import tempfile
import unittest

from check_toolchain_pins import SOURCES, problems


def tree(root, channel, pins):
    (root / "rust-toolchain.toml").write_text(f'[toolchain]\nchannel = "{channel}"\n')
    (root / ".github" / "workflows").mkdir(parents=True)
    for name in SOURCES:
        version = pins.get(name)
        if name == "Dockerfile":
            text = f"FROM rust:{version}-trixie AS builder\n" if version else "FROM debian:trixie-slim\n"
        else:
            text = f'env:\n  RUST_VERSION: "{version}"\n' if version else "env: {}\n"
        (root / name).write_text(text)


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
