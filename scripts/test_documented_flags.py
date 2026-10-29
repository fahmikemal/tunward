"""Every option README's CLI tables name exists in the binary's help, so a table cannot keep
documenting an option after it is renamed or removed."""
import os
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("TUNWARD_TEST_BINARY", ROOT / "target/release/tunward"))
OPTION = re.compile(r"(?<![\w-])(--?[A-Za-z][\w-]*)")


def documented_options(readme):
    """Options in the first cell of every table row that starts with one, such as | `-c, --connection-min-idle N` |."""
    options = set()
    for line in readme.splitlines():
        if line.startswith("| `-"):
            options.update(OPTION.findall(line.split("|")[1]))
    return options


def available_options(binary):
    help_text = "".join(
        subprocess.run([str(binary), *command, "--help"], capture_output=True, text=True, check=True).stdout
        for command in ([], ["client"], ["server"])
    )
    return set(OPTION.findall(help_text))


class DocumentedOptionTests(unittest.TestCase):
    def test_option_extraction(self):
        rows = "| `-c, --connection-min-idle N` | x |\n| `--tls-verify-certificate[=true\\|false]` | y |\n| `cn` | `--not-a-row` |\n"
        self.assertEqual(documented_options(rows), {"-c", "--connection-min-idle", "--tls-verify-certificate"})

    def test_readme_tables_name_only_existing_options(self):
        if not BINARY.exists():
            self.skipTest(f"build {BINARY} first")
        documented = documented_options((ROOT / "README.md").read_text())
        self.assertGreater(len(documented), 20)
        self.assertEqual(documented - available_options(BINARY), set())


if __name__ == "__main__":
    unittest.main()
