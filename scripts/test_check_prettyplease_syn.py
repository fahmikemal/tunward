"""The prettyplease/syn check accepts matching syn versions and names every crate that mixes them."""
import unittest

from check_prettyplease_syn import ROOT, problems


def lock(bindgen_syn, printer):
    return f'''
[[package]]
name = "syn"
version = "2.0.119"

[[package]]
name = "syn"
version = "3.0.6"

[[package]]
name = "prettyplease"
version = "0.2.37"
dependencies = ["syn 2.0.119"]

[[package]]
name = "prettyplease"
version = "0.3.0"
dependencies = ["syn 3.0.6"]

[[package]]
name = "bindgen"
version = "0.73.2"
dependencies = ["log", "prettyplease {printer}", "syn {bindgen_syn}"]

[[package]]
name = "log"
version = "0.4.29"
'''


class PrettypleaseSynTests(unittest.TestCase):
    def test_matching_syn_versions_pass(self):
        self.assertEqual(problems(lock("3.0.6", "0.3.0")), [])
        self.assertEqual(problems(lock("2.0.119", "0.2.37")), [])

    def test_syn_3_next_to_prettyplease_on_syn_2_is_reported(self):
        self.assertEqual(
            problems(lock("3.0.6", "0.2.37")),
            ["bindgen@0.73.2 uses syn 3.0.6 but its prettyplease 0.2.37 uses syn 2.0.119; "
             "run `cargo update -p bindgen@0.73.2 -p prettyplease` and check again"],
        )

    def test_references_without_a_version_name_the_only_locked_one(self):
        single = '''
[[package]]
name = "syn"
version = "2.0.119"

[[package]]
name = "prettyplease"
version = "0.2.37"
dependencies = ["syn"]

[[package]]
name = "bindgen"
version = "0.72.1"
dependencies = ["prettyplease", "syn"]
'''
        self.assertEqual(problems(single), [])

    def test_the_repository_lock_passes(self):
        self.assertEqual(problems((ROOT / "Cargo.lock").read_text()), [])


if __name__ == "__main__":
    unittest.main()
