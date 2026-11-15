import copy
from pathlib import Path
import re
import tempfile
import unittest

from check_release_artifacts import ARTIFACTS, BUILD_NAMES, TARGETS, verify_download, verify_recovery


class ReleaseArtifactTests(unittest.TestCase):
    def receipt(self):
        commit, tag, repository = "a" * 40, "v0.1.0-beta", "example/tunward"
        run = {"repository": {"full_name": repository}, "event": "push", "path": ".github/workflows/release.yaml",
               "head_branch": tag, "head_sha": commit, "status": "completed", "conclusion": "failure"}
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yaml").read_text()
        builds = re.findall(r"^\s+- name: (.+)\n(?:\s+os: .+\n)?\s+target: ([\w-]+)$", workflow, re.MULTILINE)
        names = ["Validate release tag and publication credentials", "Check - format, lint & tests",
                 "Publish Docker Hub image", *[f"native-runtime / native ({os})" for os in
                                               ("ubuntu-24.04", "macos-14", "windows-2022")],
                 *[f"Build - {name}" for name, _ in builds]]
        jobs = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
        jobs.append({"name": "Release", "status": "completed", "conclusion": "failure"})
        artifacts = [{"name": name, "expired": False, "workflow_run": {"head_sha": commit}} for name in ARTIFACTS]
        return [run, jobs, artifacts, [], repository, tag, commit]

    def test_allows_only_failed_packaging_after_successful_publication(self):
        receipt = self.receipt()
        receipt[2].extend([{"name": "example~tunward~record.dockerbuild"}, {"name": "native-runtime-ubuntu"}])
        verify_recovery(*receipt)

    def test_accepts_the_current_native_runtime_matrix(self):
        receipt = self.receipt()
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/runtime-qualification.yaml").read_text()
        runners = re.search(r"os: \[([^\]]+)\]", workflow).group(1).split(",")
        receipt[1] = [j for j in receipt[1] if not j["name"].startswith("native-runtime / native (")]
        receipt[1].extend({"name": f"native-runtime / native ({runner.strip()})", "status": "completed", "conclusion": "success"}
                          for runner in runners)
        verify_recovery(*receipt)

    def test_an_unexpected_build_cannot_replace_a_required_build(self):
        receipt = self.receipt()
        build = next(j for j in receipt[1] if j["name"].startswith("Build - "))
        build["name"] = "Build - unrelated target"
        with self.assertRaises(ValueError): verify_recovery(*receipt)

    def test_rejects_two_native_macos_jobs(self):
        receipt = self.receipt()
        receipt[1].append({"name": "native-runtime / native (macos-15)", "status": "completed", "conclusion": "success"})
        with self.assertRaises(ValueError): verify_recovery(*receipt)

    def test_rejects_wrong_run_provenance(self):
        for key, value in (("event", "pull_request"), ("path", ".github/workflows/ci.yaml"),
                           ("head_branch", "main"), ("head_sha", "b" * 40),
                           ("status", "in_progress"), ("conclusion", "success"),
                           ("repository", {"full_name": "another/repository"})):
            with self.subTest(key=key):
                receipt = self.receipt()
                receipt[0][key] = value
                with self.assertRaises(ValueError): verify_recovery(*receipt)

    def test_rejects_failed_or_missing_prerequisites(self):
        for name in [job["name"] for job in self.receipt()[1][:-1]]:
            with self.subTest(name=name):
                receipt = self.receipt()
                next(job for job in receipt[1] if job["name"] == name)["conclusion"] = "failure"
                with self.assertRaises(ValueError): verify_recovery(*receipt)
                receipt[1] = [job for job in receipt[1] if job["name"] != name]
                with self.assertRaises(ValueError): verify_recovery(*receipt)

    def test_rejects_duplicate_jobs_or_completed_release(self):
        for duplicate in (True, False):
            receipt = self.receipt()
            if duplicate: receipt[1].append(copy.deepcopy(receipt[1][0]))
            else: receipt[1][-1]["conclusion"] = "success"
            with self.assertRaises(ValueError): verify_recovery(*receipt)

    def test_rejects_incomplete_expired_foreign_or_duplicate_binary_artifacts(self):
        for case in ("missing", "expired", "foreign", "duplicate", "unexpected"):
            with self.subTest(case=case):
                receipt = self.receipt()
                if case == "missing": receipt[2].pop()
                elif case == "expired": receipt[2][0]["expired"] = True
                elif case == "foreign": receipt[2][0]["workflow_run"]["head_sha"] = "b" * 40
                elif case == "duplicate": receipt[2].append(copy.deepcopy(receipt[2][0]))
                else: receipt[2].append({"name": "tunward-unexpected"})
                with self.assertRaises(ValueError): verify_recovery(*receipt)

    def test_rejects_existing_draft_or_published_release(self):
        for draft in (True, False):
            receipt = self.receipt()
            receipt[3].append({"tag_name": receipt[5], "draft": draft})
            with self.assertRaises(ValueError): verify_recovery(*receipt)

    def test_rejects_other_failed_jobs(self):
        receipt = self.receipt()
        receipt[1].append({"name": "Additional gate", "status": "completed", "conclusion": "failure"})
        with self.assertRaises(ValueError): verify_recovery(*receipt)

    def populate(self, root):
        for name, filename in ARTIFACTS.items():
            directory = root / name
            directory.mkdir()
            (directory / filename).write_bytes(b"binary fixture")
            (directory / filename).chmod(0o644)

    def test_restores_executable_modes_for_every_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate(root)
            verify_download(root)
            for name, filename in ARTIFACTS.items():
                self.assertEqual((root / name / filename).stat().st_mode & 0o777, 0o755)

    def test_download_rejects_non_binary_inputs_and_empty_payloads(self):
        for case in ("missing", "extra-directory", "extra-file", "empty", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.populate(root)
                name, filename = next(iter(ARTIFACTS.items()))
                binary = root / name / filename
                if case == "missing": binary.unlink()
                elif case == "extra-directory": (root / "build.dockerbuild").mkdir()
                elif case == "extra-file": (root / name / "unexpected").write_text("unexpected")
                elif case == "empty": binary.write_bytes(b"")
                else:
                    binary.unlink()
                    binary.symlink_to(root / list(ARTIFACTS)[1] / filename)
                with self.assertRaises(ValueError): verify_download(root)

    def test_targets_match_release_build_matrix(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yaml").read_text()
        targets = re.findall(r"^\s+target: ([\w-]+)\s*$", workflow, re.MULTILINE)
        self.assertEqual(set(TARGETS), set(targets))
        self.assertEqual(len(TARGETS), len(targets))
        builds = re.findall(r"^\s+- name: (.+)\n(?:\s+os: .+\n)?\s+target: ([\w-]+)$", workflow, re.MULTILINE)
        self.assertEqual(dict(zip(TARGETS, BUILD_NAMES, strict=True)), {target: name for name, target in builds})


if __name__ == "__main__":
    unittest.main()
