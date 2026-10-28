"""The auto-close workflow keeps an issue open only when its body matches a pattern; every issue
template must match it, or issues filed correctly through the templates are closed."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "auto-close.yaml"
TEMPLATES = sorted((ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.md"))


def template_pattern():
    # The pattern is a JavaScript literal with the `m` flag; Python's re.MULTILINE matches it the same way.
    found = re.search(r"const template = /(.+)/m;", WORKFLOW.read_text())
    if found is None:
        raise AssertionError("auto-close.yaml no longer declares `const template = /.../m;`")
    return re.compile(found.group(1), re.MULTILINE)


def issue_body(template):
    text = template.read_text()
    # GitHub drops the YAML front matter when it prefills the issue body.
    return text.split("---", 2)[2] if text.startswith("---") else text


class IssueTemplateTests(unittest.TestCase):
    def test_every_template_keeps_its_issues_open(self):
        self.assertTrue(TEMPLATES, "no issue templates found")
        pattern = template_pattern()
        for template in TEMPLATES:
            body = issue_body(template)
            # The web form submits CRLF line endings.
            for ending, text in (("LF", body), ("CRLF", body.replace("\n", "\r\n"))):
                with self.subTest(template=template.name, line_endings=ending):
                    self.assertIsNotNone(pattern.search(text), f"{template.name} would be closed")

    def test_issues_without_a_template_are_still_closed(self):
        pattern = template_pattern()
        for body in ("", "It broke.", "**Describe the bug**\nIt broke.", "### Goal\nI want X"):
            with self.subTest(body=body):
                self.assertIsNone(pattern.search(body))


if __name__ == "__main__":
    unittest.main()
