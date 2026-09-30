"""Source refusal and sensitivity checks; live controls need separate evidence."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.check_gate0_policy import EXPECTED_WORKFLOWS, policy_errors


class Gate0PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workflows = self.root / ".github" / "workflows"
        self.workflows.mkdir(parents=True)
        for name, source in EXPECTED_WORKFLOWS.items():
            (self.workflows / name).write_text(source, encoding="utf-8")

    def test_checked_in_workflows_match_policy(self) -> None:
        self.assertEqual(policy_errors(Path(__file__).resolve().parents[1]), [])

    def test_canonical_workflows_pass(self) -> None:
        self.assertEqual(policy_errors(self.root), [])

    def test_privileged_boundary_mutations_fail(self) -> None:
        changes = {
            "PR trigger": ("  workflow_dispatch:", "  pull_request:\n  workflow_dispatch:"),
            "PR target trigger": ("  workflow_dispatch:", "  pull_request_target:\n  workflow_dispatch:"),
            "reusable trigger": ("  workflow_dispatch:", "  workflow_call:\n  workflow_dispatch:"),
            "event guard": ("github.event_name == 'workflow_dispatch'", "github.event_name == 'pull_request'"),
            "ref guard": ("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/dev'"),
            "environment": ("environment: rehearsal-issuer-protected", "environment: unprotected"),
            "runner group": ("group: gate0-issuer-protected", "group: general"),
            "token permission": ("id-token: write", "contents: write"),
            "action boundary": ("        shell: bash", "        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        shell: bash"),
            "refusal": ("          exit 1", "          exit 0"),
        }
        path = self.workflows / "gate0-issuer.yml"
        original = EXPECTED_WORKFLOWS[path.name]
        for boundary, (old, new) in changes.items():
            with self.subTest(boundary=boundary):
                self.assertIn(old, original)
                path.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.assertTrue(policy_errors(self.root))
        path.write_text(original, encoding="utf-8")

    def test_extra_workflow_cannot_select_protected_group(self) -> None:
        (self.workflows / "pr.yml").write_text(
            "on: [pull_request]\njobs:\n  probe:\n    runs-on:\n      group: gate0-issuer-protected\n",
            encoding="utf-8",
        )
        self.assertTrue(policy_errors(self.root))

    def test_policy_workflow_must_remain_hosted_and_unprivileged(self) -> None:
        path = self.workflows / "policy.yml"
        original = EXPECTED_WORKFLOWS[path.name]
        for old, new in (("ubuntu-latest", "gate0-issuer-protected"),
                         ("contents: read", "id-token: write"),
                         ("pull_request:", "workflow_dispatch:"),
                         ("actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "actions/checkout@v4")):
            with self.subTest(old=old):
                path.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.assertTrue(policy_errors(self.root))


if __name__ == "__main__":
    unittest.main()
