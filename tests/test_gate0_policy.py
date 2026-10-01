"""Source refusal and sensitivity checks; live controls need separate evidence."""

from hashlib import sha256
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

    def test_privileged_workflow_bytes_remain_at_admitted_digest(self) -> None:
        self.assertEqual(
            sha256(EXPECTED_WORKFLOWS["gate0-issuer.yml"].encode("utf-8")).hexdigest(),
            "2a62feee21d8236de28e21bb8850c4e0388a39f71cce4338b1c60e0741b876fd",
        )

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

    def test_temporary_probe_boundaries_reject_mutations(self) -> None:
        path = self.workflows / "policy.yml"
        original = EXPECTED_WORKFLOWS[path.name]
        changes = {
            "dispatch trigger": ("  workflow_dispatch:\n", "  workflow_call:\n"),
            "PR target trigger": ("  pull_request_target:\n    branches: [main]", "  schedule:\n    branches: [main]"),
            "PR target base": ("  pull_request_target:\n    branches: [main]", "  pull_request_target:\n    branches: [dev]"),
            "group job event guard": (
                "  probe_group:\n    if: ${{ github.event_name == 'workflow_dispatch' || github.event_name == 'pull_request' || github.event_name == 'pull_request_target' }}",
                "  probe_group:\n    if: ${{ always() }}",
            ),
            "label job event guard": (
                "  probe_label:\n    if: ${{ github.event_name == 'workflow_dispatch' || github.event_name == 'pull_request' || github.event_name == 'pull_request_target' }}",
                "  probe_label:\n    if: ${{ always() }}",
            ),
            "group selector": ("      group: gate0-issuer-protected", "      group: general"),
            "group label": ("      labels: gate0-managed-20261001-only", "      labels: general"),
            "label-only selector": ("    runs-on: gate0-managed-20261001-only", "    runs-on: ubuntu-latest"),
            "job permissions": ("    permissions: {}", "    permissions:\n      id-token: write"),
            "no environment": ("    timeout-minutes: 1", "    environment: rehearsal-issuer-protected\n    timeout-minutes: 1"),
            "short timeout": ("    timeout-minutes: 1", "    timeout-minutes: 5"),
            "no checkout": ("        shell: bash", "        uses: actions/checkout@v4\n        shell: bash"),
            "failure marker": ("          echo \"SCHEDULING_REFUSAL_FAILED\" >&2", "          echo \"admitted\" >&2"),
            "failure exit": ("          exit 1", "          exit 0"),
        }
        for boundary, (old, new) in changes.items():
            with self.subTest(boundary=boundary):
                self.assertIn(old, original)
                path.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.assertTrue(policy_errors(self.root))


if __name__ == "__main__":
    unittest.main()
