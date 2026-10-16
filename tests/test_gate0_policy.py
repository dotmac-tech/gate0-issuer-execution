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

    def test_proposed_producer_workflow_bytes_match_review_candidate(self) -> None:
        self.assertEqual(
            sha256(EXPECTED_WORKFLOWS["gate0-issuer.yml"].encode("utf-8")).hexdigest(),
            "127401d6d3f718d7a3900a5c426e01086b25175e2d9bc9759485f952adc39bc3",
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
            "expiry window": ("timeout-minutes: 12", "timeout-minutes: 60"),
            "action boundary": ("        shell: bash", "        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        shell: bash"),
            "refusal": ("          exit 1", "          exit 0"),
            "explicit mode": ('"$GATE0_E_MODE" != "e-readiness"', '"$GATE0_E_MODE" != "refuse"'),
            "repository identity": ("github.repository_id == '1397614140'", "github.repository_id == '1'"),
            "owner identity": ("github.repository_owner_id == '335992433'", "github.repository_owner_id == '1'"),
            "courier binary": ("/opt/dotmac-gate0/runtime/bin/dotmac-platform gate0 courier-original-oidc", "dotmac-platform gate0 courier-original-oidc"),
            "transfer binary": ("/opt/dotmac-gate0/runtime/bin/dotmac-platform gate0 await-e-transfer", "dotmac-platform gate0 await-e-transfer"),
            "pinned archive supplier": ("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "actions/upload-artifact@main"),
            "cipher-only path": ("/run/dotmac-gate0-e-transfer/gate0-evidence.pgp", "/run/dotmac-gate0-e-private/collection.json"),
            "missing artifact": ("if-no-files-found: error", "if-no-files-found: ignore"),
            "no clobber": ("overwrite: false", "overwrite: true"),
            "no hidden files": ("include-hidden-files: false", "include-hidden-files: true"),
            "zip format": ("archive: true", "archive: false"),
        }
        path = self.workflows / "gate0-issuer.yml"
        original = EXPECTED_WORKFLOWS[path.name]
        for boundary, (old, new) in changes.items():
            with self.subTest(boundary=boundary):
                self.assertIn(old, original)
                path.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.assertTrue(policy_errors(self.root))
        path.write_text(original, encoding="utf-8")

    def test_historical_a8_fixture_is_original_source(self) -> None:
        root = Path(__file__).resolve().parents[1]
        raw = (root / "tests/fixtures/gate0-issuer-a8-c4604147.yml").read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), "1058789d5519f62ef0b880549372f980049a8ebd7b29d8978e4a340aa975dc5c")

    def test_historical_a8_witness_embeddings_match_tested_source(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / "tests/fixtures/gate0-issuer-a8-c4604147.yml").read_text()
        import re
        workflow += (root / '.github/workflows/gate0-negative-witness.yml').read_text()
        bodies = re.findall(r"<<'A8_ENV_WITNESS_JS'\n(.*?)          A8_ENV_WITNESS_JS\n", workflow, re.S)
        self.assertEqual(len(bodies), 4)
        expected = (root / "scripts/environment_witness.js").read_text()
        for body in bodies:
            self.assertEqual("".join(line[10:] if line.strip() else "\n" for line in body.splitlines(keepends=True)), expected)

    def test_negative_producer_boundary_mutations_fail(self) -> None:
        path = self.workflows / "gate0-negative-witness.yml"
        original = EXPECTED_WORKFLOWS[path.name]
        for old, new in (("workflow_dispatch:", "pull_request_target:"),
                         ("ubuntu-latest", "gate0-issuer-protected"),
                         ("rehearsal-issuer-protected", "unprotected"),
                         ("id-token: write", "contents: write"),
                         ("github.ref == 'refs/heads/main'", "true"),
                         ("timeout-minutes: 3", "timeout-minutes: 60"),
                         ("types: [a8-negative-event-proof]", "types: [anything]"),
                         ("github.event.action == 'a8-negative-event-proof'", "true")):
            with self.subTest(old=old):
                self.assertIn(old, original)
                path.write_text(original.replace(old, new, 1))
                self.assertTrue(policy_errors(self.root))

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

    def test_retired_probe_surface_cannot_return(self) -> None:
        path = self.workflows / "policy.yml"
        original = EXPECTED_WORKFLOWS[path.name]
        changes = {
            "dispatch trigger": ("on:\n  pull_request:", "on:\n  workflow_dispatch:\n  pull_request:"),
            "PR target trigger": ("on:\n  pull_request:", "on:\n  pull_request_target:\n  pull_request:"),
            "group probe": ("jobs:\n  source_policy:", "jobs:\n  probe_group:\n    runs-on:\n      group: gate0-issuer-protected\n  source_policy:"),
            "label probe": ("jobs:\n  source_policy:", "jobs:\n  probe_label:\n    runs-on: gate0-managed-20261001-only\n  source_policy:"),
        }
        for boundary, (old, new) in changes.items():
            with self.subTest(boundary=boundary):
                self.assertIn(old, original)
                path.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.assertTrue(policy_errors(self.root))


if __name__ == "__main__":
    unittest.main()
