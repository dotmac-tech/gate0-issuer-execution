"""Detect drift from the two provisional workflow source files.

The exact allowlist is mutable in this same repository as the checked files.
It catches accidental drift, not a malicious PR changing both the baseline
and workflow. A green result is never independent runner-admission evidence.
"""

from pathlib import Path
import sys


EXPECTED_WORKFLOWS = {
    "gate0-issuer.yml": """name: Gate-0 provisional issuer (refuses)

on:
  workflow_dispatch:

permissions: {}

jobs:
  gate0_issuer:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}
    runs-on:
      group: gate0-issuer-protected
    environment: rehearsal-issuer-protected
    permissions:
      id-token: write
    timeout-minutes: 5
    steps:
      - name: Refuse until the real issuer connector is admitted
        shell: bash
        run: |
          echo "Gate-0 issuer connector is unavailable; no authorization was issued." >&2
          exit 1
""",
    "policy.yml": """name: Gate-0 source drift check

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  source_policy:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
      - name: Detect provisional workflow drift
        run: python3 -B scripts/check_gate0_policy.py
      - name: Verify workflow boundaries and mutation sensitivity
        run: python3 -B -m unittest discover -s tests -v
""",
}


def policy_errors(root: Path) -> list[str]:
    workflows = root / ".github" / "workflows"
    actual_names = {p.name for p in workflows.iterdir()} if workflows.is_dir() else set()
    errors = []
    for name in sorted(actual_names - EXPECTED_WORKFLOWS.keys()):
        errors.append(f"unexpected workflow entry: {name}")
    for name, expected in EXPECTED_WORKFLOWS.items():
        path = workflows / name
        if name not in actual_names or not path.is_file() or path.is_symlink():
            errors.append(f"missing or non-regular workflow: {name}")
        elif path.read_bytes() != expected.encode("utf-8"):
            errors.append(f"workflow differs from admitted provisional source: {name}")
    return errors


if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[1]
    failures = policy_errors(repo)
    for failure in failures:
        print(failure, file=sys.stderr)
    sys.exit(bool(failures))
