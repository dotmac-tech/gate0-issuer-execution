# gate0-issuer-execution

Temporary fork-origin PR fixture: this documentation-only change exercises
the inert base-branch scheduling probes and is never merged.

Public execution surface for the protected Gate-0 rehearsal issuer. Platform CP
owns the operator workflow and readiness receipt. This repository owns neither
issuer decisions nor target execution authority.

Current source is **provisional**. The `Gate-0 source drift check` runs on a
GitHub-hosted runner for pull requests, pull-request-target events into `main`,
manual dispatches, and pushes to `main`; it checks an exact allowlist of the
two workflow files with Python's standard library. Run it
locally with `python3 -B -m unittest discover -s tests -v`. The protected workflow
is directly defined in `.github/workflows/gate0-issuer.yml`; its protected
job schedules only for a manual dispatch from `main`. It requests only
`id-token: write` for its job,
uses the protected Environment and selected runner group, and exits with
failure because no safe real issuer connector is installed. A failed run is
not issuer-readiness evidence. It requests no OIDC token, issues no lease,
and makes no target connection.

The drift check is maintained in this same repository: a PR can change the
workflow, checker, and tests together. It detects accidental changes, **not**
an independently enforced security policy. It cannot admit a runner or replace
an exact-head independent review and live refusal proof.

Admission still requires the live GitHub repository, branch, Environment,
runner-group and runner-isolation read-backs and negative scheduling probes in
Platform CP's `docs/design/gate0-d-implementation-spec.md` §11. The OpenBao
JWT role and policy must bind the exact workflow and immutable repository IDs
and prove refusal cases. The CP issuer connector, signer custody, independently
signed harness evidence, and private Lane-3 vantage delivery remain unresolved.
Do not register or attach a privileged runner based on this source or a green
static check. Public source, variables, logs, and artifacts must contain no
secrets, credentials, host addresses, or private topology.

Temporary live scheduling probes are added to `policy.yml` from source base
`f218660b6ff7c3a01b877e6ab080efcd31672805`; the privileged issuer workflow
remains byte-identical. On manual dispatch, pull request, and pull-request-target
events, two inert jobs target the protected runner group plus its managed label,
and the managed label alone. They have no token permissions, environment,
checkout, secrets, artifacts, or privileged steps. If either runs, it prints
`SCHEDULING_REFUSAL_FAILED` and exits with failure. The source-policy job stays
on a GitHub-hosted runner; its pull-request-target checkout uses `main` as the
base branch through the normal checkout default.

The expected negative result is both probe jobs queued with `runner_id: null`
during a fixed observation window while the sole canary in the protected group
is confirmed online. A queued job without that online read-back is inconclusive;
an assigned runner or executed probe is a failed refusal. The primary operator
will cancel the queued runs after observation. These probes make no security
claim on their own. A follow-up source change removes both probe jobs and their
temporary dispatch and pull-request-target triggers through a protected-`main`
pull request. Before the final positive issuer dispatch, record the merged
removal commit SHA, a green `source_policy` check and workflow read-back at that
exact SHA, the unchanged issuer workflow SHA-256
`2a62feee21d8236de28e21bb8850c4e0388a39f71cce4338b1c60e0741b876fd`,
and a fresh runner/group online read-back. Only then proceed to the protected
dispatch with Michael's Environment review.
