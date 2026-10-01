# gate0-issuer-execution

Public execution surface for the protected Gate-0 rehearsal issuer. Platform CP
owns the operator workflow and readiness receipt. This repository owns neither
issuer decisions nor target execution authority.

Current source is **provisional**. The `Gate-0 source drift check` runs on a
GitHub-hosted runner for pull requests and pushes to `main`; it checks an exact
allowlist of the two workflow files with Python's standard library. Run it
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

The temporary negative scheduling probes reintroduced at
`299c1f778c2f41038d2d668d6ceea2dc104859ea` are retired in this source:
`policy.yml` again has only the GitHub-hosted `source_policy` job, triggered by
pull requests and pushes to `main`. The privileged issuer workflow remains
byte-identical. Source removal does not prove the live negative observations,
queued-run cancellation, or protected-`main` merge; those require separate
read-backs. A queued job without a confirmed online protected runner is
inconclusive, and an assigned runner or executed probe is a failed refusal.

The earlier negative window had the same canary online and idle before and
after, but its protected positive dispatch never reached an assigned runner;
the canary later auto-deregistered. That window remains inconclusive for
admission without a positive execution control. Fresh repeat proof is pending
independent validation; this source makes no readiness claim.

Before the final positive issuer dispatch, record the merged cleanup commit
SHA, a green `source_policy` check and workflow read-back at that exact SHA,
the unchanged issuer workflow SHA-256
`2a62feee21d8236de28e21bb8850c4e0388a39f71cce4338b1c60e0741b876fd`,
the live negative probe evidence and cancellation, and a fresh runner/group
online read-back. Only then proceed to the protected dispatch with Michael's
Environment review. This source change alone is not Gate-0 closure.
