# gate0-issuer-execution

Public execution surface for the protected Gate-0 rehearsal issuer. Platform CP
owns the operator workflow and readiness receipt. This repository owns neither
issuer decisions nor target execution authority.

Current source is **provisional**. The `Gate-0 source drift check` runs on a
GitHub-hosted runner for pull requests and pushes to `main`; it checks an exact
allowlist of the three workflow files with Python's standard library. Run it
locally with `python3 -B -m unittest discover -s tests -v`. The protected workflow
is directly defined in `.github/workflows/gate0-issuer.yml`; its protected
job schedules only for a manual dispatch from `main`. It requests only
`id-token: write` for its job,
uses the protected Environment and selected runner group, and exits with
failure because no safe real issuer connector is installed. A failed run is
not issuer-readiness evidence. Its bounded proof requests OIDC and measures a
scoped certificate; it issues no rehearsal lease and makes no target connection.

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

Historical scheduling-probe source: the temporary probes reintroduced at
`299c1f778c2f41038d2d668d6ceea2dc104859ea` are retired in this source:
`policy.yml` has only the GitHub-hosted `source_policy` job, triggered by
pull requests and pushes to `main`. That retirement preserved the then-current
issuer workflow; the A8 amendments below deliberately change it under review.
Source removal does not prove the live negative observations,
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
the exact issuer workflow SHA-256 admitted in the reviewed revision's digest test,
the live negative probe evidence and cancellation, and a fresh runner/group
online read-back. Only then proceed to the protected dispatch with Michael's
Environment review. This source change alone is not Gate-0 closure.

## A8 live proof amendment (pending admission)

The protected job now contains a bounded OIDC capability proof before its final
refusal. The group, Environment, main/dispatch guards and permission remain
pinned; no checkout or third-party action executes in that job. The tested Python
source is embedded verbatim, and CI checks that equality and the workflow digest.

This needs an independently qualified disposable runner and private WireGuard
route. The operator supplies `A8_BAO_ADDR` through the runner's local environment;
no estate address or credential belongs in repository variables, source or logs.
The proof requires the endpoint on the shared-address tunnel range, port8200,
with a route through wg0 and no proxy. It does not install a CA on any target,
connect to targets, read a signer or issue a rehearsal lease.

It requests a real GitHub token for the adopted audience, checks only the
allowlisted identity/run claims, and uses OpenBao login to verify authenticity.
It checks a real wrong-audience login, signing limits, private-data denials and
renewal refusal. Only public claims, certificate fields and HTTP results appear
in output. Bearer credentials stay in memory. The resulting batch token cannot
be individually revoked; it expires within300s. Runner teardown must wait for
that expiry and prove the group empty afterward.

The expiry amendment retains the same previously accepted GitHub JWT and OpenBao
batch token only in process memory. It waits past both the observed JWT expiry
and a conservative batch-token deadline, plus five seconds. It requires healthy
OpenBao, an expiry-specific JWT login refusal (400), and refusal of the same
previously successful certificate-signing request with the expired batch token
(403). A generic login error cannot pass as proof of JWT expiry. Server error
bodies are reduced privately to one expiry boolean and never logged. There is
no token refresh or renewal. A monotonic bound stops a stalled or backwards-clock
wait; unexpectedly long JWT lifetimes fail the proof.

The protected job limit is twelve minutes to accommodate the expiry observation;
the unprivileged CI job stays at five minutes. Both expiry refusals are required
before the final public proof is emitted. An operator must also corroborate that
the live role and signing policy did not change during the measurement window.
No live expiry result is claimed by source tests or a green CI check.

This is explicitly a **partial A8 proof**, not acceptance: other real-token claim
mismatches remain pending the agreed live matrix. The final step still
exits1 and issues no authorization. The existing source-policy baseline remains
mutable within this repository and is not independent runner-admission evidence.

## Proposed Environment-claim witnesses

Two additional GitHub-hosted jobs in the same dispatch produce genuine OIDC
witnesses: one without an Environment and one using
`rehearsal-issuer-negative-witness`. Neither selects the protected runner group,
checks out code, receives an OpenBao endpoint, or exchanges a token with OpenBao.
Both retain the main/dispatch guard and only `id-token: write` permission.

The dispatch input is a fresh disposable verifier's RSA3072 **public** key.
Each producer wraps its JWT using RSA-OAEP-SHA256 and AES-256-GCM, binding the
ciphertext to recipient, case, source revision, run and attempt. GitHub job
outputs transport ciphertext, which may remain in GitHub run metadata. The
private recipient key stays on the disposable verifier and is destroyed with it.
No plaintext JWT is written to a job output, log or artifact.

The protected job privately decrypts each witness, verifies its RS256 signature
against GitHub's HTTPS JWKS, checks its source/run identity and all six other
bound claims, and requires at least sixty seconds of remaining validity. Only
then does it request OpenBao login. A 400 response must specifically identify the
missing or mismatched Environment claim; generic rejection cannot pass. The
allowlisted public result contains no bearer or raw server error.

Run `node --test tests/environment_witness.test.js` alongside the Python suite.
These tests use generated fixture keys and mocked HTTP, and do not establish a
live refusal. Exact-head review, the separate test Environment and a fresh
qualified disposable verifier are required before execution. Non-Environment
claim negatives, CP acceptance and Gate-0 readiness remain outstanding.

The witness subject is pinned to GitHub's immutable prefix
`repo:dotmac-tech@335992433/gate0-issuer-execution@1397614140`, matching the
repository's live OIDC configuration. Legacy name-only subjects and substituted
owner/repository IDs fail closed. Producer failures emit only a fixed phase and
reason code, never token contents, response bodies or arbitrary error messages.

## Proposed wrong-workflow witness

`gate0-negative-witness.yml` adds a main/dispatch-only GitHub-hosted producer in
the existing `rehearsal-issuer-protected` Environment. Its normal Environment
review is retained. It has `id-token: write` only, no checkout/action, no protected
runner selection, and no OpenBao endpoint or exchange code. Its token matches
six bound claims and differs only in `workflow_ref`.

The producer prints only a recipient-bound encrypted envelope plus public run,
attempt, source revision and recipient fingerprint. Ciphertext may persist in
GitHub logs and dispatch metadata. The fresh RSA3072 private key stays on the
single-use disposable verifier and is destroyed with it. No plaintext JWT is
published or copied through the operator's machine.

Before dispatching the protected consumer, the operator must use live GitHub API
read-backs and `scripts/workflow_witness_transport.py` to qualify the producer's
repository/owner IDs, exact source, workflow file, event/ref, successful hosted
job, run/attempt, fresh time window, recipient and ciphertext metadata. Pass only
the resulting ciphertext and public producer coordinates as dispatch inputs.
The consumer checks its own run separately, decrypts privately, verifies GitHub's
signature and expiry, and requires all six other bound claims and the same source
revision. OpenBao must return400 specifically for `workflow_ref` mismatch.

The producer run is deliberately different from the consumer run. The source
verifier binds the signed producer coordinates to the supplied expected values;
the independent API lookup remains the launcher's obligation. This test helper
is not CP's admission oracle. A green source check supplies no such attestation.

Prepare/approve the exact source and the two normal Environment reviews before
execution. Use a new recipient key and disposable verifier for each attempt;
never rerun with an old key/envelope. Any stale witness or unexpected successful
login fails the proof; observe all issued-token expiry before teardown. Existing
Environment, audience, scoped-capability and expiry tests and final refusal remain.
Other ref/event/repository/owner witnesses and CP/Gate-0 acceptance remain pending.

## Proposed coupled non-dispatch witness

The hosted negative producer additionally handles only repository_dispatch type
`a8-negative-event-proof` on main, under the existing protected Environment review.
Its client payload contains only the fresh verifier's RSA3072 PUBLIC key. Values
enter shell steps through environment variables, never interpolated shell code.
No OpenBao exchange/endpoint, checkout/action or protected runner access is added.
The primary workflow stays workflow_dispatch/main-only; select `wrong_event` only
with independently API-qualified ciphertext from that reviewed producer revision.

The genuine token differs in BOTH event_name and workflow_ref. Public evidence
lists both and the specific bound claim named by OpenBao's refusal. It does not
claim an independent event test or CP acceptance. Wrong-workflow-only dispatch
remains available. Signature/source/API run/attempt/recipient/freshness checks and
actual JWT/batch expiry, scoped refusals and final connector refusal remain.
Never reuse a recipient or envelope. Source changes require exact-head review,
then a fresh disposable proof and both normal Environment reviews. No live event
proof, policy change, residual acceptance or Gate0 allocation is implied by tests.
GitHub event semantics: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#repository_dispatch
