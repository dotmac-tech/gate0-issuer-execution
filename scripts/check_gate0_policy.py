"""Detect drift from the four proposed workflow source files.

The exact allowlist is mutable in this same repository as the checked files.
It catches accidental drift, not a malicious PR changing both the baseline
and workflow. A green result is never independent runner-admission evidence.
"""

from pathlib import Path
import sys


EXPECTED_WORKFLOWS = {
    'gate0-issuer.yml': r'''name: Gate-0 E readiness producer
run-name: Gate0 E readiness

on:
  workflow_dispatch:
    inputs:
      mode:
        description: Explicit reviewed readiness mode
        required: true
        default: refuse
        type: choice
        options: [refuse, e-readiness]

permissions: {}

jobs:
  gate0_e_producer:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.repository == 'dotmac-tech/gate0-issuer-execution' && github.repository_id == '1397614140' && github.repository_owner_id == '335992433' }}
    runs-on:
      group: gate0-issuer-protected
    environment: rehearsal-issuer-protected
    permissions:
      id-token: write
    timeout-minutes: 12
    steps:
      - name: Require the reviewed E mode
        env:
          GATE0_E_MODE: ${{ inputs.mode }}
        shell: bash
        run: |
          set -euo pipefail
          if [ "$GATE0_E_MODE" != "e-readiness" ]; then
            echo "Gate0 E mode not selected." >&2
            exit 1
          fi
      - name: Deliver original protected identity
        shell: bash
        run: |
          set -euo pipefail
          /opt/dotmac-gate0/runtime/bin/dotmac-platform gate0 courier-original-oidc
      - name: Await original-bound encrypted transfer
        shell: bash
        run: |
          set -euo pipefail
          /opt/dotmac-gate0/runtime/bin/dotmac-platform gate0 await-e-transfer
      - name: Upload the encrypted evidence pair
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: gate0-encrypted-e
          path: |
            /run/dotmac-gate0-e-transfer/gate0-evidence.pgp
            /run/dotmac-gate0-e-transfer/gate0-evidence-public.json
          if-no-files-found: error
          archive: true
          compression-level: 0
          retention-days: 30
          overwrite: false
          include-hidden-files: false
''',
    'policy.yml': r'''name: Gate-0 source drift check

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
        run: |
          python3 -B -m unittest discover -s tests -v
          node --test tests/environment_witness.test.js
''',
    'gate0-negative-witness.yml': r'''name: A8 encrypted wrong-workflow witness (hosted only)

on:
  workflow_dispatch:
    inputs:
      witness_public_key:
        description: Fresh disposable verifier RSA3072 PUBLIC key
        required: true
        type: string

  repository_dispatch:
    types: [a8-negative-event-proof]

permissions: {}

jobs:
  workflow_witness:
    if: ${{ github.ref == 'refs/heads/main' && (github.event_name == 'workflow_dispatch' || (github.event_name == 'repository_dispatch' && github.event.action == 'a8-negative-event-proof')) }}
    runs-on: ubuntu-latest
    environment: rehearsal-issuer-protected
    timeout-minutes: 3
    permissions:
      id-token: write
    steps:
      - name: Encrypt real wrong-workflow token for the disposable verifier
        env:
          A8_WITNESS_MODE: produce
          A8_WITNESS_CASE: ${{ github.event_name == 'repository_dispatch' && 'wrong_event' || 'wrong_workflow' }}
          A8_WITNESS_PUBLIC_KEY: ${{ github.event_name == 'repository_dispatch' && github.event.client_payload.witness_public_key || inputs.witness_public_key }}
        shell: bash
        run: |
          set -euo pipefail
          node - <<'A8_ENV_WITNESS_JS'
          'use strict';
          // Ciphertext is public. consume stdout is a PRIVATE pipe captured by Python only.
          const C = require('node:crypto');
          const F = require('node:fs');
          const AUD = 'urn:dotmac:gate0:rehearsal-issuer';
          const ISS = 'https://token.actions.githubusercontent.com';
          const SUBJECT_PREFIX = 'repo:dotmac-tech@335992433/gate0-issuer-execution@1397614140';
          let phase='initial';
          const WRONG_ENV = 'rehearsal-issuer-negative-witness';
          function requireValue(ok, code='validation') { if (!ok) { const error=new Error('witness validation failed');error.code=code;throw error; } }
          function binding(env, kind) {
            requireValue(['missing_environment','wrong_environment','wrong_workflow','wrong_event'].includes(kind));
            requireValue(env.GITHUB_REPOSITORY === 'dotmac-tech/gate0-issuer-execution');
            requireValue(env.GITHUB_REPOSITORY_ID === '1397614140' && env.GITHUB_REPOSITORY_OWNER_ID === '335992433');
            requireValue(env.GITHUB_REF === 'refs/heads/main' && env.GITHUB_EVENT_NAME === (kind==='wrong_event'?'repository_dispatch':'workflow_dispatch'));
            const filename=['wrong_workflow','wrong_event'].includes(kind)?'gate0-negative-witness.yml':'gate0-issuer.yml';
            requireValue(env.GITHUB_WORKFLOW_REF === env.GITHUB_REPOSITORY + '/.github/workflows/'+filename+'@refs/heads/main');
            requireValue(/^\d+$/.test(env.GITHUB_RUN_ID) && /^\d+$/.test(env.GITHUB_RUN_ATTEMPT));
            requireValue(/^[a-f0-9]{40}$/.test(env.GITHUB_SHA));
            return {case:kind, repository_id:env.GITHUB_REPOSITORY_ID, owner_id:env.GITHUB_REPOSITORY_OWNER_ID,
              run_id:env.GITHUB_RUN_ID, run_attempt:env.GITHUB_RUN_ATTEMPT, workflow_ref:env.GITHUB_WORKFLOW_REF,
              ref:env.GITHUB_REF, event_name:env.GITHUB_EVENT_NAME, source_sha:env.GITHUB_SHA};
          }
          function publicKey(key) {
            const result = C.createPublicKey(key);
            requireValue(result.asymmetricKeyType === 'rsa' && result.asymmetricKeyDetails.modulusLength === 3072);
            return result;
          }
          function fingerprint(key) { return C.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex'); }
          function b64(value, maximum) {
            requireValue(typeof value === 'string' && value.length <= maximum && /^[A-Za-z0-9_-]+$/.test(value));
            const raw = Buffer.from(value,'base64url'); requireValue(raw.toString('base64url') === value); return raw;
          }
          function aad(header) { return Buffer.from(JSON.stringify(header)); }
          function seal(jwt, key, bound) {
            requireValue(typeof jwt === 'string' && Buffer.byteLength(jwt) <= 8192);
            const pub=publicKey(key), secret=C.randomBytes(32), nonce=C.randomBytes(12);
            const header={v:1,binding:bound,recipient:fingerprint(pub)};
            const cipher=C.createCipheriv('aes-256-gcm',secret,nonce); cipher.setAAD(aad(header));
            const ciphertext=Buffer.concat([cipher.update(jwt,'utf8'),cipher.final()]);
            const wrapped=C.publicEncrypt({key:pub,padding:C.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},secret);
            secret.fill(0);
            return Buffer.from(JSON.stringify({...header,wrapped:wrapped.toString('base64url'),nonce:nonce.toString('base64url'),
              ciphertext:ciphertext.toString('base64url'),tag:cipher.getAuthTag().toString('base64url')})).toString('base64url');
          }
          function open(envelope, privateKey, bound) {
            const value=JSON.parse(b64(envelope,20000).toString('utf8'));
            requireValue(Object.keys(value).sort().join(',') === 'binding,ciphertext,nonce,recipient,tag,v,wrapped');
            requireValue(value.v === 1 && JSON.stringify(value.binding) === JSON.stringify(bound));
            const pub=publicKey(privateKey); requireValue(value.recipient === fingerprint(pub));
            const secret=C.privateDecrypt({key:privateKey,padding:C.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},b64(value.wrapped,1024));
            requireValue(secret.length === 32);
            const nonce=b64(value.nonce,32), tag=b64(value.tag,32);requireValue(nonce.length===12 && tag.length===16);
            const decipher=C.createDecipheriv('aes-256-gcm',secret,nonce);decipher.setAAD(aad({v:1,binding:value.binding,recipient:value.recipient}));decipher.setAuthTag(tag);
            try { return Buffer.concat([decipher.update(b64(value.ciphertext,12000)),decipher.final()]).toString('utf8'); }
            finally { secret.fill(0); }
          }
          function decode(jwt) {
            requireValue(typeof jwt === 'string' && Buffer.byteLength(jwt)<=8192);
            const parts=jwt.split('.');requireValue(parts.length===3);
            return {parts, header:JSON.parse(b64(parts[0],2048)), claims:JSON.parse(b64(parts[1],10000))};
          }
          function validateClaims(jwt, env, kind, now=Date.now()/1000) {
            const {header,claims}=decode(jwt);const bound=binding(env,kind);
            requireValue(header.alg==='RS256' && typeof header.kid==='string' && header.kid.length<=256);
            const wanted={repository:env.GITHUB_REPOSITORY,repository_id:bound.repository_id,repository_owner_id:bound.owner_id,
              ref:bound.ref,workflow_ref:bound.workflow_ref,event_name:bound.event_name,iss:ISS,aud:AUD,
              run_id:bound.run_id,run_attempt:bound.run_attempt,workflow_sha:bound.source_sha,runner_environment:'github-hosted'};
            for (const [key,value] of Object.entries(wanted)) requireValue(claims[key]===value);
            if (kind==='missing_environment') {
              requireValue(!Object.hasOwn(claims,'environment'));
              requireValue(claims.sub===SUBJECT_PREFIX+':ref:refs/heads/main', 'subject');
            } else {
              const environment=['wrong_workflow','wrong_event'].includes(kind)?'rehearsal-issuer-protected':WRONG_ENV;
              requireValue(claims.environment===environment);
              requireValue(claims.sub===SUBJECT_PREFIX+':environment:'+environment, 'subject');
            }
            requireValue(Number.isInteger(claims.exp) && claims.exp-now>=60 && claims.exp-now<=600);
            requireValue(Number.isInteger(claims.iat) && claims.iat<=now && claims.iat>=now-600);
            requireValue(Number.isInteger(claims.nbf) && claims.nbf<=now);
            return {header,claims,bound};
          }
          function verify(jwt, env, kind, jwks, now=Date.now()/1000) {
            const result=validateClaims(jwt,env,kind,now), parts=jwt.split('.');
            requireValue(Array.isArray(jwks.keys) && jwks.keys.length<=32);
            const keys=jwks.keys.filter(k=>k.kid===result.header.kid && k.kty==='RSA' && (!k.alg || k.alg==='RS256') && (!k.use || k.use==='sig'));
            requireValue(keys.length===1);
            const key=C.createPublicKey({key:keys[0],format:'jwk'});requireValue(key.asymmetricKeyDetails.modulusLength>=2048);
            requireValue(C.verify('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),key,b64(parts[2],2048)));
            const claims={};for(const name of ['repository','repository_id','repository_owner_id','ref','workflow_ref','event_name','iss','aud','exp','run_id','run_attempt','workflow_sha'])claims[name]=result.claims[name];
            claims.environment=Object.hasOwn(result.claims,'environment')?result.claims.environment:null;
            return claims;
          }
          async function fetchJSON(url, headers={}) {
            const response=await fetch(url,{headers,redirect:'error',signal:AbortSignal.timeout(15000)});
            requireValue(response.ok);
            const reader=response.body.getReader();const chunks=[];let size=0;
            while(true) { const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();throw new Error('bounded response exceeded');}chunks.push(Buffer.from(value)); }
            return JSON.parse(Buffer.concat(chunks).toString('utf8'));
          }
          async function main(env=process.env) {
            phase='binding';
            const kind=env.A8_WITNESS_CASE, bound=binding(env,kind);
            if(env.A8_WITNESS_MODE==='produce') {
              phase='recipient';
              const pub=publicKey(env.A8_WITNESS_PUBLIC_KEY);
              const url=new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
              requireValue(url.protocol==='https:' && !url.username && !url.password && (!url.port || url.port==='443') && url.hostname.endsWith('.actions.githubusercontent.com'));
              requireValue(typeof env.ACTIONS_ID_TOKEN_REQUEST_TOKEN==='string' && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN.length>0);
              url.searchParams.set('audience',AUD);
              phase='oidc_request';
              const result=await fetchJSON(url,{Authorization:'Bearer '+env.ACTIONS_ID_TOKEN_REQUEST_TOKEN});
              phase='claims';
              validateClaims(result.value,env,kind);
              phase='encryption';
              const encrypted=seal(result.value,pub.export({type:'spki',format:'pem'}),bound);
              phase='ciphertext_output';
              F.appendFileSync(env.GITHUB_OUTPUT,'envelope='+encrypted+'\n',{encoding:'utf8'});
              const record={case:kind,status:'encrypted',recipient:fingerprint(pub)};
              // Cross-run transport publishes CIPHERTEXT only; the recipient key never leaves the verifier.
              if(['wrong_workflow','wrong_event'].includes(kind))Object.assign(record,{envelope:encrypted,run_id:bound.run_id,run_attempt:bound.run_attempt,source_sha:bound.source_sha});
              process.stdout.write(JSON.stringify(record)+'\n');
            } else {
              requireValue(env.A8_WITNESS_MODE==='consume');
              phase='private_decryption';
              const stat=F.statSync(env.A8_WITNESS_PRIVATE_KEY_FILE);requireValue(stat.isFile() && (stat.mode & 0o077)===0 && stat.size<=8192);
              const privateKey=C.createPrivateKey(F.readFileSync(env.A8_WITNESS_PRIVATE_KEY_FILE));
              const jwt=open(env.A8_WITNESS_ENVELOPE,privateKey,bound);
              phase='github_signature';
              const discovery=await fetchJSON(ISS+'/.well-known/openid-configuration');
              const url=new URL(discovery.jwks_uri);requireValue(discovery.issuer===ISS && url.origin===ISS && !url.username && !url.password);
              const claims=verify(jwt,env,kind,await fetchJSON(url));
              // This stdout is captured only by the approved Python parent, never a shell step.
              process.stdout.write(JSON.stringify({jwt,claims,case:kind}));
            }
          }
          module.exports={binding,seal,open,validateClaims,verify,main,fetchJSON,WRONG_ENV};
          if(require.main===module || process.argv[1]==='-')main().catch(error=>{process.stdout.write(JSON.stringify({witness_status:'failed',phase,reason:error.code==='subject'?'subject':'validation'})+'\n');process.exitCode=1;});
          A8_ENV_WITNESS_JS
''',
    'gate0-e-publication.yml': r'''name: Gate-0 E public operations (candidate)
run-name: ${{ inputs.mode == 'publish' && format('Gate0 E publication summary {0} draft {1} producer {2}', inputs.summary_digest, inputs.draft_release_id, inputs.producer_run_id) || 'Gate0 E draft preparation' }}

on:
  workflow_dispatch:
    inputs:
      mode:
        description: Explicit reviewed public operation
        required: true
        default: refuse
        type: choice
        options: [refuse, prepare-draft, publish]
      summary_digest:
        description: Public B verification summary SHA256, without prefix
        required: false
        default: ''
        type: string
      draft_release_id:
        description: Exact B-verified draft release ID
        required: false
        default: ''
        type: string
      producer_run_id:
        description: Exact completed E producer run ID
        required: false
        default: ''
        type: string

permissions: {}

jobs:
  gate0_e_public_operation:
    if: ${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.repository == 'dotmac-tech/gate0-issuer-execution' && github.repository_id == '1397614140' && github.repository_owner_id == '335992433' }}
    runs-on:
      group: gate0-e-publication-protected
    environment: rehearsal-issuer-protected
    permissions: {}
    timeout-minutes: 5
    steps:
      - name: Execute selected finite public operation
        env:
          GATE0_E_MODE: ${{ inputs.mode }}
          GATE0_E_SUMMARY: ${{ inputs.summary_digest }}
          GATE0_E_DRAFT: ${{ inputs.draft_release_id }}
          GATE0_E_PRODUCER: ${{ inputs.producer_run_id }}
        shell: bash
        run: |
          set -euo pipefail
          case "$GATE0_E_MODE" in
            prepare-draft)
              exec /opt/dotmac-gate0/runtime/bin/dotmac-platform gate0 prepare-e-draft
              ;;
            publish)
              if [[ ! "$GATE0_E_SUMMARY" =~ ^[a-f0-9]{64}$ ]] || [[ ! "$GATE0_E_DRAFT" =~ ^[1-9][0-9]*$ ]] || [[ ! "$GATE0_E_PRODUCER" =~ ^[1-9][0-9]*$ ]]; then
                echo PUBLIC_E_EXECUTION_REFUSED
                exit 1
              fi
              exec /opt/dotmac-gate0/runtime/bin/dotmac-platform gate0 publish-e
              ;;
            *)
              echo PUBLIC_E_EXECUTION_REFUSED
              exit 1
              ;;
          esac
''',
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
