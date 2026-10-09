"""Bounded live OIDC/SSH-capability proof; no target access or issuance."""
import base64
import hashlib
import ipaddress
import json
import os
import struct
import subprocess
import sys
import time
import tempfile
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

AUDIENCE = 'urn:dotmac:gate0:rehearsal-issuer'
CLAIMS = {
    'repository': 'dotmac-tech/gate0-issuer-execution',
    'repository_id': '1397614140',
    'repository_owner_id': '335992433',
    'environment': 'rehearsal-issuer-protected',
    'ref': 'refs/heads/main',
    'workflow_ref': 'dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main',
    'event_name': 'workflow_dispatch',
}
ISSUER = 'https://token.actions.githubusercontent.com'
CA_FINGERPRINT = 'SHA256:z9gbUh5dGjGtVh9cbQ+2vjP28j5NkPpvLxqhBwlki44'
POLICY = 'gate0-rehearsal-controller'
SIGN = 'gate0-ssh/sign/rehearsal-controller'
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def decoded_claims(jwt, run_id, attempt):
    header, payload, signature = jwt.split('.')
    decode = lambda s: json.loads(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)))
    if decode(header).get('alg') != 'RS256' or not signature:
        raise ValueError('unexpected signature algorithm')
    claims = decode(payload)
    for k, v in CLAIMS.items():
        if claims.get(k) != v:
            raise ValueError('unexpected identity claim')
    if claims.get('iss') != ISSUER or claims.get('aud') != AUDIENCE:
        raise ValueError('unexpected issuer or audience')
    if claims.get('run_id') != run_id or claims.get('run_attempt') != attempt:
        raise ValueError('unexpected run coordinates')
    now = int(time.time())
    if not (isinstance(claims.get('exp'), int) and claims['exp'] > now):
        raise ValueError('expired token')
    if claims.get('nbf', now) > now or claims.get('iat', now) > now:
        raise ValueError('future token')
    # Decode is an expectation check only. Live OpenBao login verifies authenticity.
    return {k: claims[k] for k in (*CLAIMS, 'iss', 'aud', 'exp', 'run_id', 'run_attempt')}


def certificate_info(signed, expected_key_id, expected_public):
    wire = base64.b64decode(signed.split()[1], validate=True)
    offset = 0
    def string():
        nonlocal offset
        n = struct.unpack_from('>I', wire, offset)[0]
        offset += 4
        value = wire[offset:offset+n]
        if len(value) != n:
            raise ValueError('truncated certificate')
        offset += n
        return value
    if string() != b'ssh-ed25519-cert-v01@openssh.com':
        raise ValueError('unexpected certificate type')
    string()  # nonce
    if string() != expected_public:
        raise ValueError('certificate signed another controller key')
    serial, kind = struct.unpack_from('>QI', wire, offset)
    offset += 12
    key_id, principals = string().decode(), string()
    principal = b'dotmac-gate0-controller'
    if kind != 1 or key_id != expected_key_id or principals != struct.pack('>I', len(principal)) + principal:
        raise ValueError('unexpected certificate identity')
    after, before = struct.unpack_from('>QQ', wire, offset)
    offset += 16
    if not (0 < before-after <= 600 and after <= int(time.time()) < before):
        raise ValueError('invalid certificate lifetime')
    if string() or string():
        raise ValueError('certificate options or extensions present')
    string()  # reserved
    ca = string()
    fp = 'SHA256:' + base64.b64encode(hashlib.sha256(ca).digest()).rstrip(b'=').decode()
    if fp != CA_FINGERPRINT:
        raise ValueError('unexpected certificate authority')
    payload = wire[:offset]
    signature = string()
    if offset != len(wire):
        raise ValueError('trailing certificate bytes')
    def unpack(blob):
        result = []
        while blob:
            n = struct.unpack_from('>I', blob, 0)[0]
            value, blob = blob[4:4+n], blob[4+n:]
            if len(value) != n:
                raise ValueError('truncated signature')
            result.append(value)
        return result
    ca_type, ca_key = unpack(ca)
    sig_type, sig = unpack(signature)
    if ca_type != b'ssh-ed25519' or sig_type != ca_type or len(ca_key) != 32 or len(sig) != 64:
        raise ValueError('unexpected CA signature format')
    # Files here contain only public CA, public certificate body and signature.
    with tempfile.TemporaryDirectory(prefix='a8-public-cert-') as directory:
        root = Path(directory)
        (root/'ca.der').write_bytes(bytes.fromhex('302a300506032b6570032100') + ca_key)
        (root/'payload').write_bytes(payload)
        (root/'signature').write_bytes(sig)
        check = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
            '-inkey', str(root/'ca.der'), '-sigfile', str(root/'signature'), '-rawin',
            '-in', str(root/'payload')], capture_output=True)
        if check.returncode:
            raise ValueError('invalid certificate signature')
    return {'key_id': key_id, 'principal': principal.decode(), 'measured_lifetime_seconds': before-after,
            'extensions_empty': True, 'critical_options_empty': True, 'ca_fingerprint': fp, 'ca_signature_verified': True}


def oidc(audience):
    url = urllib.parse.urlsplit(os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'])
    if url.scheme != 'https' or not url.hostname or not url.hostname.endswith('.actions.githubusercontent.com') or url.username or url.password or url.port not in (None, 443):
        raise ValueError('unexpected OIDC request endpoint')
    query = [(k, v) for k, v in urllib.parse.parse_qsl(url.query) if k != 'audience']
    query.append(('audience', audience))
    req = urllib.request.Request(urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(query))),
        headers={'Authorization': 'bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    with OPENER.open(req, timeout=15) as response:
        return json.load(response)['value']


def bao_client():
    url = urllib.parse.urlsplit(os.environ['A8_BAO_ADDR'])
    if url.scheme != 'http' or url.port != 8200 or url.path not in ('', '/') or url.query or url.fragment or url.username or url.password:
        raise ValueError('unexpected private API endpoint')
    addr = ipaddress.ip_address(url.hostname)
    if addr not in ipaddress.ip_network('100.64.0.0/10'):
        raise ValueError('endpoint is not on the qualified tunnel')
    route = subprocess.run(['ip', '-j', 'route', 'get', str(addr)], capture_output=True, check=True)
    if json.loads(route.stdout)[0].get('dev') != 'wg0':
        raise ValueError('API route is not WireGuard')
    def api(path, data=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['X-Vault-Token'] = token
        req = urllib.request.Request(url.geturl().rstrip('/') + '/v1/' + path,
            data=None if data is None else json.dumps(data).encode(), headers=headers)
        try:
            with OPENER.open(req, timeout=15) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            # Return only an expiry classification; never expose the server body.
            raw = error.read(8192)
            try:
                errors = json.loads(raw).get('errors', [])
                expired = isinstance(errors, list) and any(
                    isinstance(message, str) and ('token is expired' in message.lower()
                    or 'token expired' in message.lower()) for message in errors)
            except (ValueError, AttributeError):
                expired = False
                errors = []
            environment_error = None
            workflow_error = None
            if isinstance(errors, list):
                for message in errors:
                    if not isinstance(message, str):
                        continue
                    if message.endswith('claim "environment" is missing'):
                        environment_error = 'missing'
                    if message.endswith('claim "environment" does not match any associated bound claim values'):
                        environment_error = 'mismatch'
                    if message.endswith('claim "workflow_ref" does not match any associated bound claim values'):
                        workflow_error = 'mismatch'
            return error.code, {'expiry_error': expired, 'environment_error': environment_error,
                                'workflow_error': workflow_error}
    return api


def controller_public():
    private = subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-outform', 'DER'],
        capture_output=True, check=True).stdout
    public = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
        input=private, capture_output=True, check=True).stdout
    private = None  # No private key file, target connection or later signing operation.
    if len(public) != 44:
        raise ValueError('unexpected Ed25519 public key')
    raw = public[-32:]
    blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + raw
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode(), raw


def expiration_proof(api, jwt, token, request, jwt_exp, token_expiry_bound,
                     clock=time.time, pause=time.sleep, elapsed=time.monotonic):
    # Start AFTER the positive exchange. Use observed JWT exp and a conservative
    # token deadline measured after the successful login response, plus margin.
    deadline = max(jwt_exp, token_expiry_bound) + 5
    start = elapsed()
    while clock() < deadline:
        remaining = deadline - clock()
        if remaining > 610 or elapsed() - start > 620:
            raise ValueError('expiry wait exceeds bounded proof window')
        pause(min(10, remaining))
    status, health = api('sys/health')
    if status != 200 or health.get('sealed') is not False:
        raise ValueError('OpenBao unhealthy during expiry check')
    status, response = api('auth/jwt/login', {'role': 'rehearsal-issuer-protected', 'jwt': jwt})
    if status != 400 or response.get('expiry_error') is not True or response.get('auth'):
        raise ValueError('expired GitHub token not specifically refused for expiry')
    status, _ = api(SIGN, request, token)
    if status != 403:
        raise ValueError('expired OpenBao token still usable')
    return {'same_previously_accepted_credentials': True, 'oidc_login_http': 400,
            'oidc_expiry_error_confirmed': True, 'openbao_sign_http': 403,
            'not_before_epoch': deadline, 'checked_at_epoch': clock(),
            'wait_elapsed_seconds': elapsed() - start, 'health_http': 200}


def environment_witnesses(api, run_id, attempt):
    results = {}
    for kind, reason in [('missing_environment', 'missing'), ('wrong_environment', 'mismatch')]:
        env = dict(os.environ, A8_WITNESS_MODE='consume', A8_WITNESS_CASE=kind,
                   A8_WITNESS_ENVELOPE=os.environ['A8_WITNESS_' + kind.upper()])
        private = subprocess.run(['node', os.environ['A8_WITNESS_SCRIPT']], env=env,
                                 capture_output=True, check=True, timeout=50)
        witness = json.loads(private.stdout)
        private = None
        claims = witness['claims']
        if witness['case'] != kind or claims['run_id'] != run_id or claims['run_attempt'] != attempt:
            raise ValueError('wrong witness coordinates')
        for key, value in CLAIMS.items():
            if key != 'environment' and claims.get(key) != value:
                raise ValueError('more than one bound identity claim differs')
        expected = None if kind == 'missing_environment' else 'rehearsal-issuer-negative-witness'
        if claims.get('environment') != expected:
            raise ValueError('unexpected Environment witness')
        status, response = api('auth/jwt/login', {'role': 'rehearsal-issuer-protected', 'jwt': witness['jwt']})
        witness = None
        if status != 400 or response.get('environment_error') != reason:
            raise ValueError('Environment witness not specifically refused')
        results[kind] = {'login_http': status, 'reason': reason, 'signature_verified': True,
                         'other_six_bound_claims_match': True, 'claims': claims}
    return results



def workflow_witness(api, run_id, attempt):
    producer_run = os.environ['A8_WORKFLOW_WITNESS_RUN_ID']
    producer_attempt = os.environ['A8_WORKFLOW_WITNESS_RUN_ATTEMPT']
    if not producer_run.isdecimal() or not producer_attempt.isdecimal() or producer_run == run_id:
        raise ValueError('invalid independent producer coordinates')
    expected_workflow = 'dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-negative-witness.yml@refs/heads/main'
    env = dict(os.environ, A8_WITNESS_MODE='consume', A8_WITNESS_CASE='wrong_workflow',
               A8_WITNESS_ENVELOPE=os.environ['A8_WORKFLOW_WITNESS'],
               GITHUB_WORKFLOW_REF=expected_workflow, GITHUB_RUN_ID=producer_run,
               GITHUB_RUN_ATTEMPT=producer_attempt)
    private = subprocess.run(['node', os.environ['A8_WITNESS_SCRIPT']], env=env,
                             capture_output=True, check=True, timeout=50)
    witness = json.loads(private.stdout)
    private = None
    claims = witness['claims']
    if witness['case'] != 'wrong_workflow' or claims['run_id'] != producer_run or claims['run_attempt'] != producer_attempt:
        raise ValueError('wrong independent producer coordinates')
    if claims.get('workflow_ref') != expected_workflow or claims.get('workflow_sha') != os.environ['GITHUB_SHA']:
        raise ValueError('wrong producer workflow revision')
    for key, value in CLAIMS.items():
        if key != 'workflow_ref' and claims.get(key) != value:
            raise ValueError('more than one bound identity claim differs')
    status, response = api('auth/jwt/login', {'role': 'rehearsal-issuer-protected', 'jwt': witness['jwt']})
    witness = None
    if status != 400 or response.get('workflow_error') != 'mismatch':
        raise ValueError('workflow witness not specifically refused')
    return {'login_http': status, 'reason': 'workflow_ref_mismatch', 'signature_verified': True,
            'other_six_bound_claims_match': True, 'claims': claims,
            'consumer_run_id': run_id, 'consumer_run_attempt': attempt,
            'coordinate_binding': 'producer signature/recipient/source checked; launcher must independently attest GitHub API run binding'}


def prove(api, request_oidc, public_key, raw_public, run_id, attempt,
          check_certificate=certificate_info, check_expiry=expiration_proof,
          check_environments=environment_witnesses, check_workflow=workflow_witness):
    jwt = request_oidc(AUDIENCE)
    claims = decoded_claims(jwt, run_id, attempt)
    status, response = api('auth/jwt/login', {'role': 'rehearsal-issuer-protected', 'jwt': jwt})
    if status != 200:
        raise ValueError('protected OIDC login refused')
    auth = response['auth']
    if auth['policies'] != [POLICY] or auth['renewable'] is not False or not 0 < auth['lease_duration'] <= 300:
        raise ValueError('unexpected token authority or lifetime')
    token = auth['client_token']
    token_expiry_bound = time.time() + auth['lease_duration']
    response = auth = None
    key_id = f'gate0:1397614140:{run_id}:{attempt}'
    req = {'public_key': public_key, 'key_id': key_id, 'valid_principals': 'dotmac-gate0-controller',
           'cert_type': 'user', 'ttl': '600s'}
    status, response = api(SIGN, req, token)
    if status != 200:
        raise ValueError('controller signing refused')
    cert = check_certificate(response['data']['signed_key'], key_id, raw_public)
    response = None
    environments = check_environments(api, run_id, attempt)
    workflow = check_workflow(api, run_id, attempt)
    negative = {}
    wrong = request_oidc(AUDIENCE + ':wrong-audience')
    status, response = api('auth/jwt/login', {'role': 'rehearsal-issuer-protected', 'jwt': wrong})
    wrong = response = None
    if status not in (400, 403):
        raise ValueError('wrong audience accepted')
    negative['real_wrong_audience_login'] = status
    for part in ('rehearsal-issuer', 'rehearsal-attester'):
        for item in ('signing-key', 'trust-state'):
            status, _ = api('secret/data/dotmac/platform-cp/' + part + '/' + item, token=token)
            if status != 403:
                raise ValueError('protected data reachable')
    status, _ = api('secret/data/dotmac/starter/lane3/vantage-topology', token=token)
    if status != 403:
        raise ValueError('private topology reachable')
    status, _ = api('auth/token/renew-self', {}, token)
    if status != 403:
        raise ValueError('renewal allowed')
    for label, change in [('principal', {'valid_principals': 'root'}),
                          ('pty', {'extensions': {'permit-pty': ''}}),
                          ('forwarding', {'extensions': {'permit-port-forwarding': ''}}),
                          ('over_cap', {'ttl': '601s'})]:
        status, _ = api(SIGN, req | change, token)
        if status not in (400, 403):
            raise ValueError('forbidden certificate request accepted')
        negative[label] = status
    expiry = check_expiry(api, jwt, token, req, claims['exp'], token_expiry_bound)
    token = jwt = None  # RAM-only credentials retained until measured expiry, then discarded.
    return {'proof': 'A8-live-OIDC-partial', 'protected_login_passed': True,
        'github_claims_verified_by_openbao_login': claims, 'certificate': cert, 'negative_http': negative,
        'protected_reads_http': 403, 'renew_self_http': 403, 'batch_token_max_ttl_seconds': 300,
        'batch_token_individual_revocation_supported': False,
        'expiry': expiry, 'environment_witnesses': environments, 'workflow_witness': workflow,
        'remaining_real_claim_and_expiry_matrix': 'remaining ref/event/repository/owner identity matrix pending',
        'issuance_refused': True}


def main():
    version = subprocess.run(['openssl', 'version'], capture_output=True, check=True).stdout
    if not version.startswith(b'OpenSSL 3.'):
        raise RuntimeError('OpenSSL3 required for certificate verification')
    run_id, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    if not run_id.isdecimal() or not attempt.isdecimal():
        raise ValueError('invalid run coordinates')
    public, raw = controller_public()
    print(json.dumps(prove(bao_client(), oidc, public, raw, run_id, attempt)), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print(json.dumps({'proof': 'A8-live-OIDC-partial', 'status': 'failed',
            'failure_type': type(error).__name__, 'private_diagnostics_suppressed': True}), flush=True)
        sys.exit(1)
