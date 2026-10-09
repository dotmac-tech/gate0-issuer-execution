import base64,json,time,unittest
from scripts import a8_oidc_proof as p

def fixture(aud=p.AUDIENCE,change=None):
 c=dict(p.CLAIMS,iss=p.ISSUER,aud=aud,exp=int(time.time())+300,run_id='123',run_attempt='1');c.update(change or {})
 e=lambda x:base64.urlsafe_b64encode(json.dumps(x).encode()).rstrip(b'=').decode()
 return e({'alg':'RS256'})+'.'+e(c)+'.fixture-signature'

class ProofTests(unittest.TestCase):
 def api(self,path,data=None,token=None):
  if path=='auth/jwt/login':
   payload=data['jwt'].split('.')[1];claims=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))
   if claims['aud']!=p.AUDIENCE:return 400,{}
   return 200,{'auth':{'policies':[p.POLICY],'renewable':False,'lease_duration':300,'client_token':'PRIVATE_FIXTURE_BEARER'}}
  if path==p.SIGN and data['valid_principals']=='dotmac-gate0-controller' and data['ttl']=='600s' and 'extensions' not in data:return 200,{'data':{'signed_key':'PUBLIC_CERT'}}
  return 403,{}
 def run_proof(self,api=None,request=None):
  return p.prove(api or self.api,request or fixture,'public',b'raw','123','1',lambda c,k,r:{'key_id':k,'measured_lifetime_seconds':600})
 def test_executed_workflow_embeds_exact_tested_script(self):
  from pathlib import Path
  root=Path(__file__).resolve().parents[1]
  workflow=(root/'.github/workflows/gate0-issuer.yml').read_text()
  start=workflow.index("          python3 - <<'A8_PROOF_PY'\n")+len("          python3 - <<'A8_PROOF_PY'\n")
  end=workflow.index('          A8_PROOF_PY\n',start)
  embedded=''.join((line[10:] if line.strip() else '\n') for line in workflow[start:end].splitlines(keepends=True))
  self.assertEqual(embedded,(root/'scripts/a8_oidc_proof.py').read_text())
 def test_output_excludes_bearers_and_is_partial(self):
  r=self.run_proof();s=json.dumps(r)
  self.assertNotIn('PRIVATE_FIXTURE_BEARER',s);self.assertNotIn('fixture-signature',s)
  self.assertEqual(r['remaining_real_claim_and_expiry_matrix'],'pending');self.assertTrue(r['issuance_refused'])
 def test_wrong_claim_expiry_or_run_never_reaches_login(self):
  for change in [*({k:'wrong'} for k in p.CLAIMS),{'exp':int(time.time())-1},{'run_id':'456'},{'run_attempt':'2'}]:
   calls=[]
   with self.subTest(change=change),self.assertRaises(ValueError):self.run_proof(lambda *a,**kw:calls.append(a),lambda aud:fixture(aud,change))
   self.assertEqual(calls,[])
 def test_bad_token_authority_rejected(self):
  for change in ({'renewable':True},{'policies':[p.POLICY,'default']},{'lease_duration':301}):
   def api(path,data=None,token=None):
    s,b=self.api(path,data,token)
    if path=='auth/jwt/login' and s==200:b['auth'].update(change)
    return s,b
   with self.subTest(change=change),self.assertRaises(ValueError):self.run_proof(api)
 def test_unexpected_negative_success_fails(self):
  for bad in ('wrong-audience','protected-read','renewal','extensions'):
   def api(path,data=None,token=None):
    if bad=='wrong-audience' and path=='auth/jwt/login':return 200,{'auth':{'policies':[p.POLICY],'renewable':False,'lease_duration':300,'client_token':'PRIVATE_FIXTURE_BEARER'}}
    if bad=='protected-read' and path.startswith('secret/'):return 200,{}
    if bad=='renewal' and path=='auth/token/renew-self':return 200,{}
    if bad=='extensions' and path==p.SIGN and 'extensions' in data:return 200,{}
    return self.api(path,data,token)
   with self.subTest(bad=bad),self.assertRaises(ValueError):self.run_proof(api)

@unittest.skipUnless(__import__('subprocess').check_output(['openssl','version']).startswith(b'OpenSSL 3.'), 'Linux canary requires OpenSSL3; LibreSSL is unsupported')
class CertificateTests(unittest.TestCase):
 def test_real_signature_lifetime_and_truncation(self):
  import subprocess,tempfile,struct
  from pathlib import Path
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   for key in ('ca','controller'):
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/key)],check=True,capture_output=True)
   key_id='gate0:1397614140:123:1'
   subprocess.run(['ssh-keygen','-q','-s',str(root/'ca'),'-I',key_id,'-n','dotmac-gate0-controller','-O','clear','-V','-1s:+599s',str(root/'controller.pub')],check=True,capture_output=True)
   cert=(root/'controller-cert.pub').read_text();raw=base64.b64decode((root/'controller.pub').read_text().split()[1])[-32:]
   fp=subprocess.run(['ssh-keygen','-lf',str(root/'ca.pub'),'-E','sha256'],check=True,capture_output=True,text=True).stdout.split()[1]
   with patch.object(p,'CA_FINGERPRINT',fp):
    info=p.certificate_info(cert,key_id,raw);self.assertEqual(info['measured_lifetime_seconds'],600);self.assertTrue(info['ca_signature_verified'])
    with self.assertRaises(ValueError):p.certificate_info(cert,key_id,b'wrong-key')
    wire=bytearray(base64.b64decode(cert.split()[1]));wire[-1]^=1
    with self.assertRaises(ValueError):p.certificate_info(cert.split()[0]+' '+base64.b64encode(wire).decode(),key_id,raw)

if __name__=='__main__':unittest.main()
