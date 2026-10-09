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
  clock=[time.time()];initial=clock[0];base=api or self.api
  def phased(path,data=None,token=None):
   if path=='sys/health':return 200,{'sealed':False}
   if clock[0]>initial+300:
    if path=='auth/jwt/login':return 400,{'expiry_error':True}
    if path==p.SIGN:return 403,{}
   return base(path,data,token)
  def pause(seconds):clock[0]+=seconds
  def expiry(*args):return p.expiration_proof(*args,clock=lambda:clock[0],pause=pause,elapsed=lambda:clock[0])
  return p.prove(phased,request or fixture,'public',b'raw','123','1',lambda c,k,r:{'key_id':k,'measured_lifetime_seconds':600},expiry,lambda *args:{'fixture_environment_witnesses':True},lambda *args:{'fixture_workflow_witness':True})
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
  self.assertEqual(r['remaining_real_claim_and_expiry_matrix'],'remaining ref/event/repository/owner identity matrix pending');self.assertTrue(r['issuance_refused'])
  self.assertEqual(r['expiry']['oidc_login_http'],400);self.assertEqual(r['expiry']['openbao_sign_http'],403)
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

class ExpiryTests(unittest.TestCase):
 def test_http_error_body_is_reduced_to_expiry_boolean(self):
  import io,ipaddress,os,subprocess,urllib.error
  from unittest.mock import patch
  address=str(ipaddress.ip_network('100.64.0.0/10').network_address+1)
  for message,expected in [('token is expired (exp): PRIVATE_ERROR_BODY',True),('permission denied PRIVATE_ERROR_BODY',False)]:
   error=urllib.error.HTTPError('https://fixture.invalid',400,'fixture',{},io.BytesIO(json.dumps({'errors':[message]}).encode()))
   with patch.dict(os.environ,{'A8_BAO_ADDR':'http://'+address+':8200'}),patch.object(p.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'[{"dev":"wg0"}]')),patch.object(p.OPENER,'open',side_effect=error):
    status,result=p.bao_client()('auth/jwt/login',{'jwt':'PRIVATE_JWT'})
   self.assertEqual(status,400);self.assertEqual(result,{'expiry_error':expected,'environment_error':None,'workflow_error':None,'event_error':None})
   self.assertNotIn('PRIVATE',json.dumps(result))
 def run_expiry(self,bad=None,jwt_exp=1200):
  clock=[1000.0];calls=[]
  def api(path,data=None,token=None):
   calls.append((path,data,token,clock[0]))
   if path=='sys/health':return (503,{'sealed':True}) if bad=='health' else (200,{'sealed':False})
   if path=='auth/jwt/login':
    if bad=='jwt-success':return 200,{'auth':{'client_token':'UNEXPECTED_BEARER'}}
    return 400,{'expiry_error':bad!='wrong-reason'}
   return (200,{}) if bad=='bao-success' else (403,{})
  def pause(seconds):clock[0]+=seconds
  result=p.expiration_proof(api,'ORIGINAL_JWT','ORIGINAL_BAO',{'public_key':'PUBLIC'},jwt_exp,1300,
   clock=lambda:clock[0],pause=pause,elapsed=lambda:clock[0])
  return result,calls
 def test_waits_for_later_deadline_and_reuses_original_credentials(self):
  for jwt_exp,deadline in ((1200,1305),(1400,1405)):
   result,calls=self.run_expiry(jwt_exp=jwt_exp)
   self.assertEqual(result['not_before_epoch'],deadline)
   self.assertTrue(all(c[3]>=deadline for c in calls))
   self.assertEqual(calls[1][1]['jwt'],'ORIGINAL_JWT');self.assertEqual(calls[2][2],'ORIGINAL_BAO')
   self.assertNotIn('ORIGINAL_',json.dumps(result));self.assertNotIn('PUBLIC',json.dumps(result))
 def test_expiry_requires_both_refusals_correct_reason_and_healthy_server(self):
  for bad in ('health','jwt-success','wrong-reason','bao-success'):
   with self.subTest(bad=bad),self.assertRaises(ValueError):self.run_expiry(bad)
 def test_long_jwt_lifetime_stops_before_any_expiry_probe(self):
  with self.assertRaises(ValueError):self.run_expiry(jwt_exp=2000)
 def test_backwards_wall_clock_does_not_wait_forever(self):
  monotonic=[0];calls=[]
  def pause(seconds):monotonic[0]+=seconds
  with self.assertRaises(ValueError):
   p.expiration_proof(lambda *a:calls.append(a),'JWT','BAO',{},1100,1200,
    clock=lambda:1000,pause=pause,elapsed=lambda:monotonic[0])
  self.assertEqual(calls,[])

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


class EnvironmentWitnessTests(unittest.TestCase):
 def call(self,bad=None):
  import os,subprocess
  from unittest.mock import patch
  def consume(args,**kwargs):
   kind=kwargs['env']['A8_WITNESS_CASE'];claims=dict(p.CLAIMS,run_id='123',run_attempt='1');claims['environment']=None if kind=='missing_environment' else 'rehearsal-issuer-negative-witness'
   if bad=='other-claim':claims['ref']='wrong'
   if bad=='run':claims['run_id']='456'
   return subprocess.CompletedProcess(args,0,json.dumps({'jwt':'PRIVATE_NEGATIVE_'+kind,'claims':claims,'case':kind}).encode())
  def api(path,data):
   self.assertTrue(data['jwt'].startswith('PRIVATE_NEGATIVE_'))
   return (200,{}) if bad=='success' else (400,{'environment_error':None if bad=='reason' else ('missing' if data['jwt'].endswith('missing_environment') else 'mismatch')})
  with patch.dict(os.environ,{'A8_WITNESS_MISSING_ENVIRONMENT':'ciphertext','A8_WITNESS_WRONG_ENVIRONMENT':'ciphertext','A8_WITNESS_SCRIPT':'public-helper'}),patch.object(p.subprocess,'run',side_effect=consume):return p.environment_witnesses(api,'123','1')
 def test_both_specific_refusals_and_no_bearer_output(self):
  result=self.call();self.assertEqual(set(result),{'missing_environment','wrong_environment'});self.assertNotIn('PRIVATE_NEGATIVE_',json.dumps(result))
 def test_generic_error_success_or_other_identity_change_cannot_pass(self):
  for bad in ('other-claim','run','success','reason'):
   with self.subTest(bad=bad),self.assertRaises(ValueError):self.call(bad)
 def test_environment_error_body_classification_is_specific(self):
  import io,ipaddress,os,subprocess,urllib.error
  from unittest.mock import patch
  addr=str(ipaddress.ip_network('100.64.0.0/10').network_address+1)
  for reason,text in [('missing','claim "environment" is missing'),('mismatch','claim "environment" does not match any associated bound claim values'),(None,'claim "ref" is missing')]:
   error=urllib.error.HTTPError('https://fixture.invalid',400,'fixture',{},io.BytesIO(json.dumps({'errors':['error validating claims: '+text]}).encode()))
   with patch.dict(os.environ,{'A8_BAO_ADDR':'http://'+addr+':8200'}),patch.object(p.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'[{"dev":"wg0"}]')),patch.object(p.OPENER,'open',side_effect=error):status,result=p.bao_client()('auth/jwt/login',{})
   self.assertEqual(status,400);self.assertEqual(result['environment_error'],reason)

class WorkflowWitnessTests(unittest.TestCase):
 def call(self,bad=None):
  import os,subprocess
  from unittest.mock import patch
  wf='dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-negative-witness.yml@refs/heads/main'
  def consume(args,**kwargs):
   self.assertEqual(kwargs['env']['GITHUB_RUN_ID'],'456');self.assertEqual(kwargs['env']['GITHUB_WORKFLOW_REF'],wf)
   claims=dict(p.CLAIMS,workflow_ref=wf,workflow_sha='a'*40,run_id='456',run_attempt='1')
   if bad=='other-claim':claims['environment']='wrong'
   if bad=='run':claims['run_id']='123'
   if bad=='source':claims['workflow_sha']='b'*40
   return subprocess.CompletedProcess(args,0,json.dumps({'jwt':'PRIVATE_WORKFLOW_FIXTURE','claims':claims,'case':'wrong_workflow'}).encode())
  def api(path,data):
   self.assertEqual(data['jwt'],'PRIVATE_WORKFLOW_FIXTURE')
   return (200,{}) if bad=='success' else (400,{'workflow_error':None if bad=='reason' else 'mismatch'})
  with patch.dict(os.environ,{'A8_WORKFLOW_WITNESS_RUN_ID':'456','A8_WORKFLOW_WITNESS_RUN_ATTEMPT':'1','A8_WORKFLOW_WITNESS':'ciphertext','A8_WITNESS_SCRIPT':'public-helper','GITHUB_SHA':'a'*40}),patch.object(p.subprocess,'run',side_effect=consume):return p.workflow_witness(api,'123','1')
 def test_specific_refusal_and_public_result(self):
  result=self.call();self.assertEqual(result['login_http'],400);self.assertEqual(result['claims']['run_id'],'456');self.assertNotIn('PRIVATE_WORKFLOW_FIXTURE',json.dumps(result))
 def test_generic_rejection_success_or_other_claim_changes_fail(self):
  for bad in ('other-claim','run','source','success','reason'):
   with self.subTest(bad=bad),self.assertRaises(ValueError):self.call(bad)
 def test_workflow_error_classification_is_specific(self):
  import io,os,subprocess,urllib.error
  from unittest.mock import patch
  for reason,text in [('mismatch','claim "workflow_ref" does not match any associated bound claim values'),(None,'claim "workflow_ref" is missing'),(None,'claim "environment" does not match any associated bound claim values')]:
   error=urllib.error.HTTPError('https://fixture.invalid',400,'fixture',{},io.BytesIO(json.dumps({'errors':['error validating claims: '+text]}).encode()))
   with patch.dict(os.environ,{'A8_BAO_ADDR':'http://100.64.0.1:8200'}),patch.object(p.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'[{"dev":"wg0"}]')),patch.object(p.OPENER,'open',side_effect=error):status,result=p.bao_client()('auth/jwt/login',{})
   self.assertEqual(status,400);self.assertEqual(result['workflow_error'],reason)

class EventWitnessTests(unittest.TestCase):
 def call(self,bad=None):
  import os,subprocess
  from unittest.mock import patch
  wf='dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-negative-witness.yml@refs/heads/main'
  def consume(args,**kwargs):
   self.assertEqual(kwargs['env']['GITHUB_EVENT_NAME'],'repository_dispatch')
   self.assertEqual(kwargs['env']['A8_WITNESS_CASE'],'wrong_event')
   claims=dict(p.CLAIMS,workflow_ref=wf,event_name='repository_dispatch',workflow_sha='a'*40,run_id='456',run_attempt='1')
   if bad=='other-claim':claims['environment']='wrong'
   if bad=='event':claims['event_name']='workflow_dispatch'
   if bad=='source':claims['workflow_sha']='b'*40
   return subprocess.CompletedProcess(args,0,json.dumps({'jwt':'PRIVATE_EVENT_FIXTURE','claims':claims,'case':'wrong_event'}).encode())
  def api(path,data):
   self.assertEqual(data['jwt'],'PRIVATE_EVENT_FIXTURE')
   return (200,{}) if bad=='success' else (400,{'event_error':'mismatch' if bad!='reason' else None})
  with patch.dict(os.environ,{'A8_WORKFLOW_WITNESS_CASE':'wrong_event','A8_WORKFLOW_WITNESS_RUN_ID':'456','A8_WORKFLOW_WITNESS_RUN_ATTEMPT':'1','A8_WORKFLOW_WITNESS':'ciphertext','A8_WITNESS_SCRIPT':'public-helper','GITHUB_SHA':'a'*40}),patch.object(p.subprocess,'run',side_effect=consume):return p.workflow_witness(api,'123','1')
 def test_coupled_result_never_claims_individual_event_coverage(self):
  result=self.call();self.assertEqual(result['changed_bound_claims'],['event_name','workflow_ref'])
  self.assertFalse(result['individual_event_claim_isolated']);self.assertFalse(result['other_six_bound_claims_match'])
  self.assertTrue(result['remaining_bound_claims_match']);self.assertEqual(result['reason'],'event_name_mismatch')
  self.assertNotIn('PRIVATE_EVENT_FIXTURE',json.dumps(result))
 def test_other_claim_generic_denial_or_success_fails(self):
  for bad in ('other-claim','event','source','reason','success'):
   with self.subTest(bad=bad),self.assertRaises(ValueError):self.call(bad)
 def test_error_classification_requires_exact_event_claim(self):
  import io,os,subprocess,urllib.error
  from unittest.mock import patch
  for message,expected in [('claim "event_name" does not match any associated bound claim values','mismatch'),('claim "ref" does not match any associated bound claim values',None),('claim "event_name" is missing',None)]:
   error=urllib.error.HTTPError('https://fixture.invalid',400,'fixture',{},io.BytesIO(json.dumps({'errors':['error validating claims: '+message]}).encode()))
   with patch.dict(os.environ,{'A8_BAO_ADDR':'http://100.64.0.1:8200'}),patch.object(p.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'[{"dev":"wg0"}]')),patch.object(p.OPENER,'open',side_effect=error):status,result=p.bao_client()('auth/jwt/login',{})
   self.assertEqual(status,400);self.assertEqual(result['event_error'],expected)

if __name__=='__main__':unittest.main()
