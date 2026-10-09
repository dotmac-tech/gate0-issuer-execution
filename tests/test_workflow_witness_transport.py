import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest
from scripts import workflow_witness_transport as t

class TransportTests(unittest.TestCase):
 def setUp(self):
  self.sha='a'*40;self.recipient='b'*64
  self.run={'repository':{'id':1397614140,'full_name':t.REPOSITORY,'owner':{'id':335992433}},'status':'completed','conclusion':'success','event':'workflow_dispatch','head_branch':'main','head_sha':self.sha,'path':t.FILE,'id':456,'run_attempt':1,'created_at':'2026-10-09T10:00:10Z'}
  self.jobs=[{'id':789,'run_id':456,'head_sha':self.sha,'name':'workflow_witness','status':'completed','conclusion':'success','runner_group_id':0,'runner_id':1000000045,'labels':['ubuntu-latest']}]
  self.envelope={'v':1,'recipient':self.recipient,'wrapped':'fixture','nonce':'fixture','ciphertext':'fixture','tag':'fixture','binding':{'case':'wrong_workflow','repository_id':'1397614140','owner_id':'335992433','run_id':'456','run_attempt':'1','workflow_ref':t.WORKFLOW,'ref':'refs/heads/main','event_name':'workflow_dispatch','source_sha':self.sha}}
  self.record={'case':'wrong_workflow','status':'encrypted','recipient':self.recipient,'run_id':'456','run_attempt':'1','source_sha':self.sha}
 def log(self):
  self.record['envelope']=base64.urlsafe_b64encode(json.dumps(self.envelope).encode()).rstrip(b'=').decode()
  return 'workflow_witness\tstep\t2026-10-09T10:00:15Z '+json.dumps(self.record,separators=(',',':'))+'\n'
 def call(self,**kwargs):
  return t.qualify(self.run,self.jobs,kwargs.get('log',self.log()),self.sha,self.recipient,'2026-10-09T10:00:00Z',now=kwargs.get('now',datetime(2026,10,9,10,0,30,tzinfo=timezone.utc)),kind=kwargs.get('kind','wrong_workflow'))
 def test_qualified_api_run_returns_public_transport_and_attestation(self):
  inputs,record=self.call();self.assertEqual(inputs['workflow_witness_run_id'],'456');self.assertTrue(record['api_run_job_binding_checked']);self.assertTrue(record['not_cp_admission_evidence'])
 def test_wrong_source_event_ref_run_attempt_or_time_fails(self):
  original=deepcopy(self.run)
  for change in [{'head_sha':'c'*40},{'event':'push'},{'head_branch':'other'},{'path':'.github/workflows/gate0-issuer.yml'},{'id':457},{'run_attempt':2},{'conclusion':'failure'},{'created_at':'2026-10-09T09:59:59Z'}]:
   self.run=original|change
   with self.subTest(change=change),self.assertRaises(ValueError):self.call()
  self.run=original
  with self.assertRaises(ValueError):self.call(now=datetime(2026,10,9,10,4,tzinfo=timezone.utc))
 def test_wrong_repository_owner_or_privileged_job_fails(self):
  for key in ('id','full_name','owner'):
   original=deepcopy(self.run);self.run['repository'][key]={'id':1} if key=='owner' else 'wrong'
   with self.subTest(key=key),self.assertRaises(ValueError):self.call()
   self.run=original
  for change in [{'runner_group_id':3},{'labels':['self-hosted']},{'run_id':457},{'head_sha':'c'*40}]:
   original=deepcopy(self.jobs);self.jobs[0].update(change)
   with self.subTest(change=change),self.assertRaises(ValueError):self.call()
   self.jobs=original
 def test_envelope_case_recipient_source_and_replay_fail(self):
  original=deepcopy(self.envelope)
  for change in [{'recipient':'c'*64},{'v':2},{'extra':'unexpected'},{'binding':original['binding']|{'run_attempt':'2'}},{'binding':original['binding']|{'case':'missing_environment'}}]:
   self.envelope=original|change
   with self.subTest(change=change),self.assertRaises(ValueError):self.call()
  self.envelope=original
 def test_duplicate_missing_oversized_or_extra_field_logs_fail(self):
  log=self.log()
  for bad in [log+log,'unrelated',log+'a'*(2*1024*1024)]:
   with self.assertRaises(ValueError):self.call(log=bad)
  self.record['private_extra']='refuse'
  with self.assertRaises(ValueError):self.call()

class EventTransportTests(TransportTests):
 def setUp(self):
  super().setUp()
 def event_fixture(self):
  self.run['event']='repository_dispatch'
  self.record['case']='wrong_event'
  self.envelope['binding'].update(case='wrong_event',event_name='repository_dispatch')
 def test_event_transport_keeps_case_and_api_event_binding(self):
  self.event_fixture();inputs,record=self.call(kind='wrong_event')
  self.assertEqual(inputs['workflow_witness_case'],'wrong_event')
  self.assertEqual(record['producer_event'],'repository_dispatch')
  with self.assertRaises(ValueError):self.call()
 def test_event_substitution_case_replay_and_unknown_case_fail(self):
  for change in ('api_event','encrypted_event','case','unknown'):
   self.setUp();self.event_fixture()
   if change=='api_event':self.run['event']='workflow_dispatch'
   if change=='encrypted_event':self.envelope['binding']['event_name']='workflow_dispatch'
   if change=='case':self.record['case']='wrong_workflow'
   with self.subTest(change=change),self.assertRaises(ValueError):self.call(kind='unknown' if change=='unknown' else 'wrong_event')

if __name__=='__main__':unittest.main()
