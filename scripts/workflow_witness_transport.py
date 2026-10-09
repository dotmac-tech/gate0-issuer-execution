"""Public ciphertext transport qualification; caller supplies live GitHub API data.

No network, credentials or decryption here. This is an operator test helper, not
CP's admission oracle. The consumer separately verifies the GitHub JWT signature.
"""
import base64
from datetime import datetime, timezone
import json
import re

REPOSITORY = 'dotmac-tech/gate0-issuer-execution'
FILE = '.github/workflows/gate0-negative-witness.yml'
WORKFLOW = REPOSITORY + '/' + FILE + '@refs/heads/main'


def require(condition):
    if not condition:
        raise ValueError('producer transport qualification failed')


def qualify(run, jobs, log, revision, recipient, dispatched_at, now=None):
    """Return ciphertext dispatch inputs only after exact-source/API qualification."""
    now = datetime.now(timezone.utc) if now is None else now
    require(re.fullmatch(r'[a-f0-9]{40}', revision) is not None)
    require(re.fullmatch(r'[a-f0-9]{64}', recipient) is not None)
    require(run['repository']['id'] == 1397614140 and run['repository']['full_name'] == REPOSITORY)
    require(run['repository']['owner']['id'] == 335992433)
    require(run['status'] == 'completed' and run['conclusion'] == 'success')
    require(run['event'] == 'workflow_dispatch' and run['head_branch'] == 'main' and run['head_sha'] == revision)
    require(run['path'] in (FILE, FILE + '@refs/heads/main'))
    created = datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
    dispatched = datetime.fromisoformat(dispatched_at.replace('Z', '+00:00'))
    require(dispatched <= created <= now and 0 <= (now-created).total_seconds() <= 180)
    require(type(run['id']) is int and run['id'] > 0 and type(run['run_attempt']) is int and run['run_attempt'] > 0)
    require(len(jobs) == 1)
    job = jobs[0]
    require(job['run_id'] == run['id'] and job['head_sha'] == revision)
    require(job['name'] == 'workflow_witness' and job['status'] == 'completed' and job['conclusion'] == 'success')
    require(job['runner_group_id'] == 0 and job['runner_id'] > 0 and job['labels'] == ['ubuntu-latest'])
    require(len(log.encode()) <= 2*1024*1024)
    records = []
    for line in log.splitlines():
        marker = line.find('{"case":"wrong_workflow"')
        if marker < 0:
            continue
        value = json.loads(line[marker:])
        require(set(value) == {'case','status','recipient','envelope','run_id','run_attempt','source_sha'})
        records.append(value)
    require(len(records) == 1)
    value = records[0]
    require(value['status'] == 'encrypted' and value['recipient'] == recipient and value['source_sha'] == revision)
    require(value['run_id'] == str(run['id']) and value['run_attempt'] == str(run['run_attempt']))
    encoded = value['envelope']
    require(isinstance(encoded,str) and 0 < len(encoded) <= 20000 and re.fullmatch(r'[A-Za-z0-9_-]+',encoded) is not None)
    raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded)%4))
    require(base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == encoded)
    envelope = json.loads(raw)
    require(set(envelope) == {'v','binding','recipient','wrapped','nonce','ciphertext','tag'})
    expected = {'case':'wrong_workflow','repository_id':'1397614140','owner_id':'335992433',
                'run_id':str(run['id']),'run_attempt':str(run['run_attempt']), 'workflow_ref':WORKFLOW,
                'ref':'refs/heads/main','event_name':'workflow_dispatch','source_sha':revision}
    require(envelope['v'] == 1 and envelope['recipient'] == recipient and envelope['binding'] == expected)
    return {'workflow_witness':encoded, 'workflow_witness_run_id':str(run['id']),
            'workflow_witness_run_attempt':str(run['run_attempt'])}, {
                'producer_run_id':run['id'],'producer_run_attempt':run['run_attempt'],
                'producer_job_id':job['id'],'producer_source_sha':revision,
                'recipient_sha256':recipient,'api_run_job_binding_checked':True,
                'ciphertext_only':True,'not_cp_admission_evidence':True}
