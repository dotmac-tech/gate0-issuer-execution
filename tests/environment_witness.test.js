'use strict';
const {test}=require('node:test');const A=require('node:assert/strict');const C=require('node:crypto');
const W=require('../scripts/environment_witness.js');
const recipient=C.generateKeyPairSync('rsa',{modulusLength:3072});
const key=C.generateKeyPairSync('rsa',{modulusLength:2048});
const pem=recipient.publicKey.export({type:'spki',format:'pem'});
const env={GITHUB_REPOSITORY:'dotmac-tech/gate0-issuer-execution',GITHUB_REPOSITORY_ID:'1397614140',GITHUB_REPOSITORY_OWNER_ID:'335992433',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_WORKFLOW_REF:'dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main',GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1'};
const jwks={keys:[{...key.publicKey.export({format:'jwk'}),kid:'fixture',alg:'RS256',use:'sig'}]};
function fixture(kind='missing_environment',changes={},header={}) {
 const claims={repository:env.GITHUB_REPOSITORY,repository_id:'1397614140',repository_owner_id:'335992433',ref:env.GITHUB_REF,workflow_ref:env.GITHUB_WORKFLOW_REF,event_name:'workflow_dispatch',workflow_sha:env.GITHUB_SHA,run_id:'123',run_attempt:'1',runner_environment:'github-hosted',iss:'https://token.actions.githubusercontent.com',aud:'urn:dotmac:gate0:rehearsal-issuer',exp:1300,iat:999,nbf:999,sub:'repo:dotmac-tech@335992433/gate0-issuer-execution@1397614140:ref:refs/heads/main'};
 if(kind==='wrong_workflow'){claims.workflow_ref='dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-negative-witness.yml@refs/heads/main';claims.run_id='456';claims.environment='rehearsal-issuer-protected';claims.sub='repo:dotmac-tech@335992433/gate0-issuer-execution@1397614140:environment:rehearsal-issuer-protected';}
 if(kind==='wrong_environment'){claims.environment=W.WRONG_ENV;claims.sub='repo:dotmac-tech@335992433/gate0-issuer-execution@1397614140:environment:'+W.WRONG_ENV;}
 Object.assign(claims,changes);
 const encoded=[{alg:'RS256',kid:'fixture',...header},claims].map(x=>Buffer.from(JSON.stringify(x)).toString('base64url')).join('.');
 return encoded+'.'+C.sign('RSA-SHA256',Buffer.from(encoded),key.privateKey).toString('base64url');
}
test('both signed witnesses differ only in the bound Environment claim',()=>{
 for(const kind of ['missing_environment','wrong_environment']){
  const jwt=fixture(kind),bound=W.binding(env,kind),encrypted=W.seal(jwt,pem,bound);
  A.ok(!encrypted.includes(jwt));A.equal(W.open(encrypted,recipient.privateKey,bound),jwt);
  const claims=W.verify(jwt,env,kind,jwks,1000);A.equal(claims.environment,kind==='missing_environment'?null:W.WRONG_ENV);
  A.ok(!JSON.stringify(claims).includes(jwt));
 }
});
test('ciphertext tag, recipient and extra fields cannot be substituted',()=>{
 const bound=W.binding(env,'missing_environment'),encrypted=W.seal(fixture(),pem,bound);
 for(const field of ['ciphertext','tag','recipient','extra']){
  const value=JSON.parse(Buffer.from(encrypted,'base64url'));
  if(field==='extra')value.extra='unexpected';else if(field==='recipient')value.recipient='0'.repeat(64);else{const b=Buffer.from(value[field],'base64url');b[0]^=1;value[field]=b.toString('base64url');}
  A.throws(()=>W.open(Buffer.from(JSON.stringify(value)).toString('base64url'),recipient.privateKey,bound));
 }
});
test('recipient key, run, attempt, case and source replay fail',()=>{
 const bound=W.binding(env,'missing_environment'),encrypted=W.seal(fixture(),pem,bound);
 const wrongKey=C.generateKeyPairSync('rsa',{modulusLength:3072});A.throws(()=>W.open(encrypted,wrongKey.privateKey,bound));
 for(const change of [{run_id:'456'},{run_attempt:'2'},{case:'wrong_environment'},{source_sha:'b'.repeat(40)}])A.throws(()=>W.open(encrypted,recipient.privateKey,{...bound,...change}));
});
test('weaker recipient key and oversized ciphertext are refused',()=>{
 A.throws(()=>W.seal(fixture(),key.publicKey.export({type:'spki',format:'pem'}),W.binding(env,'missing_environment')));
 A.throws(()=>W.open('a'.repeat(20001),recipient.privateKey,W.binding(env,'missing_environment')));
});
test('signature, algorithm and signing-key selection are verified',()=>{
 const jwt=fixture();const p=jwt.split('.');const signature=Buffer.from(p[2],'base64url');signature[0]^=1;p[2]=signature.toString('base64url');A.throws(()=>W.verify(p.join('.'),env,'missing_environment',jwks,1000));
 A.throws(()=>W.verify(fixture('missing_environment',{}, {alg:'HS256'}),env,'missing_environment',jwks,1000));
 A.throws(()=>W.verify(jwt,env,'missing_environment',{keys:[]},1000));
 A.throws(()=>W.verify(jwt,env,'missing_environment',{keys:[jwks.keys[0],jwks.keys[0]]},1000));
});
test('any other bound identity, source, audience or issuer mismatch is refused',()=>{
 for(const claim of ['repository','repository_id','repository_owner_id','ref','workflow_ref','event_name','workflow_sha','run_id','run_attempt','aud','iss','runner_environment','sub'])A.throws(()=>W.verify(fixture('missing_environment',{[claim]:'wrong'}),env,'missing_environment',jwks,1000));
});
test('case and time checks prevent expiry from masquerading as Environment refusal',()=>{
 for(const change of [{environment:'unexpected'},{exp:1059},{exp:1601},{iat:1001},{nbf:1001}])A.throws(()=>W.verify(fixture('missing_environment',change),env,'missing_environment',jwks,1000));
 A.throws(()=>W.verify(fixture('wrong_environment',{environment:'rehearsal-issuer-protected'}),env,'wrong_environment',jwks,1000));
 A.throws(()=>W.verify(fixture(),env,'wrong_environment',jwks,1000));
});
for(const kind of ['missing_environment','wrong_workflow'])test(kind+': producer emits ciphertext only and consumer uses private captured pipe',async()=>{
 const selected=kind==='wrong_workflow'?{...env,GITHUB_WORKFLOW_REF:'dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-negative-witness.yml@refs/heads/main',GITHUB_RUN_ID:'456'}:env;
 const jwt=fixture(kind);
 const F=require('node:fs'),O=require('node:os'),P=require('node:path');const dir=F.mkdtempSync(P.join(O.tmpdir(),'a8-witness-fixture-'));
 const output=P.join(dir,'output'),privateFile=P.join(dir,'private');F.writeFileSync(privateFile,recipient.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});F.writeFileSync(output,'',{mode:0o600});
 const oldFetch=global.fetch,oldNow=Date.now,oldWrite=process.stdout.write;let printed='';const urls=[];
 try{
  Date.now=()=>1000000;process.stdout.write=function(chunk){printed+=chunk;return true;};
  global.fetch=async(url,options)=>{
   urls.push(String(url));A.equal(options.redirect,'error');
   const value=String(url).includes('/oidc?')?{value:jwt}:String(url).endsWith('openid-configuration')?{issuer:'https://token.actions.githubusercontent.com',jwks_uri:'https://token.actions.githubusercontent.com/jwks'}:jwks;
   return new Response(JSON.stringify(value));
  };
  await W.main({...selected,A8_WITNESS_CASE:kind,A8_WITNESS_MODE:'produce',A8_WITNESS_PUBLIC_KEY:pem,GITHUB_OUTPUT:output,ACTIONS_ID_TOKEN_REQUEST_URL:'https://fixture.actions.githubusercontent.com/oidc',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'PRIVATE_FIXTURE_REQUEST_TOKEN'});
  const line=F.readFileSync(output,'utf8');A.ok(line.startsWith('envelope='));A.ok(!line.includes(jwt));A.ok(!printed.includes('PRIVATE_FIXTURE_REQUEST_TOKEN'));A.ok(!printed.includes(jwt));
  const encrypted=line.trim().slice('envelope='.length);
  if(kind==='wrong_workflow'){const log=JSON.parse(printed);A.equal(log.envelope,encrypted);A.equal(log.run_id,'456');A.equal(log.source_sha,env.GITHUB_SHA);}
  printed='';
  await W.main({...selected,A8_WITNESS_CASE:kind,A8_WITNESS_MODE:'consume',A8_WITNESS_PRIVATE_KEY_FILE:privateFile,A8_WITNESS_ENVELOPE:encrypted});
  const result=JSON.parse(printed);A.equal(result.jwt,jwt);A.equal(result.claims.environment,kind==='wrong_workflow'?'rehearsal-issuer-protected':null);A.equal(urls.length,3);
 }finally{global.fetch=oldFetch;Date.now=oldNow;process.stdout.write=oldWrite;F.rmSync(dir,{recursive:true,force:true});}
});
test('network response cap fails closed',async()=>{
 const old=global.fetch;try{global.fetch=async()=>new Response('a'.repeat(65537));await A.rejects(()=>W.fetchJSON('https://fixture.invalid'));}finally{global.fetch=old;}
});

test('legacy and substituted immutable subjects fail closed',()=>{
 for(const kind of ['missing_environment','wrong_environment']){
  const context=kind==='missing_environment'?':ref:refs/heads/main':':environment:'+W.WRONG_ENV;
  for(const prefix of ['repo:'+env.GITHUB_REPOSITORY,'repo:dotmac-tech@1/gate0-issuer-execution@1397614140','repo:dotmac-tech@335992433/gate0-issuer-execution@1'])
   A.throws(()=>W.verify(fixture(kind,{sub:prefix+context}),env,kind,jwks,1000));
 }
});

test('wrong workflow witness preserves six bound claims and cannot be replayed as Environment witness',()=>{
 const selected={...env,GITHUB_WORKFLOW_REF:'dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-negative-witness.yml@refs/heads/main',GITHUB_RUN_ID:'456'};
 const jwt=fixture('wrong_workflow'),bound=W.binding(selected,'wrong_workflow');
 const encrypted=W.seal(jwt,pem,bound);A.equal(W.open(encrypted,recipient.privateKey,bound),jwt);
 const claims=W.verify(jwt,selected,'wrong_workflow',jwks,1000);A.equal(claims.environment,'rehearsal-issuer-protected');
 for(const claim of ['repository','repository_id','repository_owner_id','ref','event_name','environment','workflow_sha','run_id','run_attempt','sub'])
  A.throws(()=>W.verify(fixture('wrong_workflow',{[claim]:'wrong'}),selected,'wrong_workflow',jwks,1000));
 A.throws(()=>W.open(encrypted,recipient.privateKey,W.binding(env,'missing_environment')));
 A.throws(()=>W.verify(jwt,env,'wrong_workflow',jwks,1000));
});
