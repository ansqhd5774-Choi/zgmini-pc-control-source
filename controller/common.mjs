import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
// Logical read-only access: SQLite owns its read locks/WAL coordination.
// Business rows/schema stay read-only; a read transaction keeps all queries
// on one committed snapshot while the operational writer continues.
export function openSqliteReadonly(filename,{timeout=4000}={}){
 if(typeof filename!=='string'||!path.isAbsolute(filename)||filename.includes('\0'))
  throw Error('SQLITE_READONLY_PATH_INVALID');
 const {DatabaseSync}=createRequire(import.meta.url)('node:sqlite');
 const db=new DatabaseSync(filename,{readOnly:true,timeout});
 try{db.exec('PRAGMA query_only=ON');db.exec('BEGIN');return db;}
 catch(error){db.close();throw error;}
}
export const digest=x=>createHash('sha256').update(x).digest('hex');
export const need=(condition,code)=>{if(!condition)throw Object.assign(new Error(code),{code});};
export function exclusive(root,id,io=fs){
 const p=path.join(root,id);io.mkdirSync(root,{recursive:true});
 try{io.mkdirSync(p);}catch(e){if(e.code==='EEXIST')throw Object.assign(new Error('LEASE_BUSY'),{code:'LEASE_BUSY'});throw e;}
 let nonce;
 try{
  nonce=crypto.randomUUID();
  io.writeFileSync(path.join(p,'owner.json'),JSON.stringify({pid:process.pid,nonce,at:new Date().toISOString(),bootAt:Date.now()-os.uptime()*1000}),{flag:'wx'});
 }catch(error){
  // Only an empty directory created by this call may be rolled back.
  // Never unlink a possibly written owner or touch a pre-existing lease.
  try{io.rmdirSync(p);}catch{}
  throw error;
 }
 return ()=>{const f=path.join(p,'owner.json');need(JSON.parse(io.readFileSync(f)).nonce===nonce,'LEASE_OWNER_CHANGED');io.unlinkSync(f);io.rmdirSync(p);};
}
// R3 same-host standby: the existing supervisor owner is the only authority
// to start *new* work. Historical installations without the attested standby
// source keep their original entry contract until a separately approved B install.
export function assertSupervisorOwner(root,host,environment=process.env,io=fs){
 if(!Object.hasOwn(host?.controllerFiles??{},'controller/standby.mjs'))
  return 'LEGACY_CONTROLLER_UNCHANGED';
 const token=environment.ZGMINI_SUPERVISOR_NONCE;
 need(typeof token==='string'&&/^[0-9a-f-]{36}$/i.test(token),
  'SUPERVISOR_OWNERSHIP_UNVERIFIED');
 let owner;
 try{owner=JSON.parse(io.readFileSync(path.join(root,'leases/supervisor/owner.json'),'utf8'));}
 catch{need(false,'SUPERVISOR_OWNERSHIP_UNVERIFIED');}
 const bootAt=Date.now()-os.uptime()*1000;
 need(owner?.nonce===token&&Number.isSafeInteger(owner.pid)&&owner.pid>0&&
  Number.isFinite(owner.bootAt)&&Math.abs(owner.bootAt-bootAt)<10000,
  'SUPERVISOR_OWNERSHIP_LOST');
 try{process.kill(owner.pid,0);}
 catch{need(false,'SUPERVISOR_OWNERSHIP_LOST');}
 return 'SUPERVISOR_OWNERSHIP_VERIFIED';
}

export function validateRequest(request,policy){
 need(request&&typeof request==='object'&&!Array.isArray(request),'REQUEST_OBJECT');
 const keys=['schema','requestId','chatId','operation','sourceRepository','sourceBranch','sourceSha'];
 const extra=['preimageManifestPath','preimageManifestSha256'];
 const scoped=request.operation==='writer-install-preimage-readonly'&&
  Object.keys(request).length===keys.length+extra.length&&
  extra.every(k=>Object.hasOwn(request,k));
 // W04 PIT-04-08: one optional nonnegative page offset on the existing
 // allowlisted read-only R6 operation. All other request shapes stay fixed.
 const pit04=request.operation==='employment-r6-candidate-stage-readonly'&&
  Object.hasOwn(request,'pit04Offset');
 const pit0605=request.operation==='employment-r6-candidate-stage-readonly'&&
  Object.hasOwn(request,'pit0605Raw');
 const pit0408Private=request.operation==='employment-r6-candidate-stage-readonly'&&
  Object.hasOwn(request,'pit0408Private');
 need(!(pit04&&pit0605)&&!(pit0605&&pit0408Private)
  &&(!pit0408Private||(pit04&&request.pit04Offset===0))
  &&Object.keys(request).length===keys.length+(scoped?extra.length:0)
    +(pit04?1:0)+(pit0605?1:0)+(pit0408Private?1:0)
  &&keys.every(k=>Object.hasOwn(request,k))
  &&Object.keys(request).every(k=>keys.includes(k)||(scoped&&extra.includes(k))
    ||(pit04&&k==='pit04Offset')||(pit0605&&k==='pit0605Raw')
    ||(pit0408Private&&k==='pit0408Private')),
  'REQUEST_FIELDS');
 if(pit04)need(Number.isSafeInteger(request.pit04Offset)&&request.pit04Offset>=0
   &&request.pit04Offset<=50000,'PIT04_OFFSET_INVALID');
 if(pit0605)need(request.pit0605Raw===true,'PIT0605_FLAG_INVALID');
 if(pit0408Private)need(request.pit0408Private===true,'PIT0408_PRIVATE_FLAG_INVALID');
 if(scoped){
  need(typeof request.preimageManifestPath==='string'&&
   /^approvals\/writer-preimage\/[a-z0-9][a-z0-9-]{3,79}\.json$/.test(request.preimageManifestPath),
   'PREIMAGE_MANIFEST_PATH');
  need(typeof request.preimageManifestSha256==='string'&&
   /^[0-9a-f]{64}$/.test(request.preimageManifestSha256),
   'PREIMAGE_MANIFEST_SHA');
 }
 need(request.schema==='ZGMINI_PC_JOB_V1','REQUEST_SCHEMA');
 need(/^[a-z0-9][a-z0-9-]{7,79}$/.test(request.requestId),'REQUEST_ID');
 need(/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(request.chatId),'CHAT_ID');
 need(Object.hasOwn(policy.operations,request.operation),'OPERATION_NOT_ALLOWED');
 need(request.sourceRepository===policy.sourceRepository,'SOURCE_REPOSITORY');
 need(typeof request.sourceBranch==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9_./-]{0,159}$/.test(request.sourceBranch)&&!request.sourceBranch.includes('..')&&!request.sourceBranch.endsWith('.lock'),'SOURCE_BRANCH');
 need(/^[a-f0-9]{40}$/.test(request.sourceSha),'SOURCE_SHA');return request;
}
export function under(root,relative){const resolved=path.resolve(root,relative);need(resolved.startsWith(path.resolve(root)+path.sep),'PATH_OUTSIDE_JOB');return resolved;}
export function writeJson(file,value){const tmp=file+'.'+crypto.randomUUID()+'.tmp';fs.writeFileSync(tmp,JSON.stringify(value,null,2)+'\n',{flag:'wx'});fs.renameSync(tmp,file);}
// A transient heartbeat write failure must not terminate all Runner seats.
// Only the Supervisor uses this wrapper; lease/ledger writes remain strict.
export function createSupervisorStatusWriter({write=writeJson,
 report=value=>process.stderr.write(JSON.stringify(value)+'\n')}={}){
 let reported=false;
 return (file,value)=>{
  try{write(file,value);reported=false;return true;}
  catch(error){
   if(!['EACCES','EPERM','EBUSY'].includes(error?.code))throw error;
   if(!reported){
    reported=true;
    report({code:'SUPERVISOR_HEARTBEAT_WRITE_BLOCKED',ioCode:error.code,
     heartbeatUpdated:false});
   }
   // Do not synthesize a fresh heartbeat or relax the installer's freshness
   // check. The next normal tick may publish again; no job is replayed.
   return false;
  }
 };
}
export function errorCode(error){return /^[A-Z0-9_]{1,100}$/.test(error?.code??'')?error.code:'INTERNAL_EXECUTION_ERROR';}
export async function readAllPages(readPage,{maxPages=100}={}){
 const out=[];
 for(let page=1;page<=maxPages;page++){
  const rows=await readPage(page);need(Array.isArray(rows),'PAGINATION_RESPONSE_INVALID');out.push(...rows);
  if(rows.length<100)return out;
 }
 need(false,'PAGINATION_INCOMPLETE');
}
