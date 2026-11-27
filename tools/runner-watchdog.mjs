// Out-of-band recovery of the existing six-seat controller. No Core/DB access.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {execFileSync,execFile,spawn} from 'node:child_process';
import os from 'node:os';
import {pathToFileURL} from 'node:url';

const control='E:/ZGmini/automation/pc-control';
const maintenance='E:/ZGmini/automation/pc-maintenance';
const home='E:/ZGmini/automation/pc-watchdog';
const gh='C:/Program Files/GitHub CLI/gh.exe';
const node='E:/ZGmini/runtime/node.exe';
const repo='ansqhd5774-Choi/zgmini-pc-control';
const isolatedSourceRoot=path.join(os.tmpdir(),'zgmini-watchdog-handoff-checkouts');
const handoffApprovedFiles=Object.freeze([
 'tools/maintenance-contract.mjs','tools/maintenance-apply.mjs',
 'tools/maintenance-agent.mjs','tools/maintenance-lock.mjs',
 'tools/update.mjs','tools/maintenance-ancestry.vbs',
 'tools/source-bundle-register.mjs','tools/bootstrap-maintenance.mjs',
 'tools/handoff-maintenance.mjs',
]);
const handoffTitle='pc-maintenance-handoff';
const handoffSchema='ZGMINI_MAINTENANCE_HANDOFF_REQUEST_V1';
const handoffScope='RUNNER_RECOVERY_AND_MAINTENANCE_HANDOFF_V1';
const sha40=/^[a-f0-9]{40}$/,sha64=/^[a-f0-9]{64}$/;
const requestIdPattern=/^pc-handoff-[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const strictKeys=(obj,keys)=>obj&&typeof obj==='object'&&!Array.isArray(obj)
  &&Object.keys(obj).length===keys.length&&keys.every(k=>Object.hasOwn(obj,k));
const code=x=>{throw Object.assign(Error(x),{code:x});};
const safeCode=x=>/^[A-Z][A-Z0-9_]{2,100}$/.test(String(x??''))?String(x):'HANDOFF_UNCLASSIFIED';

const sha=b=>createHash('sha256').update(b).digest('hex');
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const write=(p,x)=>{const tmp=p+'.'+randomUUID()+'.tmp';fs.writeFileSync(tmp,JSON.stringify(x,null,2)+'\n',{flag:'wx'});fs.renameSync(tmp,p);};
// Deterministic single choice: an unresolved promotion blocks BOTH candidates.
// The second candidate is a passive fallback, never an additional elector.
// A promotion attempt is not a completed switchover. If its exact IPC
// child has exited, a new candidate may be considered only after proving
// there is no live Supervisor owner or old six-seat Runner process.
export function canReconcileExitedPendingPromotion({
 pending,owner,heartbeat,runnerExecutableProof,pidAlive=alive
}={}){
 return pending?.promoting===true&&
  Number.isSafeInteger(pending?.child?.pid)&&pending.child.pid>0&&
  pidAlive(pending.child.pid)===false&&owner===null&&
  provenOldRunnerExit({owner,heartbeat,pidAlive})===true&&
  runnerExecutableProof==='NO_CONTROLLER_RUNNER_PROCESS';
}

export function selectStandbyCandidate(primary,secondary,{
 dual=false,promotionPending=null
}={}){
 if(promotionPending)return null;
 for(const candidate of dual?[primary,secondary]:[primary]){
  if(candidate?.ready===true&&candidate.promoting===false&&
    Number.isSafeInteger(candidate.child?.pid)&&candidate.child.pid>0)
   return candidate;
 }
 return null;
}
export function alive(pid){if(!Number.isSafeInteger(pid)||pid<=0)return null;try{process.kill(pid,0);return true;}catch(e){return e.code==='ESRCH'?false:null;}}
export function decide({paused,owner,live,heartbeat,now=Date.now()}){
 if(paused)return 'PAUSED';
 if(owner&&live!==false){
  // Reject future, malformed, and stale heartbeat timestamps. An unknown
  // live Supervisor is never terminated or force-recovered by this decision.
  const age=typeof heartbeat==='string'&&Number.isFinite(now)?now-Date.parse(heartbeat):NaN;
  return live===true&&Number.isFinite(age)&&age>=0&&age<45000?
   'HEALTHY':'BLOCKED_LIVE_OR_UNKNOWN';
 }
 return 'RECOVER';
}
// A stale or partial heartbeat is not a complete inventory of children.
// A crashed Supervisor can leave Runner.Listeners alive after its own PID dies.
// Standby promotion is allowed only if the last exact six-seat inventory is
// present, tied to the old owner, and every recorded child is proven exited.
// Other active Workers remain protected by their existing request/seat leases.
export function provenOldRunnerExit({owner,heartbeat,pidAlive=alive}={}){
 // A lease may be absent after a clean Supervisor exit. In that case the
 // previous heartbeat PID itself must be proven dead; a missing heartbeat
 // or a recycled/live PID is never a clean-start witness.
 const oldPid=owner?.pid??heartbeat?.pid;
 if(!Number.isSafeInteger(oldPid)||oldPid<=0||
   heartbeat?.pid!==oldPid||!Array.isArray(heartbeat.children)||
   heartbeat.children.length!==6||
   (owner==null&&pidAlive(oldPid)!==false))return false;
 const seen=new Set(),pids=new Set();
 for(const child of heartbeat.children){
  if(!Number.isSafeInteger(child?.seat)||child.seat<1||child.seat>6||
    seen.has(child.seat)||!Number.isSafeInteger(child.pid)||child.pid<=0||
    pids.has(child.pid)||pidAlive(child.pid)!==false)return false;
  seen.add(child.seat);pids.add(child.pid);
 }
 return seen.size===6;
}
// The Supervisor's six child PIDs can be cmd.exe wrappers, not the actual
// Runner.Listener/Worker executables. Dead wrappers alone do not prove the
// child process tree was stopped. This bounded, read-only WMI result is a
// SECOND required proof. Never publish raw executable paths or process ids.
export function classifyRunnerExecutableProof(rows,{controllerRoot=control,
 canonicalize=fs.realpathSync.native}={}){
 if(!Array.isArray(rows)||rows.length>256)return 'UNVERIFIED';
 let realRoot;
 try{realRoot=path.win32.normalize(canonicalize(controllerRoot)).toLowerCase();}
 catch{return 'UNVERIFIED';}
 if(!path.win32.isAbsolute(realRoot))return 'UNVERIFIED';
 const prefix=realRoot.replace(/[\\]+$/,'')+'\\runners\\';
 const seen=new Set();let serviceExceptions=0;
 for(const row of rows){
  if(!row||typeof row!=='object'||!Number.isSafeInteger(row.pid)||
    row.pid<=0||seen.has(row.pid)||!/^runner\.(listener|worker)\.exe$/i.test(row.name??''))
    return 'UNVERIFIED';
  seen.add(row.pid);
  // Only a registered running actions.runner service's own session-0 Listener
  // may lack ExecutablePath. An unbound/extra Listener always blocks promotion.
  if(row.executablePath===''&&/^runner\.listener\.exe$/i.test(row.name)&&
    row.sessionId===0&&row.serviceObservationAvailable===true&&
    row.serviceAncestor===true){
   if(++serviceExceptions>1)return 'UNVERIFIED';
   continue;
  }
  if(typeof row.executablePath!=='string'||!path.win32.isAbsolute(row.executablePath))
   return 'UNVERIFIED';
  let realFile;
  try{realFile=path.win32.normalize(canonicalize(row.executablePath)).toLowerCase();}
  catch{return 'UNVERIFIED';}
  if(!path.win32.isAbsolute(realFile))return 'UNVERIFIED';
  if(realFile.startsWith(prefix))return 'ACTIVE_RUNNER_PROCESS';
 }
 return 'NO_CONTROLLER_RUNNER_PROCESS';
}
// Fixed Windows-only observation. Uses the same WMI API as the existing
// process inventory. No command lines, environment variables, or identities
// leave this function. Query failures conservatively block only promotion.
export function scanControllerRunnersReadOnly({run=execFileSync,systemRoot=process.env.SystemRoot,
 controllerRoot=control,canonicalize=fs.realpathSync.native}={}){
 if(process.platform!=='win32'||typeof systemRoot!=='string'||
   !/^[a-z]:\\windows$/i.test(systemRoot))return 'UNVERIFIED';
 const ps=path.win32.join(systemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
 const script=[
  "$ErrorActionPreference='Stop'",
  "$all=@(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)",
  "if($all.Count -gt 4096){throw 'PROCESS_SCOPE_EXCEEDED'}",
  "$byPid=@{};foreach($p in $all){$byPid[[int]$p.ProcessId]=$p}",
  "$svc=@();$serviceObservationAvailable=$false",
  "try{$svc=@(Get-CimInstance -ClassName Win32_Service -Filter \"Name LIKE 'actions.runner.%'\" -ErrorAction Stop | Where-Object {$_.State -eq 'Running' -and [int]$_.ProcessId -gt 0});$serviceObservationAvailable=$true}catch{}",
  "$svcByPid=@{};foreach($sv in $svc){if([string]$sv.Name -match '(?i)^actions\\.runner\\.'){$svcByPid[[int]$sv.ProcessId]=$true}}",
  "$items=@(foreach($p in @($all | Where-Object {$_.Name -in @('Runner.Listener.exe','Runner.Worker.exe')})){$seen=@{};$parent=[int]$p.ParentProcessId;$serviceAncestor=$svcByPid.ContainsKey([int]$p.ProcessId);for($depth=0;$depth -lt 8 -and !$serviceAncestor;$depth++){if($parent -le 0 -or $seen.ContainsKey($parent)){break};$seen[$parent]=$true;if($svcByPid.ContainsKey($parent)){$serviceAncestor=$true;break};if(!$byPid.ContainsKey($parent)){break};$next=[int]$byPid[$parent].ParentProcessId;if($next -eq $parent){break};$parent=$next};$session=if($null -eq $p.SessionId){-1}else{[int]$p.SessionId};[pscustomobject]@{pid=[int]$p.ProcessId;name=[string]$p.Name;executablePath=[string]$p.ExecutablePath;sessionId=$session;serviceAncestor=$serviceAncestor;serviceObservationAvailable=$serviceObservationAvailable}})",
  "[pscustomobject]@{rows=$items} | ConvertTo-Json -Depth 4 -Compress"
 ].join(';');
 try{
  const out=run(ps,['-NoLogo','-NoProfile','-NonInteractive','-Command',script],
   {windowsHide:true,timeout:15000,maxBuffer:65536,encoding:'utf8'});
  if(typeof out!=='string'||Buffer.byteLength(out)>65536)return 'UNVERIFIED';
  const parsed=JSON.parse(out);
  return classifyRunnerExecutableProof(parsed?.rows,{controllerRoot,canonicalize});
 }catch{return 'UNVERIFIED';}
}

// An initial installation has no previous Supervisor and no heartbeat.
// This is different from a malformed/missing owner *with a prior heartbeat*.
// WMI executable absence and the real atomic Supervisor lease are separate
// mandatory checks before any candidate may start new Runner listeners.
export function verifiedColdStandbyStart({owner,heartbeat}={}){
 return owner===null&&heartbeat===null;
}
export function archiveDeadLease(directory,isAlive=alive,destination=null){
 if(!fs.existsSync(directory))return null;
 const original=fs.readFileSync(path.join(directory,'owner.json'));
 const owner=JSON.parse(original);
 if(isAlive(owner.pid)!==false)throw Error('LEASE_OWNER_NOT_PROVEN_DEAD');
 if(!original.equals(fs.readFileSync(path.join(directory,'owner.json'))))throw Error('LEASE_OWNER_CHANGED');
 const archived=destination??directory+'.dead-'+Date.now()+'-'+randomUUID();
 fs.renameSync(directory,archived); // Preserve evidence; never delete a lock.
 return archived;
}
function workflowActive(){return JSON.parse(execFileSync(gh,['api','repos/ansqhd5774-Choi/zgmini-pc-control/actions/workflows/pc-job.yml'],{encoding:'utf8',windowsHide:true,timeout:20000})).state==='active';}
function verifyController(){
 const host=read(path.join(control,'host.json'));
 for(const [rel,hash] of Object.entries(host.controllerFiles)){
  const p=path.resolve(control,rel);
  if(!p.startsWith(path.resolve(control)+path.sep)||sha(fs.readFileSync(p))!==hash)throw Error('CONTROLLER_HASH_MISMATCH');
 }
 return host.controllerSourceSha;
}
// A signed-looking Issue body alone is NEVER authority. The authenticated GitHub
// author, existing label, immutable raw approval bytes, and installed source
// must match. This admits only a fixed local Windows operator, not commands.
export function validateHandoffIntent(issue,body,approval,installed,rawDigest){
 const keys=['schema','requestId','operation','targetSha','approvalManifestSha256'];
 if(!strictKeys(body,keys)||body.schema!==handoffSchema
   ||body.operation!=='maintenance-handoff'
   ||!requestIdPattern.test(body.requestId??'')
   ||!sha40.test(body.targetSha??'')
   ||!sha64.test(body.approvalManifestSha256??''))code('HANDOFF_REQUEST_CONTRACT_INVALID');
 const labels=issue?.labels;
 if(issue?.title!==handoffTitle||issue?.state!=='OPEN'
   ||issue?.author?.login!=='ansqhd5774-Choi'
   ||!Array.isArray(labels)||!labels.some(label=>label?.name==='pc-maintenance'))
   code('HANDOFF_REQUEST_ACTOR_OR_LABEL_DENIED');
 if(!approval||approval.schema!=='ZGMINI_MAINTENANCE_HANDOFF_V2'
   ||approval.transition!=='SEVEN_TO_SEVEN'||approval.approved!==true
   ||approval.scope!=='COOPERATIVE_OR_STOPPED_RECEIVER_IN_PLACE'
   ||approval.targetSha!==body.targetSha
   ||approval.installedSha!==installed?.sourceSha
   ||!sha64.test(rawDigest??'')
   ||body.approvalManifestSha256!==rawDigest)
   code('HANDOFF_APPROVAL_BYTES_OR_SOURCE_MISMATCH');
 return Object.freeze({requestId:body.requestId,targetSha:body.targetSha});
}
function ghRead(args){
 return execFileSync(gh,args,{encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:1000000});
}
function git(cwd,args){
 return execFileSync('git',args,{cwd,encoding:args[0]==='show'?null:'utf8',
  windowsHide:true,timeout:30000,maxBuffer:3000000,
  env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
}
export function validateHandoffStaging(issue,body){
 if(issue?.title!==handoffTitle||issue?.state!=='OPEN'
  ||issue?.author?.login!=='ansqhd5774-Choi'
  ||!Array.isArray(issue.labels)||!issue.labels.some(x=>x?.name==='pc-maintenance')
  ||!strictKeys(body,['schema','requestId','operation','targetSha','approvalManifestSha256'])
  ||body.schema!==handoffSchema||body.operation!=='maintenance-handoff'
  ||!requestIdPattern.test(body.requestId??'')
  ||!sha40.test(body.targetSha??'')||!sha64.test(body.approvalManifestSha256??''))
  code('HANDOFF_SOURCE_STAGING_REQUEST_DENIED');
 return Object.freeze({requestId:body.requestId,targetSha:body.targetSha});
}
// Repost only an authenticated existing receipt; never rerun handoff.
export function validateExistingHandoffReceipt(issue,body,receipt,issueNumber){
 const admitted=validateHandoffStaging(issue,body);
 if(!Number.isSafeInteger(issueNumber)||issueNumber<1
   ||issue?.number!==issueNumber
   ||receipt?.schema!=='ZGMINI_WATCHDOG_HANDOFF_RECEIPT_V1'
   ||receipt.requestId!==admitted.requestId
   ||receipt.issueNumber!==issueNumber
   ||receipt.targetSha!==admitted.targetSha
   ||!['RUNNING','PASS','BLOCKED','RECOVERY_REQUIRED',
       'AUTOMATION_BLOCKED','STATE_UNKNOWN'].includes(receipt.status)
   ||(receipt.status!=='RUNNING'
       &&(typeof receipt.code!=='string'||safeCode(receipt.code)!==receipt.code))
   ||(receipt.status==='PASS'
       &&receipt.code!=='STOPPED_RECEIVER_HANDOFF_AND_WINDOWS_ORIGIN_VERIFIED'))
   code('HANDOFF_LEDGER_REQUEST_DRIFT');
 return admitted;
}
export function verifyHandoffIsolatedSource({
 checkout, approval, approvalBytes, body, installed, gitRun=git,
 readBytes=p=>fs.readFileSync(p)
}){
 const admitted=validateHandoffIntent({
  title:handoffTitle,state:'OPEN',author:{login:'ansqhd5774-Choi'},
  labels:[{name:'pc-maintenance'}],
 },body,approval,installed,sha(approvalBytes));
 if(!checkout||!path.isAbsolute(checkout))
  code('HANDOFF_SOURCE_ISOLATED_PATH_INVALID');
 if(String(gitRun(checkout,['branch','--show-current'])).trim()!=='main')
  code('HANDOFF_SOURCE_ISOLATED_NOT_MAIN');
 try{gitRun(checkout,['merge-base','--is-ancestor',admitted.targetSha,'HEAD']);}
 catch{code('HANDOFF_SOURCE_ISOLATED_ANCESTRY_DENIED');}
 const origin=String(gitRun(checkout,['remote','get-url','origin'])).trim();
 if(!['https://github.com/'+repo+'.git','https://github.com/'+repo,
       'git@github.com:'+repo+'.git','git@github.com:'+repo].includes(origin))
  code('HANDOFF_SOURCE_ISOLATED_ORIGIN_DENIED');
 const refs=[...handoffApprovedFiles,'approvals/maintenance-handoffs/'+admitted.targetSha+'.json'];
 if(String(gitRun(checkout,['status','--porcelain','--',...refs])).trim()!=='')
  code('HANDOFF_SOURCE_ISOLATED_DIRTY');
 if(!approval.files||Object.keys(approval.files).length!==handoffApprovedFiles.length
   ||!handoffApprovedFiles.every(rel=>sha64.test(approval.files[rel]??'')))
  code('HANDOFF_SOURCE_ISOLATED_FILE_PLAN_DENIED');
 for(const rel of handoffApprovedFiles){
  const filename=path.join(checkout,rel),stat=fs.lstatSync(filename);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1
    ||stat.size>2_000_000||stat.size<1
    ||sha(readBytes(filename))!==approval.files[rel])
   code('HANDOFF_SOURCE_ISOLATED_HASH_DENIED');
  if(sha(gitRun(checkout,['show',admitted.targetSha+':'+rel]))
    !==approval.files[rel])
   code('HANDOFF_SOURCE_ISOLATED_TARGET_HASH_DENIED');
 }
 return {admitted,script:path.join(checkout,'tools/handoff-maintenance.mjs'),cwd:checkout};
}
async function createHandoffSourceCheckout(requestId){
 const dir=isolatedSourceRoot;
 if(fs.existsSync(dir)){
  const stat=fs.lstatSync(dir);
  if(!stat.isDirectory()||stat.isSymbolicLink())
   code('HANDOFF_SOURCE_ISOLATED_ROOT_ALIAS');
 }else fs.mkdirSync(dir,{recursive:true});
 const checkout=path.join(dir,requestId);
 if(fs.existsSync(checkout))code('HANDOFF_SOURCE_ISOLATED_REUSED');
 const result=await new Promise((resolve,reject)=>{
  // Exact trusted private repo, isolated temp destination, new checkout.
  // Neither E:/ZGmini/projects nor the installed Controller/Receiver is changed.
  const env={...process.env,GIT_TERMINAL_PROMPT:'0',GIT_CONFIG_COUNT:'1',
   GIT_CONFIG_KEY_0:'core.autocrlf',GIT_CONFIG_VALUE_0:'false'};
  execFile(gh,['repo','clone',repo,checkout,'--','--single-branch','--branch','main'],
   {cwd:dir,env,windowsHide:true,timeout:120000,maxBuffer:250000},
   error=>error?reject(Object.assign(Error('HANDOFF_SOURCE_CLONE_FAILED'),
     {code:'HANDOFF_SOURCE_CLONE_FAILED'})):resolve(true));
 });
 if(result!==true)code('HANDOFF_SOURCE_CLONE_FAILED');
 const check=fs.lstatSync(checkout);
 if(!check.isDirectory()||check.isSymbolicLink())code('HANDOFF_SOURCE_ISOLATED_PATH_ALIAS');
 const gitDir=fs.lstatSync(path.join(checkout,'.git'));
 if(!gitDir.isDirectory()||gitDir.isSymbolicLink())
  code('HANDOFF_SOURCE_ISOLATED_GIT_ALIAS');
 return checkout;
}
async function prepareHandoff(issue,body){
 const checkout=await createHandoffSourceCheckout(body.requestId);
 const approvalFile=path.join(checkout,'approvals/maintenance-handoffs',
  body.targetSha+'.json');
 const metadata=fs.lstatSync(approvalFile);
 if(!metadata.isFile()||metadata.isSymbolicLink()||metadata.nlink!==1
   ||metadata.size>16000||metadata.size<10)
  code('HANDOFF_SOURCE_APPROVAL_PATH_DENIED');
 const approvalBytes=fs.readFileSync(approvalFile);
 const approval=JSON.parse(approvalBytes.toString('utf8'));
 const installed=read(path.join(maintenance,'MAINTENANCE_INSTALL.json'));
 const plan=verifyHandoffIsolatedSource({
  checkout,approval,approvalBytes,body,installed});
 if(fs.existsSync(path.join(maintenance,'leases/controller-install')))
  code('HANDOFF_OPERATOR_INSTALL_LEASE_BUSY');
 return plan;
}
// A child's printed PASS is insufficient: require the independent local
// install ledger and installed receiver source to agree with the exact target.
export function verifyHandoffPass({report,ledger,installed,targetSha,exitCode}){
 if(report?.status!=='PASS'||exitCode!==0
   ||ledger?.schema!=='ZGMINI_MAINTENANCE_HANDOFF_RESULT_V1'
   ||ledger.status!=='PASS'||ledger.targetSha!==targetSha
   ||ledger.code!=='STOPPED_RECEIVER_HANDOFF_AND_WINDOWS_ORIGIN_VERIFIED'
   ||!Number.isSafeInteger(ledger.receiverPid)||ledger.receiverPid<=0
   ||installed?.sourceSha!==targetSha)
   code('HANDOFF_PASS_RUNTIME_READBACK_MISMATCH');
 return true;
}
function postHandoffReceipt(issueNumber,receipt){
 const marker='zgmini-handoff-once:'+receipt.requestId;
 // A lost acknowledgement is reconciled before posting; never re-execute.
 const prior=JSON.parse(ghRead(['issue','view',String(issueNumber),'--repo',repo,'--json','comments']));
 if(prior.comments?.some(c=>String(c.body??'').includes(marker)))return;
 const body=['<!-- '+marker+' -->',
   'ZGMINI independent Windows handoff result',
   'requestId='+receipt.requestId,
   'targetSha='+receipt.targetSha,
   'status='+receipt.status,
   'code='+safeCode(receipt.code)].join('\n');
 ghRead(['issue','comment',String(issueNumber),'--repo',repo,'--body',body]);
}
export async function main(){
 const installed=read(path.join(home,'INSTALL.json'));
 if(sha(fs.readFileSync(new URL(import.meta.url)))!==installed.sha256)throw Error('WATCHDOG_SOURCE_DRIFT');
 fs.mkdirSync(home,{recursive:true});
 const lease=path.join(home,'receiver');
 if(fs.existsSync(lease)){
  const prior=read(path.join(lease,'owner.json'));
  if(alive(prior.pid)!==false){process.exitCode=10;return;}
  archiveDeadLease(lease);
 }
 fs.mkdirSync(lease);
 const nonce=randomUUID();
 write(path.join(lease,'owner.json'),{pid:process.pid,nonce,at:new Date().toISOString()});
 let history=fs.existsSync(path.join(home,'RESTART_HISTORY.json'))?read(path.join(home,'RESTART_HISTORY.json')):[];
 let healthySince=null;
 // The second passive candidate is opt-in via a distinct, future approved
 // INSTALL.json generation. Existing R4 ACTIVE_1_STANDBY_1 is unchanged.
 const standby2Mode=installed.standby?.mode==='ACTIVE_1_STANDBY_2'&&
  installed.standby?.approved===true;
 const standbyMode=installed.standby?.approved===true&&
  (installed.standby?.mode==='ACTIVE_1_STANDBY_1'||standby2Mode);
 let standby=null,secondStandby=null,standbyStarts=[],secondStandbyStarts=[];
 let promotionPending=null;
 const status=(state,extra={})=>write(path.join(home,'STATUS.json'),{
  at:new Date().toISOString(),pid:process.pid,state,
  ...(standbyMode?{
   standbyRole:standby?.ready?'READY':standby?.promoting?'PROMOTING':
    standby?'STARTING':'UNVERIFIED',standbyPid:standby?.child?.pid??null,
   ...(standby2Mode?{
    secondStandbyRole:secondStandby?.ready?'READY':secondStandby?.promoting?
     'PROMOTING':secondStandby?'STARTING':'UNVERIFIED',
    secondStandbyPid:secondStandby?.child?.pid??null,
    standbyReadyCount:Number(standby?.ready===true)+Number(secondStandby?.ready===true)
   }:{})
  }:{}),
  ...extra});
 function ensureStandby(){
  if(!standbyMode||promotionPending)return;
  // One Watchdog owns BOTH children. Every slot has its own 3/hour restart
  // budget; the existing single-Standby slot retains its old ceiling.
  for(const slot of (standby2Mode?[1,2]:[1])){
   if(slot===1?standby:secondStandby)continue;
   const recent=(slot===1?standbyStarts:secondStandbyStarts)
    .filter(t=>Date.now()-t<3600000);
   if(slot===1)standbyStarts=recent;else secondStandbyStarts=recent;
   if(recent.length>=3)continue;
   try{
    const host=read(path.join(control,'host.json'));
    if(!/^[a-f0-9]{64}$/.test(host.controllerFiles?.['controller/standby.mjs']??''))
     throw Error('STANDBY_SOURCE_NOT_ATTESTED');
    const sourceSha=verifyController();
    const child=spawn(node,[path.join(control,'controller/standby.mjs')],{
     cwd:control,windowsHide:true,stdio:['ignore','ignore','ignore','ipc'],
     env:{...process.env,ZGMINI_WATCHDOG_NONCE:nonce,
      ZGMINI_WATCHDOG_PID:String(process.pid)}
    });
    recent.push(Date.now());
    const current={child,ready:false,promoting:false,sourceSha,slot};
    if(slot===1)standby=current;else secondStandby=current;
    const currentSlot=()=>slot===1?standby:secondStandby;
    child.on('message',message=>{
     if(currentSlot()!==current)return;
     if(message?.type==='READY'&&message.pid===child.pid&&
       message.sourceSha===sourceSha)current.ready=true;
     if(message?.type==='PROMOTION_ATTEMPTED'&&message.pid===child.pid)
      current.promoting=true;
     if(message?.type==='PROMOTION_BLOCKED'||message?.type==='PROMOTION_FAILED'){
      current.ready=false;current.error=message.code??'STANDBY_PROMOTION_UNVERIFIED';
     }
    });
    child.once('exit',()=>{
     if(currentSlot()===current){
      if(slot===1)standby=null;else secondStandby=null;
     }
    });
    child.once('error',()=>{
     if(currentSlot()===current){
      if(slot===1)standby=null;else secondStandby=null;
     }
    });
   }catch{status('BLOCKED_STANDBY_SETUP');}
  }
 }
 async function tick(){
  try{
   const ownerFile=path.join(control,'leases/supervisor/owner.json');
   const owner=fs.existsSync(ownerFile)?read(ownerFile):null;
   const hb=fs.existsSync(path.join(control,'SUPERVISOR_STATUS.json'))?read(path.join(control,'SUPERVISOR_STATUS.json')):null;
   const paused=fs.existsSync(path.join(home,'PAUSE'))||fs.existsSync(path.join(control,'DRAIN'))
    ||fs.existsSync(path.join(maintenance,'leases/controller-install'))
    ||fs.readdirSync(path.join(control,'leases')).some(x=>x!=='supervisor'&&!x.startsWith('supervisor.dead-'));
   const state=decide({paused,owner,live:owner?alive(owner.pid):false,heartbeat:hb?.pid===owner?.pid?hb?.at:null});
   if(state==='HEALTHY'){
    // A single pending promotion must be confirmed by the *real* Supervisor
    // lease and fresh heartbeat before either standby slot can rearm.
    if(standbyMode&&promotionPending){
     if(promotionPending.child.pid!==owner.pid){
      // Existing Active is objectively healthy. Never degrade its public
      // Watchdog health just because our passive promotion remains uncertain.
      status(state,{supervisorPid:owner.pid,heartbeatAt:hb.at,
       standbyPromotionStatus:'UNVERIFIED_OWNER_MISMATCH'});return;
     }
     if(promotionPending.slot===2)secondStandby=null;
     else standby=null;
     promotionPending=null;
    }
    healthySince??=Date.now();
    if(Date.now()-healthySince>600000&&history.length){history=[];write(path.join(home,'RESTART_HISTORY.json'),history);}
    status(state,{supervisorPid:owner.pid,heartbeatAt:hb.at});return;
   }
   healthySince=null;
   if(state!=='RECOVER'){status(state,{supervisorPid:owner?.pid??null,heartbeatAt:hb?.at??null});return;}
   // No fallback while an earlier promotion has an unknown outcome.
   if(standbyMode&&promotionPending){
    const pending=promotionPending;
    // Failed IPC promotion can leave an exited primary in memory while the
    // secondary remains READY. Never clear this fence just because a status
    // field is empty or one PID has disappeared.
    const safe=canReconcileExitedPendingPromotion({
     pending,owner,heartbeat:hb,runnerExecutableProof:scanControllerRunnersReadOnly()
    });
    if(!safe){
     status('BLOCKED_STANDBY_PROMOTION_OUTCOME_UNKNOWN');return;
    }
    // This is not approval to force-promote anything. Existing selection,
    // six-child proof, WMI checks and atomic Supervisor lease still apply.
    if(pending.slot===1&&standby===pending)standby=null;
    if(pending.slot===2&&secondStandby===pending)secondStandby=null;
    promotionPending=null;
   }
   const candidate=standbyMode?selectStandbyCandidate(standby,secondStandby,
    {dual:standby2Mode,promotionPending}):null;
   if(standbyMode&&!candidate){
    status('BLOCKED_STANDBY_NOT_READY');return;
   }
   if(standbyMode&&!verifiedColdStandbyStart({owner,heartbeat:hb})&&
     !provenOldRunnerExit({owner,heartbeat:hb})){
    // A partial/ambiguous past owner needs full six-seat exit evidence.
    // A verified first start (no owner AND no historical heartbeat) is
    // handled separately, still requiring the independent WMI check below.
    status('BLOCKED_OLD_RUNNER_CHILD_UNVERIFIED');return;
   }
   if(standbyMode&&scanControllerRunnersReadOnly()!=='NO_CONTROLLER_RUNNER_PROCESS'){
    // A dead cmd.exe launcher does not prove its Runner.Listener.exe exited.
    // Unknown WMI process attribution must not create a second Runner owner.
    status('BLOCKED_OLD_RUNNER_EXECUTABLE_UNVERIFIED');return;
   }
   if(!workflowActive()){status('PAUSED_WORKFLOW');return;}
   history=history.filter(x=>Date.now()-x<3600000);
   if(history.length>=3){status('BLOCKED_RESTART_LIMIT');return;}
   const sourceSha=verifyController();
   // Recheck update and owner immediately before recovery; no process is killed.
   if(fs.existsSync(path.join(maintenance,'leases/controller-install'))){status('PAUSED');return;}
   fs.mkdirSync(path.join(home,'archives'),{recursive:true});
   const archived=archiveDeadLease(path.join(control,'leases/supervisor'),alive,path.join(home,'archives','supervisor-'+Date.now()+'-'+randomUUID()));
   history.push(Date.now());write(path.join(home,'RESTART_HISTORY.json'),history);
   if(standbyMode){
    candidate.promoting=true;candidate.ready=false;
    promotionPending=candidate;
    try{
     candidate.child.send({type:'PROMOTE',oldChildrenStopped:true},error=>{
      if(error)status('BLOCKED_STANDBY_IPC_DELIVERY_UNKNOWN');
     });
    }catch{status('BLOCKED_STANDBY_IPC_DELIVERY_UNKNOWN');return;}
    // No active/pass claim until the next tick verifies real owner+heartbeat.
    status('STARTING',{standbyPid:candidate.child.pid,sourceSha,archivedLease:archived});
    return;
   }
   const out=fs.openSync(path.join(home,'SUPERVISOR_OUTPUT.log'),'a');
   try{
    const child=spawn(node,[path.join(control,'controller/supervisor.mjs')],{cwd:control,windowsHide:true,detached:true,stdio:['ignore',out,out],env:{...process.env}});
    child.once('error',()=>status('BLOCKED_SPAWN_ERROR'));
    child.unref();status('STARTING',{supervisorPid:child.pid??null,sourceSha,archivedLease:archived});
   }finally{fs.closeSync(out);}
  }catch(e){status('BLOCKED',{code:/^[A-Z_]+$/.test(e.message)?e.message:'WATCHDOG_CHECK_FAILED'});}
 }
 // This optional capability is activated only by a separately verified,
 // approved watchdog install; historical RUNNER_RECOVERY_ONLY installations
 // stay unchanged even if a checkout file is updated.
 let handoffActive=false;
 async function pollHandoff(){
  if(handoffActive||installed.scope!==handoffScope)return;
  if(process.platform!=='win32'||process.env.GITHUB_ACTIONS||process.env.RUNNER_NAME)return;
  handoffActive=true;
  let issueNumber=null,receiptFile=null;
  try{
   // Paused/active Controller transitions are never used as a handoff window.
   if(fs.existsSync(path.join(home,'PAUSE'))||fs.existsSync(path.join(control,'DRAIN'))
     ||fs.existsSync(path.join(maintenance,'leases/controller-install')))return;
   const listed=JSON.parse(ghRead(['issue','list','--repo',repo,'--label','pc-maintenance',
     '--state','open','--limit','1000','--json','number,title']));
   if(!Array.isArray(listed))code('HANDOFF_ISSUE_LIST_INVALID');
   const intents=listed.filter(q=>q?.title===handoffTitle);
   if(!intents.length)return;
   if(intents.length!==1||!Number.isSafeInteger(intents[0].number))
     code('HANDOFF_MULTIPLE_OR_INVALID_INTENTS');
   issueNumber=intents[0].number;
   const issue=JSON.parse(ghRead(['issue','view',String(issueNumber),'--repo',repo,
     '--json','number,title,state,author,labels,body']));
   let body;
   try{body=JSON.parse(issue.body??'');}
   catch{code('HANDOFF_SOURCE_STAGING_REQUEST_DENIED');}
   const admitted=validateHandoffStaging(issue,body);
   const dir=path.join(home,'handoff-attempts');fs.mkdirSync(dir,{recursive:true});
   receiptFile=path.join(dir,admitted.requestId+'.json');
   if(fs.existsSync(receiptFile)){
    const receipt=read(receiptFile);
    // Re-authenticate receipt identity; never repeat installation.
    validateExistingHandoffReceipt(issue,body,receipt,issueNumber);
    if(receipt.status==='RUNNING'){
     // After this watchdog process restarted, the old child may still be
     // running. Never retry or assert failure; preserve and report unknown.
     const unknown={...receipt,status:'STATE_UNKNOWN',
       code:'HANDOFF_INTERRUPTED_RECONCILE',at:new Date().toISOString()};
     write(receiptFile,unknown);
     postHandoffReceipt(issueNumber,unknown);
     return;
    }
    if(receipt.status&&receipt.code)postHandoffReceipt(issueNumber,receipt);
    return;
   }
   const initial={schema:'ZGMINI_WATCHDOG_HANDOFF_RECEIPT_V1',
     requestId:admitted.requestId,issueNumber,targetSha:admitted.targetSha,
     status:'RUNNING',phase:'SOURCE_PREPARING',at:new Date().toISOString()};
   // Durable one-use claim BEFORE temporary source preparation. A clone
   // failure is terminal BLOCKED; no automatic retries, force pulls or resets.
   fs.writeFileSync(receiptFile,JSON.stringify(initial)+'\n',{flag:'wx',mode:0o600});
   let plan;
   try{plan=await prepareHandoff(issue,body);}
   catch(e){
    const failed={...initial,status:'BLOCKED',phase:'SOURCE_STAGING_FAILED',
      code:safeCode(e?.code??e?.message),at:new Date().toISOString()};
    write(receiptFile,failed);
    postHandoffReceipt(issueNumber,failed);
    return;
   }
   write(receiptFile,{...initial,phase:'OPERATOR_INVOCATION'});
   const result=await new Promise(resolve=>{
    const child=spawn(node,[plan.script,'--source-sha',plan.admitted.targetSha],
      {cwd:plan.cwd,windowsHide:true,stdio:['ignore','pipe','pipe']});
    let output='',limit=false;
    child.stdout.on('data',b=>{if(output.length+String(b).length>16384)limit=true;
      else output+=String(b);});
    child.stderr.on('data',()=>{}); // No operator stderr or secrets in GitHub.
    child.on('error',()=>resolve({status:'STATE_UNKNOWN',code:'HANDOFF_SPAWN_UNCERTAIN'}));
    child.on('close',(exitCode,signal)=>{
     if(limit||signal)return resolve({status:'STATE_UNKNOWN',code:'HANDOFF_OUTCOME_UNCERTAIN'});
     try{
      const lines=output.trim().split(/\r?\n/),json=JSON.parse(lines[lines.length-1]);
      if(json.targetSha!==plan.admitted.targetSha||!['PASS','BLOCKED',
          'RECOVERY_REQUIRED','AUTOMATION_BLOCKED'].includes(json.status))
        return resolve({status:'STATE_UNKNOWN',code:'HANDOFF_OUTCOME_UNCERTAIN'});
      if(json.status==='PASS'){
       try{
        verifyHandoffPass({report:json,
         ledger:read(path.join(maintenance,'handoff-'+plan.admitted.targetSha+'.json')),
         installed:read(path.join(maintenance,'MAINTENANCE_INSTALL.json')),
         targetSha:plan.admitted.targetSha,exitCode});
       }catch{return resolve({status:'STATE_UNKNOWN',code:'HANDOFF_PASS_RUNTIME_READBACK_MISMATCH'});}
      }
      return resolve({status:json.status,code:safeCode(json.code??'HANDOFF_UNKNOWN')});
     }catch{return resolve({status:'STATE_UNKNOWN',code:'HANDOFF_OUTCOME_UNCERTAIN'});}
    });
   });
   const receipt={...initial,...result,at:new Date().toISOString()};
   write(receiptFile,receipt);
   postHandoffReceipt(issueNumber,receipt);
  }catch(error){
   const c=safeCode(error?.code??error?.message);
   write(path.join(home,'HANDOFF_STATUS.json'),{at:new Date().toISOString(),
     status:'BLOCKED',code:c,issueNumber});
  }finally{handoffActive=false;}
 }
 ensureStandby();await tick();setInterval(()=>{ensureStandby();void tick();},15000);
 void pollHandoff();setInterval(()=>{void pollHandoff();},60000);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{process.exitCode=1;});
