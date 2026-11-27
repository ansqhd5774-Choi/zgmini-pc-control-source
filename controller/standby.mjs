// ZGMINI R3 same-host warm Standby. No Runner or Worker starts while READY.
// Only the installed Watchdog's verified IPC may request promotion.
// Promoted process imports the existing Supervisor, which atomically owns
// leases/supervisor and retains its original six-seat execution policy.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const watchdogHome='E:/ZGmini/automation/pc-watchdog';
const maintenanceHome='E:/ZGmini/automation/pc-maintenance';
const sha=x=>createHash('sha256').update(x).digest('hex');
const err=x=>Object.assign(Error(x),{code:x});
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));

export function decideStandbyPromotion({
 sourceVerified,watchdogBound,supervisorLeasePresent,relatedLeasesPresent,
 maintenanceBusy,activeChildrenStopped
}={}){
 if(sourceVerified!==true)return 'HOLD_SOURCE_UNVERIFIED';
 if(watchdogBound!==true)return 'HOLD_WATCHDOG_IDENTITY';
 if(maintenanceBusy!==false)return 'HOLD_MAINTENANCE';
 if(relatedLeasesPresent!==false)return 'HOLD_RELATED_JOB';
 if(supervisorLeasePresent!==false)return 'HOLD_EXISTING_OWNER';
 if(activeChildrenStopped!==true)return 'HOLD_EXISTING_CHILD';
 return 'ELIGIBLE_FOR_SUPERVISOR_ATOMIC_ACQUIRE';
}

export function watchdogIdentityMatches(owner,{parentPid,nonce}={}){
 return owner!==null&&typeof owner==='object'&&
  Number.isSafeInteger(owner.pid)&&owner.pid>0&&
  owner.pid===parentPid&&typeof owner.nonce==='string'&&
  owner.nonce.length>=16&&owner.nonce===nonce;
}

export function verifyStandbySource(home=root,files=fs){
 const host=read(path.join(home,'host.json'));
 const expected=host?.controllerFiles;
 if(!expected||typeof expected!=='object'||Array.isArray(expected)||
  !/^[a-f0-9]{64}$/.test(expected['controller/standby.mjs']??'')||
  !/^[a-f0-9]{64}$/.test(expected['controller/supervisor.mjs']??''))
  throw err('STANDBY_MANIFEST_NOT_APPROVED');
 for(const [rel,digest] of Object.entries(expected)){
  if(!/^(controller\/[a-z0-9-]+\.mjs|config\/operations\.json)$/.test(rel)||
   !/^[a-f0-9]{64}$/.test(digest))throw err('STANDBY_MANIFEST_UNSAFE');
  const filename=path.resolve(home,rel);
  if(!filename.startsWith(path.resolve(home)+path.sep)||
   sha(files.readFileSync(filename))!==digest)throw err('STANDBY_SOURCE_DRIFT');
 }
 return host.controllerSourceSha;
}

function observePromotion({expectedNonce,expectedPid,sourceSha}){
 const receiver=path.join(watchdogHome,'receiver/owner.json');
 let bound=false;
 try{bound=watchdogIdentityMatches(read(receiver),{
  parentPid:expectedPid,nonce:expectedNonce});
 }catch{/* Unable to authenticate: never promote. */}
 const controlLeases=path.join(root,'leases');
 const names=fs.readdirSync(controlLeases);
 const supervisorLeasePresent=names.includes('supervisor');
 const relatedLeasesPresent=names.some(x=>
  x!=='supervisor'&&!x.startsWith('supervisor.dead-'));
 const maintenanceBusy=fs.existsSync(path.join(watchdogHome,'PAUSE'))||
  fs.existsSync(path.join(root,'DRAIN'))||
  fs.existsSync(path.join(maintenanceHome,'leases/controller-install'));
 let verified=false;
 try{verified=verifyStandbySource()===sourceSha;}catch{/* Source not certified. */}
 // The Watchdog already checked every child PID before archiving the old
 // lease. A second unchanged, exact proof is required by the promotion IPC.
 return {sourceVerified:verified,watchdogBound:bound,
  supervisorLeasePresent,relatedLeasesPresent,maintenanceBusy};
}

export async function main(){
 if(process.platform!=='win32'||typeof process.send!=='function'||
  process.env.GITHUB_ACTIONS||process.env.RUNNER_NAME)
  throw err('STANDBY_WATCHDOG_WINDOWS_IPC_REQUIRED');
 const nonce=process.env.ZGMINI_WATCHDOG_NONCE;
 const parentPid=Number(process.env.ZGMINI_WATCHDOG_PID);
 const receiver=read(path.join(watchdogHome,'receiver/owner.json'));
 if(!watchdogIdentityMatches(receiver,{parentPid,nonce})||
  process.ppid!==parentPid)throw err('STANDBY_WATCHDOG_IDENTITY_UNVERIFIED');
 // Keep the authenticated IPC token only in this candidate's private closure.
 // The promoted process later spawns Runner.Listener children; Watchdog
 // credentials must never be inherited into jobs or worker environments.
 delete process.env.ZGMINI_WATCHDOG_NONCE;
 delete process.env.ZGMINI_WATCHDOG_PID;
 const sourceSha=verifyStandbySource();
 let promoting=false,done=false;
 process.on('disconnect',()=>{if(!promoting)process.exit(0);});
 process.on('message',async message=>{
  if(message?.type!=='PROMOTE'||done)return;
  done=true;
  let state;
  try{
   state=decideStandbyPromotion({
    ...observePromotion({expectedNonce:nonce,expectedPid:parentPid,sourceSha}),
    activeChildrenStopped:message.oldChildrenStopped===true
   });
  }catch{state='HOLD_PROMOTION_OBSERVATION_UNVERIFIED';}
  if(state!=='ELIGIBLE_FOR_SUPERVISOR_ATOMIC_ACQUIRE'){
   // A rejected one-shot candidate must not remain READY=false forever:
   // release the IPC child so the sole Watchdog may rearm a fresh candidate.
   process.send?.({type:'PROMOTION_BLOCKED',code:state,pid:process.pid},()=>{
    process.exitCode=1;
    process.disconnect?.();
   });
   return;
  }
  // A one-shot, authenticated promotion request never steals or removes
  // leases. Existing supervisor.mjs acquires the sole real Active lease.
  promoting=true;
  process.send?.({type:'PROMOTION_ATTEMPTED',pid:process.pid});
  try{await import('./supervisor.mjs');}
  catch(e){
   process.send?.({type:'PROMOTION_FAILED',code:'STANDBY_SUPERVISOR_IMPORT_FAILED'},()=>{
    process.exitCode=1;
    process.disconnect?.();
   });
  }
 });
 process.send({type:'READY',pid:process.pid,sourceSha});
 // IPC listener keeps the process warm; READY itself has zero operational writes.
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(error=>{process.stderr.write((error?.code??'STANDBY_INIT_FAILED')+'\n');process.exitCode=1;});
}
