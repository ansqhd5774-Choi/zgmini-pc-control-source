import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {spawn} from 'node:child_process';import {fileURLToPath} from 'node:url';import {exclusive,createSupervisorStatusWriter,digest,need,assertSupervisorOwner} from './common.mjs';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),host=JSON.parse(fs.readFileSync(path.join(root,'host.json')));
for(const [rel,sha] of Object.entries(host.controllerFiles))need(digest(fs.readFileSync(path.join(root,rel)))===sha,'CONTROLLER_SOURCE_DRIFT');
const ownLease=path.join(root,'leases/supervisor'),ownerFile=path.join(ownLease,'owner.json');
if(fs.existsSync(ownerFile)){const previous=JSON.parse(fs.readFileSync(ownerFile));if(Number.isFinite(previous.bootAt)&&Math.abs(previous.bootAt-(Date.now()-os.uptime()*1000))>10000){fs.copyFileSync(ownerFile,path.join(root,'supervisor-prior-boot-'+Date.now()+'.json'));fs.unlinkSync(ownerFile);fs.rmdirSync(ownLease);}}
let release;try{release=exclusive(path.join(root,'leases'),'supervisor');}catch(error){if(error.code==='LEASE_BUSY')process.exit(0);throw error;}
const leaseNonce=JSON.parse(fs.readFileSync(ownerFile,'utf8')).nonce;
try{os.setPriority(0,os.constants.priority.PRIORITY_BELOW_NORMAL);}catch{}
const children=new Map(),attempts=new Map();let draining=false;
const writeJson=createSupervisorStatusWriter();
const status=()=>writeJson(path.join(root,'SUPERVISOR_STATUS.json'),{at:new Date().toISOString(),pid:process.pid,sourceSha:host.controllerSourceSha,mode:draining?'DRAIN':'LISTENING',children:[...children].map(([seat,c])=>({seat,pid:c.pid,alive:c.exitCode===null})),restartCounts:Object.fromEntries(attempts)});
function launch(seat){if(draining)return;
 try{assertSupervisorOwner(root,host,{ZGMINI_SUPERVISOR_NONCE:leaseNonce});}
 catch{draining=true;status();return;}
 const n=(attempts.get(seat)||0)+1;attempts.set(seat,n);if(n>3){status();return;}
 const directory=path.join(root,'runners',String(seat).padStart(2,'0'));
 const started=Date.now(),child=spawn(process.env.ComSpec||'cmd.exe',['/d','/c',path.join(directory,'run.cmd')],{cwd:directory,windowsHide:true,stdio:'ignore',env:{...process.env,ZGMINI_CONTROL_ROOT:root,ZGMINI_SUPERVISOR_NONCE:leaseNonce}});children.set(seat,child);status();
 child.once('exit',()=>{children.delete(seat);if(Date.now()-started>=600000)attempts.set(seat,0);status();if(!draining)setTimeout(()=>launch(seat),30000);});child.once('error',()=>{children.delete(seat);status();});
}
for(let seat=1;seat<=6;seat++)launch(seat);
setInterval(()=>{if(fs.existsSync(path.join(root,'DRAIN')))draining=true;status();},15000);
process.once('exit',()=>release?.());
