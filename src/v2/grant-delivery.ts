import {constants} from 'node:fs';
import {open,lstat,realpath} from 'node:fs/promises';
import {dirname,resolve,join,basename} from 'node:path';
import {randomUUID} from 'node:crypto';
import {AccessDenied,type Actor} from './authorization.js';
import type {GrantDelivery} from './grants.js';
import {scopeFilter,type V2MongoStore,type V2Transaction} from './mongo-store.js';
export interface DeploymentGrantSink {
 readonly id:string;
 deliver(input:{applicationId:string;environment:string;password:string}):Promise<void>;
}
/** Operator-configured output only. No browser-controlled paths or active-file replacement. */
export class PrivateFileGrantSink implements DeploymentGrantSink {
 constructor(readonly id:string,private readonly filename:string,private readonly vaultUrl:string) {}
 async deliver(input:{applicationId:string;environment:string;password:string}) {
  const {environment}=scopeFilter({environment:input.environment,ownerType:'application',ownerId:input.applicationId});
  const url=new URL(this.vaultUrl);
  if(!this.id || url.username||url.password||url.search||url.hash||url.pathname!=='/' ||
   (url.protocol!=='https:' && !(url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname))) ||
   !/^[A-Za-z0-9_-]{43}$/.test(input.password))throw new AccessDenied();
  const parent=resolve(dirname(this.filename)), info=await lstat(parent);
  if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o077)!==0)throw new AccessDenied();
  const canonicalParent=await realpath(parent);
  const file=await open(join(canonicalParent,basename(this.filename)),constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
  const bytes=Buffer.from(JSON.stringify({VAULT_URL:this.vaultUrl,VAULT_APPLICATION_ID:input.applicationId,VAULT_ENVIRONMENT:environment,VAULT_GRANT:input.password}));
  try{await file.writeFile(bytes);await file.sync();}finally{bytes.fill(0);await file.close();}
  const directory=await open(canonicalParent,constants.O_RDONLY|constants.O_DIRECTORY);
  try{await directory.sync();}finally{await directory.close();}
 }
}
/** A concrete deployment-only delivery adapter. Administrators receive metadata,
 * while grants are staged to an operator-configured private sink. */
export class DeploymentGrantDelivery implements GrantDelivery {
 constructor(private readonly store:V2MongoStore,private readonly sink:DeploymentGrantSink) {}
 async approve(_actor:Actor,applicationId:string,environment:string) {
  scopeFilter({environment,ownerType:'application',ownerId:applicationId});
  const observe=async(tx:V2Transaction)=>{
   const opts={session:tx.session};
   const custody=await tx.db.collection<any>('vault_deployment_custody').findOne({applicationId,environment,enabled:true,mode:'deployment-only',deliveryId:this.sink.id},opts);
   if(!custody||!Number.isSafeInteger(custody.revision)||custody.revision<1)throw new AccessDenied();
   const assignments=await tx.db.collection('vault_application_tenants').find({applicationId,environment,enabled:true},opts).limit(1001).toArray();
   if(assignments.length>1000)throw new AccessDenied();
   const enrollments=[];
   for(const assignment of assignments){
    if(typeof assignment.tenantId!=='string')throw new AccessDenied();
    const enrollment=await tx.db.collection('vault_machine_enrollments').findOne({applicationId,environment,tenantId:assignment.tenantId,approved:true},opts);
    if(!enrollment)throw new AccessDenied();enrollments.push(enrollment);
   }
   return {custody,enrollments};
  };
  const initial=await this.store.transaction(observe);
  const approvedTenantIds=initial.enrollments.map(row=>String(row.tenantId)).sort();
  return {
   applicationId,environment,approvedTenantIds,
   deliver:(password:string)=>this.sink.deliver({applicationId,environment,password}),
   fence:async(tx:V2Transaction)=>{
    const current=await observe(tx);
    if(current.custody._id!==initial.custody._id||current.custody.revision!==initial.custody.revision||
      JSON.stringify(current.enrollments.map(row=>String(row.tenantId)).sort())!==JSON.stringify(approvedTenantIds))throw new AccessDenied();
    const updated=await tx.db.collection('vault_deployment_custody').updateOne({_id:current.custody._id,revision:current.custody.revision,enabled:true,deliveryId:this.sink.id},{$inc:{authorizationFence:1}},{session:tx.session});
    if(updated.matchedCount!==1)throw new AccessDenied();
    for(const enrollment of current.enrollments){
     const changed=await tx.db.collection('vault_machine_enrollments').updateOne({_id:enrollment._id,approved:true},{$inc:{authorizationFence:1}},{session:tx.session});
     if(changed.matchedCount!==1)throw new AccessDenied();
    }
   },
  };
 }
}

/** Root directory is selected by the deployment, never an admin request. */
export class PrivateDirectoryGrantSink implements DeploymentGrantSink {
  readonly id="private-deployment-files";
  constructor(private readonly directory:string,private readonly vaultUrl:string){}
  deliver(input:{applicationId:string;environment:string;password:string}) {
    scopeFilter({environment:input.environment,ownerType:"application",ownerId:input.applicationId});
    return new PrivateFileGrantSink(this.id,join(this.directory,`${input.environment}-${input.applicationId}-${randomUUID()}.json`),this.vaultUrl).deliver(input);
  }
}
