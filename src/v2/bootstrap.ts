import { effectiveCustody, isWorkloadAccessName } from "./resource-custody.js";
import { IntegrationSchemas } from "./integration-schemas.js";
import { hash } from "./instances.js";
import { createHash } from "node:crypto";
import { AccessDenied } from "./authorization.js";
import {
  scopeFilter,
  type V2MongoStore,
  type V2Transaction,
} from "./mongo-store.js";
import type {
  GrantRecord,
  ResourceRecord,
  ResourceScope,
  ResourceVersion,
} from "./records.js";
export interface BootstrapValue {
  resourceId: string;
  versionId: string;
  name: string;
  accessName: string;
  kind: ResourceRecord["kind"];
  valueFormat: ResourceRecord["valueFormat"];
  schemaIdentity: string;
  value: string | Record<string, unknown>;
  schema?: unknown;
  keyVersions?: {
    versionId: string;
    state: string;
    value: string;
    rotationId?: string;
    keyLabel?: string;
  }[];
}
export interface BootstrapContext {
  ready: boolean;
  reason?: string;
  values: BootstrapValue[];
}
export interface BootstrapSnapshot {
  format: 2;
  applicationId: string;
  environment: string;
  revision: string;
  application: BootstrapContext;
  tenants: Record<string, BootstrapContext>;
}
export function bootstrapDigest(view: unknown): string {
  return (
    '"' + createHash("sha256").update(JSON.stringify(view)).digest("hex") + '"'
  );
}
export class BootstrapService {
 constructor(private readonly store:V2MongoStore,private readonly schemas=new IntegrationSchemas()){}
 async snapshot(header:unknown,applicationId:string,environment:string,ifNoneMatch?:string,instance?:{instanceId:string;password:string}):Promise<{status:304;etag:string}|{status:200;etag:string;snapshot:BootstrapSnapshot}>{
  scopeFilter({environment,ownerType:'application',ownerId:applicationId});if(typeof header!=='string'||!/^Bearer [A-Za-z0-9_-]{43}$/.test(header))throw new AccessDenied();const tokenHash=createHash('sha256').update(header.slice(7)).digest('hex');
  return this.store.transaction(async tx=>{
   const opts={session:tx.session},grant=await this.store.grants.findOne({tokenHash,applicationId,environment,grantClass:'application',enabled:true},opts);if(!grant)throw new AccessDenied();
   if(instance&&!await tx.db.collection<any>('vault_application_instances').findOne({_id:instance.instanceId,applicationId,environment,grantId:grant._id,retired:false,passwordHash:hash(instance.password)},opts))throw new AccessDenied();
   const deployment=await tx.db.collection('vault_application_environments').findOne({applicationId,environment,enabled:true},opts);if(!deployment)throw new AccessDenied();
   const assignments=await tx.db.collection('vault_application_tenants').find({applicationId,environment,enabled:true},opts).sort({tenantId:1}).limit(1001).toArray(),links=await this.store.links.find({applicationId,environment},opts).sort({_id:1}).limit(10001).toArray();if(assignments.length>1000||links.length>10000)throw Error('Bootstrap view exceeds limits');
   const scopes=new Map<string,ResourceScope>([['',{environment,ownerType:'application',ownerId:applicationId}]]);for(const row of assignments){if(typeof row.tenantId!=='string')throw Error('Invalid tenant assignment');scopes.set(row.tenantId,scopeFilter({environment,ownerType:'tenant',ownerId:row.tenantId}));}
   type Row={resource:ResourceRecord;versionId:string;accessName:string};type Context={ready:boolean;reason?:string;rows:Row[]};const contexts=new Map<string,Context>([...scopes].map(([id])=>[id,{ready:true,rows:[]}]));
   const activeTenants=new Set((await tx.db.collection('vault_tenant_environments').find({environment,tenantId:{$in:[...scopes.keys()].filter(Boolean)},enabled:true},opts).toArray()).map(r=>r.tenantId));for(const[id,c]of contexts)if(id&&!activeTenants.has(id)){c.ready=false;c.reason='Tenant static access unavailable';}
   const resourceRows=await this.store.resources.find({_id:{$in:links.map(l=>l.resourceId)},environment,enabled:true,deletedAt:{$exists:false}},opts).toArray(),resources=new Map(resourceRows.map(r=>[r._id,r]));
   const activeSources=new Set((await tx.db.collection('vault_application_environments').find({environment,applicationId:{$in:[...new Set(resourceRows.filter(r=>r.ownerType==='application').map(r=>r.ownerId))]},enabled:true},opts).toArray()).map(r=>r.applicationId));
   const selectedIds=links.map(l=>l.versionPolicy==='latest'?resources.get(l.resourceId)?.currentVersionId:l.versionPolicy).filter((id):id is string=>!!id);
   const metadata=await this.store.versions.find({_id:{$in:selectedIds},environment},{...opts,projection:{_id:1,resourceId:1,environment:1,ownerType:1,ownerId:1,versionNumber:1,kind:1,contentType:1,valueFormat:1,schemaIdentity:1,encodedBytes:{$strLenCP:'$value.ciphertext'}}}).toArray(),versions=new Map(metadata.map(v=>[v._id,v]));
   for(const link of links){const id=link.tenantId??'',scope=scopes.get(id),context=contexts.get(id);if(!scope||!context)continue;const resource=resources.get(link.resourceId),versionId=link.versionPolicy==='latest'?resource?.currentVersionId:link.versionPolicy,version=versionId?versions.get(versionId):undefined;
    if(!resource||(resource.ownerType==='application'&&isWorkloadAccessName(link.accessName)&&effectiveCustody(resource)!=='workload-only')||resource.ownerType!==scope.ownerType||(scope.ownerType==='tenant'?resource.ownerId!==scope.ownerId:!activeSources.has(resource.ownerId))||!version||version.resourceId!==resource._id||version.ownerType!==resource.ownerType||version.ownerId!==resource.ownerId||version.kind!==resource.kind||!grant.capabilities.includes(resource.kind==='encryption-key'?'keys:export':'secrets:read')||context.rows.some(r=>r.accessName===link.accessName)||!/^[A-Z][A-Z0-9_]{0,127}$/.test(link.accessName)){context.ready=false;context.reason='Required static material unavailable';continue;}
    context.rows.push({resource,versionId:version._id,accessName:link.accessName});
   }
   const keyStates=await tx.db.collection<any>('vault_key_version_states').find({environment,resourceId:{$in:links.map(l=>l.resourceId)},state:{$ne:'revoked'}},opts).sort({_id:1}).limit(10001).toArray();if(keyStates.length>10000)throw Error('Bootstrap key ring exceeds limits');
   let encodedBudget=0;for(const context of contexts.values())if(context.ready){const estimate=context.rows.reduce((n,row)=>n+Number((versions.get(row.versionId) as any)?.encodedBytes??0),0);if(encodedBudget+estimate>10*1024*1024||context.rows.some(row=>keyStates.filter(s=>s.resourceId===row.resource._id).length>256)){context.ready=false;context.reason='Bootstrap view exceeds safe payload limits'}else encodedBudget+=estimate;}
   const view={applicationId,environment,grantId:grant._id,grantRevision:grant.revision,deploymentRevision:deployment.revision,keyStates:keyStates.map(s=>[s._id,s.resourceId,s.state,s.rotationId,s.keyLabel]),contexts:[...contexts].map(([id,c])=>({id,ready:c.ready,rows:c.rows.map(r=>[r.resource._id,r.resource.revision,r.versionId,r.accessName])}))};
   const etag=bootstrapDigest(view);if(etag===ifNoneMatch)return{status:304 as const,etag};
   const needed=[...new Set([...contexts.values()].filter(c=>c.ready).flatMap(c=>c.rows.flatMap(r=>[r.versionId,...keyStates.filter(s=>s.resourceId===r.resource._id).map(s=>s._id as string)])))];
   const payloads=new Map((await this.store.versions.find({_id:{$in:needed},environment},opts).toArray()).map(v=>[v._id,v]));
   const result=new Map<string,BootstrapContext>();let payloadFailed=false,totalBytes=0;
   for(const[id,c]of contexts){const output:BootstrapContext={ready:c.ready,...(c.reason?{reason:c.reason}:{}),values:[]};result.set(id,output);if(!c.ready)continue;let contextBytes=0;
    for(const row of c.rows)try{const value=await this.value(scopeFilter(row.resource),row,tx,keyStates.filter(s=>s.resourceId===row.resource._id),payloads),size=Buffer.byteLength(JSON.stringify(value));if(totalBytes+size>8*1024*1024)throw Error('Bootstrap payload exceeds limits');output.values.push(value);totalBytes+=size;contextBytes+=size}catch{payloadFailed=true;output.ready=false;output.reason='Required static material unavailable';output.values=[];totalBytes-=contextBytes;break;}
   }
   const effective=payloadFailed?bootstrapDigest({view,failed:true}):etag;return{status:200 as const,etag:effective,snapshot:{format:2 as const,applicationId,environment,revision:effective,application:result.get('')!,tenants:Object.fromEntries([...result].filter(([id])=>id!==''))}};
  });
 }
 private async value(scope:ResourceScope,row:{resource:ResourceRecord;versionId:string;accessName:string},tx:V2Transaction,keyStates:any[],payloads:Map<string,ResourceVersion>):Promise<BootstrapValue>{
  const version=payloads.get(row.versionId);if(!version)throw Error('Unavailable');const plain=this.store.openVersion(scope,row.resource._id,version);
  try{
   if(version.kind==='integration'){try{this.schemas.schema(version.schemaIdentity)}catch{const schema=await tx.db.collection<any>('vault_integration_schema_versions').findOne({_id:version.schemaIdentity,...scope},{session:tx.session});if(!schema||this.schemas.registerCustom(scope,schema.name,schema.version,schema.schema)!==version.schemaIdentity)throw Error('Integration schema unavailable')}}
   const keyVersions:NonNullable<BootstrapValue['keyVersions']>=[];if(version.kind==='encryption-key')for(const state of keyStates){const key=payloads.get(state._id);if(!key)throw Error('Key version unavailable');const bytes=this.store.openVersion(scope,row.resource._id,key);try{keyVersions.push({versionId:state._id,state:state.state,...(state.keyLabel?{keyLabel:state.keyLabel}:{}),value:bytes.toString('utf8'),...(state.rotationId?{rotationId:state.rotationId}:{})})}finally{bytes.fill(0)}}
   return{resourceId:row.resource._id,versionId:row.versionId,name:row.resource.name,accessName:row.accessName,kind:version.kind,valueFormat:version.valueFormat,schemaIdentity:version.schemaIdentity,...(version.kind==='integration'?{schema:this.schemas.schema(version.schemaIdentity)}:{}),...(version.kind==='encryption-key'?{keyVersions:keyVersions.length?keyVersions:[{versionId:row.versionId,state:'active-for-encryption',value:plain.toString('utf8')}]}:{}),value:version.kind==='integration'?this.schemas.validate(version.schemaIdentity,JSON.parse(plain.toString('utf8'))):plain.toString('utf8')};
  }finally{plain.fill(0)}
 }
}
