import {createHash} from 'node:crypto';
import type {V2MongoStore} from './mongo-store.js';
import {scopeFilter} from './mongo-store.js';
import {applicationIdentity} from './catalog.js';
import {validateLink} from './links.js';
import {effectiveCustody,isWorkloadAccessName} from './resource-custody.js';
export interface MigrationCatalog {
 environment:string;
 applications:{id:string;displayName:string;description:string}[];
 tenants:{id:string;displayName:string}[];
 assignments:{applicationId:string;tenantId:string;approvedBy:string;approvedAt:number}[];
 links:{applicationId:string;tenantId?:string;resourceId:string;accessName:string;versionPolicy:string}[];
}
const identity=(...parts:string[])=>createHash('sha256').update(JSON.stringify(parts)).digest('hex');
export function validateMigrationCatalog(plan:MigrationCatalog){
 if(!plan||!Array.isArray(plan.applications)||!Array.isArray(plan.tenants)||!Array.isArray(plan.assignments)||!Array.isArray(plan.links)||plan.applications.length>100||plan.tenants.length>1000||plan.links.length>10000)throw Error('Invalid reviewed catalogue');
 const apps=new Set(plan.applications.map(a=>applicationIdentity(a.id))),tenants=new Set(plan.tenants.map(t=>scopeFilter({environment:plan.environment,ownerType:'tenant',ownerId:t.id}).ownerId));
 if(apps.size!==plan.applications.length||tenants.size!==plan.tenants.length)throw Error('Duplicate reviewed catalogue identity');
 const assignments=new Set<string>(),links=new Set<string>(),names=new Map<string,string>();
 for(const a of plan.assignments){const key=identity(a.applicationId,a.tenantId);if(!apps.has(a.applicationId)||!tenants.has(a.tenantId)||!a.approvedBy||!Number.isSafeInteger(a.approvedAt)||a.approvedAt<=0||assignments.has(key))throw Error('Explicit machine enrollment approval required');assignments.add(key);}
 for(const l of plan.links){const key=identity(l.applicationId,l.tenantId??'',l.accessName);if(!apps.has(l.applicationId)||links.has(key)||(l.tenantId&&!assignments.has(identity(l.applicationId,l.tenantId))))throw Error('Invalid reviewed resource link');links.add(key);const name=names.get(l.resourceId);if(name&&name!==l.accessName)throw Error('Shared resource requires the same ENV name');names.set(l.resourceId,l.accessName);}
 return plan;
}
/** Trusted maintenance seeding only. No HTTP caller or supplied value payload. */
export async function stageMigrationCatalog(store:V2MongoStore,plan:MigrationCatalog){
 validateMigrationCatalog(plan);
 return store.transaction(async tx=>{
 const opts={session:tx.session};
 if(await tx.db.collection('vault_platform_settings').findOne({_id:'v2-authority',enabled:true} as any,opts))throw Error('Active catalogue requires ordinary administration');
 async function insert(name:string,row:any){const c=tx.db.collection<any>(name),old=await c.findOne({_id:row._id},opts);if(old){if(JSON.stringify(old)!==JSON.stringify(row))throw Error('Migration catalogue target conflict');}else await c.insertOne(row,opts);}
 for(const a of plan.applications){await insert('vault_applications',{_id:a.id,displayName:a.displayName,description:a.description,revision:1});await insert('vault_application_environments',{_id:identity(plan.environment,a.id),applicationId:a.id,environment:plan.environment,enabled:true,revision:1});await insert('vault_deployment_custody',{_id:identity('custody',plan.environment,a.id),applicationId:a.id,environment:plan.environment,mode:'deployment-only',deliveryId:'private-deployment-files',enabled:true,revision:1});}
 for(const t of plan.tenants){await insert('vault_tenants',{_id:t.id,displayName:t.displayName,revision:1});await insert('vault_tenant_environments',{_id:identity(plan.environment,t.id),tenantId:t.id,environment:plan.environment,enabled:true,revision:1});}
 for(const a of plan.assignments){const id=identity(plan.environment,a.applicationId,a.tenantId);await insert('vault_application_tenants',{_id:id,applicationId:a.applicationId,tenantId:a.tenantId,environment:plan.environment,enabled:true,revision:1});await insert('vault_machine_enrollments',{_id:id,applicationId:a.applicationId,tenantId:a.tenantId,environment:plan.environment,approved:true,approvedBy:a.approvedBy,approvedAt:a.approvedAt,revision:1});}
 for(const l of plan.links){const r=await store.resources.findOne({_id:l.resourceId,environment:plan.environment},opts);if(!r)throw Error('Missing staged resource');validateLink(r,l.applicationId,plan.environment,l.tenantId,!!l.tenantId,l.accessName,l.versionPolicy);if(r.ownerType==='application'&&isWorkloadAccessName(l.accessName)&&effectiveCustody(r)!=='workload-only')throw Error('Critical resource requires workload-only custody');if(l.versionPolicy!=='latest'&&!await store.versions.findOne({_id:l.versionPolicy,resourceId:r._id},opts))throw Error('Missing reviewed resource version');await insert('vault_resource_links',{_id:identity(plan.environment,l.applicationId,l.tenantId??'',l.accessName),...l,environment:plan.environment,revision:1});}
 return {applications:plan.applications.length,tenants:plan.tenants.length,assignments:plan.assignments.length,links:plan.links.length};
 });
}
