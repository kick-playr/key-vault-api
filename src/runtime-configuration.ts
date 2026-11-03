import {runtimeReferences,inheritedConfiguration,inheritedTenant,inheritedApplications,type RuntimeReferenceRecord} from './runtime-inheritance.js';
import {createHash} from 'node:crypto';
import {applicationDescriptor} from './application-runtime.js';
import type{MongoStore}from'./store.js';
import type{Namespace,Scope}from'./types.js';
import type{RuntimeManifest,RuntimeSnapshotRequest}from'@kick-playr/local-key-vault/runtime-client';
import{applicationName}from'./applications.js';
import{object,envName,identifier,scopePart}from'./validation.js';
import{requireCondition as check,fail}from'./errors.js';
import{parsePlan,createBindings}from'./runtime-manifest-plan.js';
import{publishManifests}from'./runtime-manifests.js';
import{vaultName}from'./manifest.js';
import{tenantKeySet}from'./tenant-key-tree.js';
import{active,changed}from'./vault.js';
export interface SecretSelection{purpose:string;mapping:string;version?:string;displayName?:string}
export interface KeyPlan{reference:string;currentWrappingVersion:string;wrappingVersions:{keyVersion:string;vaultVersion?:string}[];mappings?:{wrapping:string;index:string;control:string};indexVersion?:string;controlVersion?:string}
export interface TenantSelection{tenant:string;applications:string[];secrets:SecretSelection[];keySets:KeyPlan[]}
export interface RuntimeConfigurationDocument{kind:'runtime-configuration';schemaVersion:1;id:string;applications:Record<string,{displayName:string;description:string;secrets:SecretSelection[]}>;tenants:TenantSelection[]}
export interface RuntimeConfigurationRecord{revision:number;publicationId?:string;configuration:RuntimeConfigurationDocument}
const labels:Record<string,string>={'club-api':'Club API',app:'Club APP',explorer:'Explorer APP','explorer-api':'Explorer API'};
const text=(v:unknown,max:number)=>{check(typeof v==='string'&&v.length<=max&&!/[\u0000-\u001f\u007f]/.test(v));return v;};
function pin(v:unknown){check(v===undefined||v==='latest'||typeof v==='string'&&/^[a-f0-9]{32}$/.test(v));return v as string|undefined;}
function secrets(input:unknown):SecretSelection[]{check(Array.isArray(input)&&input.length<=100);const rows=input.map(raw=>{const s=object(raw,['purpose','mapping','version','displayName']);return{purpose:identifier(s.purpose),mapping:envName(s.mapping),...(s.displayName===undefined?{}:{displayName:text(s.displayName,160)}),...(s.version===undefined?{}:{version:pin(s.version)})};});check(new Set(rows.map(s=>s.mapping)).size===rows.length&&new Set(rows.map(s=>s.purpose)).size===rows.length);return rows;}
function keys(input:unknown,scope:Scope):KeyPlan[]{check(Array.isArray(input)&&input.length<=100);return input.map(raw=>{const k=object(raw,['reference','currentWrappingVersion','wrappingVersions','mappings','indexVersion','controlVersion']);tenantKeySet(scope,k.reference as string);const label=(v:unknown)=>{check(typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(v)&&v!=='latest');return v;};check(Array.isArray(k.wrappingVersions)&&k.wrappingVersions.length>0&&k.wrappingVersions.length<=100);const wrappingVersions=k.wrappingVersions.map(raw=>{const v=object(raw,['keyVersion','vaultVersion']);return{keyVersion:label(v.keyVersion),...(v.vaultVersion===undefined?{}:{vaultVersion:pin(v.vaultVersion)})};});check(new Set(wrappingVersions.map(v=>v.keyVersion)).size===wrappingVersions.length);const currentWrappingVersion=label(k.currentWrappingVersion);check(wrappingVersions.some(v=>v.keyVersion===currentWrappingVersion));const mappings=k.mappings===undefined?undefined:object(k.mappings,['wrapping','index','control']);return{reference:k.reference as string,currentWrappingVersion,wrappingVersions,...(mappings?{mappings:{wrapping:envName(mappings.wrapping),index:envName(mappings.index),control:envName(mappings.control)}}:{}),...(k.indexVersion===undefined?{}:{indexVersion:pin(k.indexVersion)}),...(k.controlVersion===undefined?{}:{controlVersion:pin(k.controlVersion)})};});}
export function parseRuntimeConfiguration(input:unknown):RuntimeConfigurationDocument{
 const b=object(input,['kind','schemaVersion','id','applications','tenants']);check(b.kind==='runtime-configuration'&&b.schemaVersion===1&&['development','dev','test'].includes(b.id as string));const id=b.id as string;
 check(b.applications&&typeof b.applications==='object'&&!Array.isArray(b.applications));const entries=Object.entries(b.applications as Record<string,unknown>);check(entries.length>0&&entries.length<=16);
 const applications=Object.fromEntries(entries.map(([name,raw])=>{applicationName(name);const a=object(raw,['displayName','description','secrets']);const displayName=text(a.displayName,128).trim();check(displayName.length>0);return[name,{displayName,description:text(a.description??'',512),secrets:secrets(a.secrets)}];}));
 check(Array.isArray(b.tenants)&&b.tenants.length<=32);const tenants=b.tenants.map(raw=>{const t=object(raw,['tenant','applications','secrets','keySets']);const tenant=scopePart(t.tenant);check(tenant!=='_shared');check(Array.isArray(t.applications)&&t.applications.length>0&&t.applications.every(a=>typeof a==='string'&&Object.hasOwn(applications,a)));check(new Set(t.applications).size===t.applications.length);return{tenant,applications:t.applications as string[],secrets:secrets(t.secrets),keySets:keys(t.keySets,{environment:id,tenant})};});check(new Set(tenants.map(t=>t.tenant)).size===tenants.length);
 return{kind:'runtime-configuration',schemaVersion:1,id,applications,tenants};
}
export function importRuntimeConfiguration(input:unknown):RuntimeConfigurationDocument{
 if(input&&typeof input==='object'&&(input as {kind?:unknown}).kind==='runtime-configuration')return parseRuntimeConfiguration(input);
 const p=parsePlan(input);return parseRuntimeConfiguration({kind:'runtime-configuration',schemaVersion:1,id:p.environment,applications:Object.fromEntries(Object.entries(p.applications).map(([name,a])=>[name,{displayName:labels[name]??name,description:'',secrets:a.secrets}])),tenants:p.tenants.map(t=>({tenant:t.tenant,applications:Object.keys(p.applications),secrets:t.secrets,keySets:t.keySets}))});
}
export function parseTenantTokens(header:unknown):Record<string,string>{if(header===undefined)return{};check(typeof header==='string'&&Buffer.byteLength(header)<=12288);let raw:unknown;try{raw=JSON.parse(header);}catch{fail(400,'BadParameter');}check(raw&&typeof raw==='object'&&!Array.isArray(raw)&&Object.keys(raw).length<=32);return Object.fromEntries(Object.entries(raw as Record<string,unknown>).map(([tenant,token])=>{check(scopePart(tenant)!=='_shared'&&typeof token==='string'&&/^[\x21-\x7e]{32,4096}$/.test(token));return[tenant,token as string];}));}
type Authorize=(scope:Scope)=>Promise<void>;
export class RuntimeConfigurationService{
 constructor(private readonly store:Pick<MongoStore,'read'|'transaction'>){}
 private root(scope:Scope){check(scope.tenant==='_shared'&&['development','dev','test'].includes(scope.environment));}
 async get(scope:Scope):Promise<RuntimeConfigurationRecord & {availableApplications:RuntimeConfigurationDocument['applications']}>{this.root(scope);return this.store.read(scope,ns=>{
  if(!ns)fail(404,'RuntimeNamespaceNotFound');
  const saved=ns.runtimeConfiguration;const tenants=new Map<string,Set<string>>();for(const[name,r]of Object.entries(ns.runtimeManifests??{}))for(const t of r.versions[String(r.currentRevision)]?.tenants??[]){const names=tenants.get(t.tenant)??new Set<string>();names.add(name);tenants.set(t.tenant,names);}
  const refs=saved?runtimeReferences(saved.configuration):runtimeReferences({kind:'runtime-configuration',schemaVersion:2,id:scope.environment,applications:Object.keys(ns.applications??{}),tenants:[...tenants].map(([tenant,apps])=>({tenant,applications:[...apps]}))});
  return{revision:saved?.revision??0,...(saved?.publicationId?{publicationId:saved.publicationId}:{}),configuration:inheritedConfiguration(scope,refs,ns),availableApplications:inheritedApplications(scope,ns,Object.keys(ns.applications??{}))};
 });}
 async tenant(scope:Scope){check(scope.tenant!=='_shared');return this.store.read(scope,ns=>{if(!ns)fail(404,'RuntimeNamespaceNotFound');return inheritedTenant(scope,ns);});}
 async import(scope:Scope,input:unknown,authorize:Authorize){this.root(scope);const refs=runtimeReferences(input);check(refs.id===scope.environment);await authorize(scope);const root=await this.store.read(scope,n=>n);if(!root)fail(404,'RuntimeNamespaceNotFound');const tenants=new Map<string,Namespace>();for(const t of refs.tenants){try{await authorize({...scope,tenant:t.tenant});}catch{continue;}const ns=await this.store.read({...scope,tenant:t.tenant},n=>n);if(ns)tenants.set(t.tenant,ns);}return{configuration:inheritedConfiguration(scope,refs,root,tenants)};}
 async save(scope:Scope,input:unknown,authorize:Authorize):Promise<RuntimeConfigurationRecord>{
  this.root(scope);const body=object(input,['expectedRevision','configuration','expectedGenerations']);check(Number.isSafeInteger(body.expectedRevision)&&(body.expectedRevision as number)>=0);const refs=runtimeReferences(body.configuration);check(refs.id===scope.environment);
  const current=await this.get(scope);if(current.revision!==body.expectedRevision)fail(409,'RuntimeConfigurationConflict');
  const snapshots=new Map<string,Namespace>();for(const tenant of ['_shared',...refs.tenants.map(t=>t.tenant)]){const s={...scope,tenant};await authorize(s);const ns=await this.store.read(s,n=>n);if(!ns)fail(404,'RuntimeNamespaceNotFound');snapshots.set(tenant,ns);}
  const configuration=inheritedConfiguration(scope,refs,snapshots.get('_shared')!,snapshots);
  const expected=body.expectedGenerations===undefined?{}:object(body.expectedGenerations,['_shared',...configuration.tenants.map(t=>t.tenant)]);for(const[tenant,generation]of Object.entries(expected))if(snapshots.get(tenant)?.generation!==generation)fail(409,'RuntimeConfigurationConflict');
  const select=(tenant:string,name:string,version:string|undefined)=>{const versions=snapshots.get(tenant)!.secrets[name];const item=version==='latest'?versions?.at(-1):version?versions?.find(v=>v.version===version):versions?.length===1?versions[0]:undefined;if(!item)fail(409,'MissingOrAmbiguousRuntimeVersion');active(item);return item;};
  const resolvedSecret=(tenant:string,s:SecretSelection)=>{const item=select(tenant,vaultName({...scope,tenant},'secret',s.purpose),s.version);if(item.tags?.purpose!==undefined&&item.tags.purpose!==s.purpose||item.tags?.envName!==undefined&&item.tags.envName!==s.mapping)fail(409,'CanonicalMappingConflict');if(s.version===undefined)s.version=item.version;return{purpose:s.purpose,mapping:s.mapping,version:item.version};};
  const resolvedTenants=configuration.tenants.map(t=>({tenant:t.tenant,bindingRevision:1,secrets:t.secrets.map(s=>resolvedSecret(t.tenant,s)),keySets:t.keySets.map(k=>{const layout=tenantKeySet({...scope,tenant:t.tenant},k.reference);const role=(r:string)=>layout.entries.find(e=>e.role===r)!.name;return{...k,wrappingVersions:k.wrappingVersions.map(v=>({...v,vaultVersion:select(t.tenant,role('wrapping'),v.vaultVersion).version})),indexVersion:select(t.tenant,role('index'),k.indexVersion).version,controlVersion:select(t.tenant,role('control'),k.controlVersion).version};})}));
  const bindings=await createBindings({schemaVersion:1,environment:scope.environment,applications:Object.fromEntries(Object.entries(configuration.applications).map(([name,a])=>[name,{bindingRevision:1,secrets:a.secrets.map(s=>resolvedSecret('_shared',s))}])),tenants:resolvedTenants},{read:async(s,fn)=>fn(snapshots.get(s.tenant))});
  for(const tenant of configuration.tenants)for(const key of tenant.keySets){const actual=bindings.tenants.find(t=>t.scope.tenant===tenant.tenant)!.request.keySets.find(k=>k.reference===key.reference)!;key.mappings??=actual.mappings;key.indexVersion??=actual.indexVersion;key.controlVersion??=actual.controlVersion;for(const version of key.wrappingVersions)version.vaultVersion??=actual.wrappingVersions.find(v=>v.keyVersion===version.keyVersion)!.vaultVersion;}
  const tenantManifests=new Map<string,RuntimeManifest[]>();const sharedManifests:RuntimeManifest[]=[];
  for(const[name,binding]of Object.entries(bindings.applications)){
   const rootNS=snapshots.get('_shared')!;const rootRevision=(rootNS.runtimeManifests?.[name]?.currentRevision??0)+1;const request={...binding.request,bindingRevision:rootRevision};const {bindingDigest}=await import('@kick-playr/local-key-vault/runtime-client');request.bindingDigest=bindingDigest(request);
   const refs=[];for(const entry of configuration.tenants.filter(t=>t.applications.includes(name))){const target=bindings.tenants.find(t=>t.scope.tenant===entry.tenant)!;const revision=(snapshots.get(entry.tenant)!.runtimeManifests?.[name]?.currentRevision??0)+1;const req={...target.request,bindingRevision:revision};req.bindingDigest=bindingDigest(req);const manifest:RuntimeManifest={schemaVersion:1,application:name,scope:target.scope,request:req,tenants:[]};tenantManifests.set(entry.tenant,[...(tenantManifests.get(entry.tenant)??[]),manifest]);refs.push({tenant:entry.tenant,bindingRevision:revision,bindingDigest:req.bindingDigest});}
   sharedManifests.push({schemaVersion:1,application:name,scope,request,tenants:refs});
  }
  for(const name of refs.applications)applicationDescriptor(scope,name,snapshots.get('_shared')!);
  // A configuration editor cannot use startup publication to bypass encryption migration.
  for(const manifest of [...sharedManifests,...[...tenantManifests.values()].flat()]){
   const ns=snapshots.get(manifest.scope.tenant)!;const old=ns.runtimeManifests?.[manifest.application];const prior=old?.versions[String(old.currentRevision)]?.request;
   if(prior){for(const oldSet of prior.keySets){const target=manifest.request.keySets.find(k=>k.reference===oldSet.reference);if(!target||oldSet.wrappingVersions.some(old=>!target.wrappingVersions.some(v=>v.keyVersion===old.keyVersion&&v.vaultVersion===old.vaultVersion)))fail(409,'EncryptionMigrationRequired');}const crypto=(r:RuntimeSnapshotRequest)=>[...r.keySets.flatMap(k=>[{name:tenantKeySet(manifest.scope,k.reference).entries[0]!.name,version:k.wrappingVersions.find(v=>v.keyVersion===k.currentWrappingVersion)!.vaultVersion},{name:tenantKeySet(manifest.scope,k.reference).entries[1]!.name,version:k.indexVersion},{name:tenantKeySet(manifest.scope,k.reference).entries[2]!.name,version:k.controlVersion}]),...r.secrets.filter(s=>/(?:ENCRYPTION_KEY|CREDENTIAL_KEY|WRAPPING_KEY_V\d+|INDEX_KEY|CONTROL_KEY|INVITATION_FLOW_KEY)$/.test(s.mapping)).map(s=>({name:vaultName(manifest.scope,'secret',s.purpose),version:s.version}))];const before=crypto(prior);for(const oldKey of before){const next=crypto(manifest.request).find(k=>k.name===oldKey.name&&k.version===oldKey.version)??crypto(manifest.request).find(k=>k.name===oldKey.name);if(!next||select(manifest.scope.tenant,next.name,next.version).value!==select(manifest.scope.tenant,oldKey.name,oldKey.version).value)fail(409,'EncryptionMigrationRequired');}}
  }
  const publicationId=createHash('sha256').update(JSON.stringify([body.expectedRevision,configuration],(_key,value)=>value&&typeof value==='object'&&!Array.isArray(value)?Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))):value)).digest('hex');
  const held:string[]=[];
  try{
  for(const[tenant,manifests]of tenantManifests){await this.store.transaction({...scope,tenant},ns=>{if(ns.generation!==snapshots.get(tenant)!.generation)fail(409,'RuntimeConfigurationConflict');if(Object.keys(ns.runtimeLinkPublications??{}).length>=32)fail(409,'RuntimePublicationLimit');ns.runtimePublicationReservation=publicationId;(ns.runtimeLinkPublications??={})[publicationId]={baseGeneration:ns.generation,applicationRevision:ns.applicationRevision??0,effectiveManifests:Object.fromEntries(manifests.map(m=>[m.application,{revision:m.request.bindingRevision,digest:m.request.bindingDigest,policies:Object.fromEntries(configuration.tenants.find(t=>t.tenant===tenant)!.secrets.map(s=>[vaultName({...scope,tenant},'secret',s.purpose),s.version!]))}]))};publishManifests(ns,{...scope,tenant},manifests);},{runtimePublicationId:publicationId});held.push(tenant);}
  const saved=await this.store.transaction(scope,ns=>{if((ns.runtimeConfiguration?.revision??0)!==body.expectedRevision||ns.generation!==snapshots.get('_shared')!.generation)fail(409,'RuntimeConfigurationConflict');
   ns.runtimeTenantPublications??={};for(const tenant of tenantManifests.keys())ns.runtimeTenantPublications[tenant]=publicationId;
   publishManifests(ns,scope,sharedManifests);const record:RuntimeReferenceRecord={revision:(body.expectedRevision as number)+1,publicationId,configuration:refs};ns.runtimeConfiguration=record;changed(ns,'runtime.configuration.save',configuration.id);return{...record,configuration};
  });

  return saved;
  }catch(error){
   // Unknown write outcomes retain holds; retrying the same reviewed configuration resumes them.
   if(!(error&&typeof error==='object'&&'code' in error&&error.code==='StoreUnavailable')){
    const committed=await this.store.read(scope,ns=>({current:ns?.runtimeConfiguration?.publicationId,tenants:ns?.runtimeTenantPublications??{}}));
    for(const tenant of held)if((committed.tenants[tenant]??committed.current)!==publicationId)await this.store.transaction({...scope,tenant},ns=>{if(ns.runtimePublicationReservation===publicationId){delete ns.runtimePublicationReservation;delete ns.runtimeLinkPublications?.[publicationId];}},{runtimePublicationId:publicationId});
   }
   throw error;
  }
 }
}
