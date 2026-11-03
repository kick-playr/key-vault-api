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
export interface SecretSelection{purpose:string;mapping:string;version?:string}
export interface KeyPlan{reference:string;currentWrappingVersion:string;wrappingVersions:{keyVersion:string;vaultVersion?:string}[];mappings?:{wrapping:string;index:string;control:string};indexVersion?:string;controlVersion?:string}
export interface TenantSelection{tenant:string;applications:string[];secrets:SecretSelection[];keySets:KeyPlan[]}
export interface RuntimeConfigurationDocument{kind:'runtime-configuration';schemaVersion:1;id:string;applications:Record<string,{displayName:string;description:string;secrets:SecretSelection[]}>;tenants:TenantSelection[]}
export interface RuntimeConfigurationRecord{revision:number;publicationId?:string;configuration:RuntimeConfigurationDocument}
const labels:Record<string,string>={'club-api':'Club API',app:'Club APP',explorer:'Explorer APP','explorer-api':'Explorer API'};
const text=(v:unknown,max:number)=>{check(typeof v==='string'&&v.length<=max&&!/[\u0000-\u001f\u007f]/.test(v));return v;};
function pin(v:unknown){check(v===undefined||v==='latest'||typeof v==='string'&&/^[a-f0-9]{32}$/.test(v));return v as string|undefined;}
function secrets(input:unknown):SecretSelection[]{check(Array.isArray(input)&&input.length<=100);const rows=input.map(raw=>{const s=object(raw,['purpose','mapping','version']);return{purpose:identifier(s.purpose),mapping:envName(s.mapping),...(s.version===undefined?{}:{version:pin(s.version)})};});check(new Set(rows.map(s=>s.mapping)).size===rows.length&&new Set(rows.map(s=>s.purpose)).size===rows.length);return rows;}
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
function requestSelections(request:RuntimeSnapshotRequest|undefined){return{secrets:request?.secrets.map(s=>({...s}))??[],keySets:request?.keySets.map(k=>structuredClone(k))??[]};}
export class RuntimeConfigurationService{
 constructor(private readonly store:Pick<MongoStore,'read'|'transaction'>){}
 private root(scope:Scope){check(scope.tenant==='_shared'&&['development','dev','test'].includes(scope.environment));}
 async get(scope:Scope):Promise<RuntimeConfigurationRecord>{this.root(scope);return this.store.read(scope,ns=>{
  if(ns?.runtimeConfiguration)return ns.runtimeConfiguration;
  const applications:RuntimeConfigurationDocument['applications']={};const tenants=new Map<string,Set<string>>();
  for(const name of new Set([...Object.keys(ns?.applications??{}),...Object.keys(ns?.runtimeManifests??{})])){
   const manifest=ns?.runtimeManifests?.[name];const current=manifest?.versions[String(manifest.currentRevision)];const app=ns?.applications?.[name];
   const selections=Object.entries(ns?.resourceAssociations??{}).flatMap(([ref,a])=>{if(!Object.hasOwn(a.memberships,name)||!ref.startsWith('secrets/'))return[];const versions=ns?.secrets[ref.slice(8)];const item=versions?.find(v=>v.version===a.memberships[name])??versions?.at(-1);if(!item?.tags?.purpose)return[];return[{purpose:item.tags.purpose,mapping:a.envName,version:a.memberships[name]}];});
   applications[name]={displayName:labels[name]??app?.displayName??name,description:app?.description??'',secrets:selections.length?selections:requestSelections(current?.request).secrets};
   for(const t of current?.tenants??[]){const set=tenants.get(t.tenant)??new Set();set.add(name);tenants.set(t.tenant,set);}
  }
  return{revision:0,configuration:{kind:'runtime-configuration',schemaVersion:1,id:scope.environment,applications,tenants:[...tenants].map(([tenant,names])=>({tenant,applications:[...names],secrets:[],keySets:[]}))}};
 });}
 async tenant(scope:Scope){check(scope.tenant!=='_shared');return this.store.read(scope,ns=>{
  const requests=Object.values(ns?.runtimeManifests??{}).map(r=>r.versions[String(r.currentRevision)]!.request);const first=requests[0];
  if(first)return{tenant:scope.tenant,...requestSelections(first),generation:ns?.generation??0};
  const found=(Object.values(ns?.secrets??{}).map(v=>v.at(-1)).filter(v=>v?.tags?.purpose&&!v.tags.keySet));
  return{tenant:scope.tenant,secrets:found.map(v=>({purpose:v!.tags!.purpose!,mapping:v!.tags!.envName??'',version:v!.version})),keySets:[],generation:ns?.generation??0};
 });}
 async import(scope:Scope,input:unknown,authorize:Authorize){
  this.root(scope);const configuration=importRuntimeConfiguration(input);check(configuration.id===scope.environment);
  for(const tenant of ['_shared',...configuration.tenants.map(t=>t.tenant)]){
   try{await authorize({...scope,tenant});}catch(error){if(tenant==='_shared')throw error;continue;}
   const ns=await this.store.read({...scope,tenant},n=>n);const list=tenant==='_shared'?Object.values(configuration.applications).flatMap(a=>a.secrets):configuration.tenants.find(t=>t.tenant===tenant)!.secrets;
   for(const selection of list)if(selection.version===undefined){const versions=ns?.secrets[vaultName({...scope,tenant},'secret',selection.purpose)];if(versions?.length===1)selection.version=versions[0]!.version;else fail(409,'MissingOrAmbiguousRuntimeVersion');}
  }
  return{configuration};
 }
 async save(scope:Scope,input:unknown,authorize:Authorize):Promise<RuntimeConfigurationRecord>{
  this.root(scope);const body=object(input,['expectedRevision','configuration','expectedGenerations']);check(Number.isSafeInteger(body.expectedRevision)&&(body.expectedRevision as number)>=0);const configuration=parseRuntimeConfiguration(body.configuration);check(configuration.id===scope.environment);
  const current=await this.get(scope);if(current.revision!==body.expectedRevision)fail(409,'RuntimeConfigurationConflict');
  const snapshots=new Map<string,Namespace>();for(const tenant of ['_shared',...configuration.tenants.map(t=>t.tenant)]){const s={...scope,tenant};await authorize(s);const ns=await this.store.read(s,n=>n);if(!ns)fail(404,'RuntimeNamespaceNotFound');snapshots.set(tenant,ns);}
  const expected=body.expectedGenerations===undefined?{}:object(body.expectedGenerations,['_shared',...configuration.tenants.map(t=>t.tenant)]);for(const[tenant,generation]of Object.entries(expected))if(snapshots.get(tenant)?.generation!==generation)fail(409,'RuntimeConfigurationConflict');
  const select=(tenant:string,name:string,version:string|undefined)=>{const versions=snapshots.get(tenant)!.secrets[name];const item=version==='latest'?versions?.at(-1):version?versions?.find(v=>v.version===version):versions?.length===1?versions[0]:undefined;if(!item)fail(409,'MissingOrAmbiguousRuntimeVersion');active(item);return item;};
  const resolvedSecret=(tenant:string,s:SecretSelection)=>{const item=select(tenant,vaultName({...scope,tenant},'secret',s.purpose),s.version);if(item.tags?.purpose!==undefined&&item.tags.purpose!==s.purpose||item.tags?.envName!==undefined&&item.tags.envName!==s.mapping)fail(409,'CanonicalMappingConflict');if(s.version===undefined)s.version=item.version;return{...s,version:item.version};};
  const resolvedTenants=configuration.tenants.map(t=>({tenant:t.tenant,bindingRevision:1,secrets:t.secrets.map(s=>resolvedSecret(t.tenant,s)),keySets:t.keySets.map(k=>{const layout=tenantKeySet({...scope,tenant:t.tenant},k.reference);const role=(r:string)=>layout.entries.find(e=>e.role===r)!.name;return{...k,wrappingVersions:k.wrappingVersions.map(v=>({...v,vaultVersion:select(t.tenant,role('wrapping'),v.vaultVersion).version})),indexVersion:select(t.tenant,role('index'),k.indexVersion).version,controlVersion:select(t.tenant,role('control'),k.controlVersion).version};})}));
  const bindings=await createBindings({schemaVersion:1,environment:scope.environment,applications:Object.fromEntries(Object.entries(configuration.applications).map(([name,a])=>[name,{bindingRevision:1,secrets:a.secrets.map(s=>resolvedSecret('_shared',s))}])),tenants:resolvedTenants},{read:async(s,fn)=>fn(snapshots.get(s.tenant))});
  for(const tenant of configuration.tenants)for(const key of tenant.keySets){const actual=bindings.tenants.find(t=>t.scope.tenant===tenant.tenant)!.request.keySets.find(k=>k.reference===key.reference)!;key.mappings??=actual.mappings;key.indexVersion??=actual.indexVersion;key.controlVersion??=actual.controlVersion;for(const version of key.wrappingVersions)version.vaultVersion??=actual.wrappingVersions.find(v=>v.keyVersion===version.keyVersion)!.vaultVersion;}
  const tenantManifests=new Map<string,RuntimeManifest[]>();const sharedManifests:RuntimeManifest[]=[];
  for(const[name,binding]of Object.entries(bindings.applications)){
   const rootNS=snapshots.get('_shared')!;const rootRevision=(rootNS.runtimeManifests?.[name]?.currentRevision??0)+1;const request={...binding.request,bindingRevision:rootRevision};const {bindingDigest}=await import('@kick-playr/local-key-vault/runtime-client');request.bindingDigest=bindingDigest(request);
   const refs=[];for(const entry of configuration.tenants.filter(t=>t.applications.includes(name))){const target=bindings.tenants.find(t=>t.scope.tenant===entry.tenant)!;const revision=(snapshots.get(entry.tenant)!.runtimeManifests?.[name]?.currentRevision??0)+1;const req={...target.request,bindingRevision:revision};req.bindingDigest=bindingDigest(req);const manifest:RuntimeManifest={schemaVersion:1,application:name,scope:target.scope,request:req,tenants:[]};tenantManifests.set(entry.tenant,[...(tenantManifests.get(entry.tenant)??[]),manifest]);refs.push({tenant:entry.tenant,bindingRevision:revision,bindingDigest:req.bindingDigest});}
   sharedManifests.push({schemaVersion:1,application:name,scope,request,tenants:refs});
  }
  const applyCatalog=(ns:Namespace)=>{
   ns.applications??={};ns.resourceAssociations??={};for(const[name,a]of Object.entries(configuration.applications)){if(ns.deletedApplications)ns.deletedApplications=ns.deletedApplications.filter(n=>n!==name);ns.applications[name]={...ns.applications[name],displayName:a.displayName,description:a.description};for(const association of Object.values(ns.resourceAssociations))delete association.memberships[name];for(const s of a.secrets){const ref='secrets/'+vaultName(scope,'secret',s.purpose),association=ns.resourceAssociations[ref];if(association&&association.envName!==s.mapping)fail(409,'CanonicalMappingConflict');(ns.resourceAssociations[ref]??={envName:s.mapping,memberships:{}}).memberships[name]=s.version!;}}
  };
  const staged=structuredClone(snapshots.get('_shared')!);applyCatalog(staged);for(const name of Object.keys(configuration.applications))applicationDescriptor(scope,name,staged);
  // A configuration editor cannot use startup publication to bypass encryption migration.
  for(const manifest of [...sharedManifests,...[...tenantManifests.values()].flat()]){
   const ns=snapshots.get(manifest.scope.tenant)!;const old=ns.runtimeManifests?.[manifest.application];const prior=old?.versions[String(old.currentRevision)]?.request;
   if(prior){for(const oldSet of prior.keySets){const target=manifest.request.keySets.find(k=>k.reference===oldSet.reference);if(!target||oldSet.wrappingVersions.some(old=>!target.wrappingVersions.some(v=>v.keyVersion===old.keyVersion&&v.vaultVersion===old.vaultVersion)))fail(409,'EncryptionMigrationRequired');}const crypto=(r:RuntimeSnapshotRequest)=>[...r.keySets.flatMap(k=>[{name:tenantKeySet(manifest.scope,k.reference).entries[0]!.name,version:k.wrappingVersions.find(v=>v.keyVersion===k.currentWrappingVersion)!.vaultVersion},{name:tenantKeySet(manifest.scope,k.reference).entries[1]!.name,version:k.indexVersion},{name:tenantKeySet(manifest.scope,k.reference).entries[2]!.name,version:k.controlVersion}]),...r.secrets.filter(s=>/(?:ENCRYPTION_KEY|CREDENTIAL_KEY|WRAPPING_KEY_V\d+|INDEX_KEY|CONTROL_KEY|INVITATION_FLOW_KEY)$/.test(s.mapping)).map(s=>({name:vaultName(manifest.scope,'secret',s.purpose),version:s.version}))];const before=crypto(prior);for(const oldKey of before){const next=crypto(manifest.request).find(k=>k.name===oldKey.name&&k.version===oldKey.version)??crypto(manifest.request).find(k=>k.name===oldKey.name);if(!next||select(manifest.scope.tenant,next.name,next.version).value!==select(manifest.scope.tenant,oldKey.name,oldKey.version).value)fail(409,'EncryptionMigrationRequired');}}
  }
  const applyTenantLinks=(ns:Namespace,manifests:RuntimeManifest[])=>{
   ns.resourceAssociations??={};for(const manifest of manifests){const name=manifest.application;for(const a of Object.values(ns.resourceAssociations))delete a.memberships[name];
    const link=(resource:string,mapping:string,version:string)=>{const ref='secrets/'+resource;const a=ns.resourceAssociations![ref];if(a&&a.envName!==mapping)fail(409,'CanonicalMappingConflict');(ns.resourceAssociations![ref]??={envName:mapping,memberships:{}}).memberships[name]=version;};
    for(const secret of manifest.request.secrets)link(vaultName(manifest.scope,'secret',secret.purpose),secret.mapping,secret.version);
    for(const k of manifest.request.keySets){const layout=tenantKeySet(manifest.scope,k.reference);link(layout.entries[0]!.name,k.mappings.wrapping,k.wrappingVersions.find(v=>v.keyVersion===k.currentWrappingVersion)!.vaultVersion);link(layout.entries[1]!.name,k.mappings.index,k.indexVersion);link(layout.entries[2]!.name,k.mappings.control,k.controlVersion);}
   }
  };
  for(const[tenant,manifests]of tenantManifests)applyTenantLinks(structuredClone(snapshots.get(tenant)!),manifests);
  const publicationId=createHash('sha256').update(JSON.stringify([body.expectedRevision,configuration],(_key,value)=>value&&typeof value==='object'&&!Array.isArray(value)?Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))):value)).digest('hex');
  const held:string[]=[];
  try{
  for(const[tenant,manifests]of tenantManifests){await this.store.transaction({...scope,tenant},ns=>{if(ns.generation!==snapshots.get(tenant)!.generation)fail(409,'RuntimeConfigurationConflict');const staged=structuredClone(ns);applyTenantLinks(staged,manifests);if(Object.keys(ns.runtimeLinkPublications??{}).length>=32)fail(409,'RuntimePublicationLimit');ns.runtimePublicationReservation=publicationId;(ns.runtimeLinkPublications??={})[publicationId]={baseGeneration:ns.generation,applicationRevision:(ns.applicationRevision??0)+1,associations:staged.resourceAssociations??{}};publishManifests(ns,{...scope,tenant},manifests);},{runtimePublicationId:publicationId});held.push(tenant);}
  const saved=await this.store.transaction(scope,ns=>{if((ns.runtimeConfiguration?.revision??0)!==body.expectedRevision||ns.generation!==snapshots.get('_shared')!.generation)fail(409,'RuntimeConfigurationConflict');
   applyCatalog(ns);
   ns.runtimeTenantPublications??={};for(const tenant of tenantManifests.keys())ns.runtimeTenantPublications[tenant]=publicationId;
   publishManifests(ns,scope,sharedManifests);ns.applicationRevision=(ns.applicationRevision??0)+1;ns.runtimeConfiguration={revision:(body.expectedRevision as number)+1,publicationId,configuration};changed(ns,'runtime.configuration.save',configuration.id);return ns.runtimeConfiguration;
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
