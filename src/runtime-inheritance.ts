import type {Namespace,Scope} from './types.js';
import type {RuntimeConfigurationDocument,SecretSelection,KeyPlan} from './runtime-configuration.js';
import {importRuntimeConfiguration} from './runtime-configuration.js';
import {object,scopePart,identifier,envName} from './validation.js';
import {applicationName} from './applications.js';
import {vaultName} from './manifest.js';
import {tenantKeySet} from './tenant-key-tree.js';
import {fail,requireCondition as check} from './errors.js';

/** The editable runtime model contains references, never copies of binding definitions. */
export interface RuntimeReferences {
 kind:'runtime-configuration'; schemaVersion:2; id:string;
 applications:string[]; tenants:{tenant:string;applications:string[]}[];
}
export interface RuntimeReferenceRecord {revision:number;publicationId?:string;configuration:RuntimeReferences}
export function runtimeReferences(input:unknown):RuntimeReferences {
 if(input&&typeof input==='object'&&(input as {schemaVersion?:unknown}).schemaVersion===2){
  const b=object(input,['kind','schemaVersion','id','applications','tenants']);check(b.kind==='runtime-configuration'&&['development','dev','test'].includes(b.id as string));
  check(Array.isArray(b.applications)&&b.applications.length>0&&b.applications.length<=16);const applications=b.applications.map(applicationName);check(new Set(applications).size===applications.length);
  check(Array.isArray(b.tenants)&&b.tenants.length<=32);const tenants=b.tenants.map(raw=>{const t=object(raw,['tenant','applications']);const tenant=scopePart(t.tenant);check(tenant!=='_shared'&&Array.isArray(t.applications)&&t.applications.length>0&&t.applications.length<=16);const names=t.applications.map(applicationName);check(!names.includes('vault-app'));check(new Set(names).size===names.length&&names.every(a=>applications.includes(a)));return{tenant,applications:names};});check(new Set(tenants.map(t=>t.tenant)).size===tenants.length);
  return{kind:'runtime-configuration',schemaVersion:2,id:b.id as string,applications,tenants};
 }
 const legacy=importRuntimeConfiguration(input);return runtimeReferences({kind:legacy.kind,schemaVersion:2,id:legacy.id,applications:Object.keys(legacy.applications),tenants:legacy.tenants.map(t=>({tenant:t.tenant,applications:t.applications}))});
}
function credentialName(ns:Namespace,purpose:string):{displayName?:string}{
 if(!/^runtime-credential-[a-f0-9]{24}$/.test(purpose))return{};
 const record=Object.values(ns.oauthCredentials??{}).find(r=>r.purpose===purpose);
 return{displayName:record?.provider==='bexio'?'Bexio OAuth credentials':record?.provider==='dropbox'?'Dropbox OAuth credentials':'Integration credentials'};
}
function policy(ns:Namespace,name:string,applications?:string[]){
 const association=ns.resourceAssociations?.['secrets/'+name];const policies=Object.entries(association?.memberships??{}).filter(([app])=>!applications||applications.includes(app)).map(([,p])=>p);
 if(new Set(policies).size>1)fail(409,'ConflictingTenantBindingPolicies');return{mapping:association?.envName,version:policies[0]};
}
export function inheritedApplications(scope:Scope,ns:Namespace,names:string[]):RuntimeConfigurationDocument['applications'] {
 return Object.fromEntries(names.map(name=>{
  const app=ns.applications?.[name];if(!app||ns.deletedApplications?.includes(name))fail(409,'RuntimeApplicationNotFound');
  const secrets:SecretSelection[]=Object.entries(ns.resourceAssociations??{}).flatMap(([ref,a])=>{
   const version=a.memberships[name];if(!version||!ref.startsWith('secrets/'))return[];const resource=ref.slice(8),versions=ns.secrets[resource];const selected=version==='latest'?versions?.at(-1):versions?.find(v=>v.version===version);if(!selected)fail(409,'MissingOrAmbiguousRuntimeVersion');
   const purpose=selected.tags?.purpose;if(!purpose||vaultName(scope,'secret',purpose)!==resource)fail(409,'MissingCanonicalPurpose');return[{purpose:identifier(purpose),mapping:envName(a.envName),version,...credentialName(ns,purpose)}];
  });return[name,{displayName:app.displayName,description:app.description,secrets}];
 }));
}
/** Key labels/history come from the last validated tenant descriptor, not a runtime editor.
 * New key trees are discovered from canonical key-role tags. Crypto changes still require migration. */
export function inheritedTenant(scope:Scope,ns:Namespace,applications?:string[]){
 const requests=Object.entries(ns.runtimeManifests??{}).flatMap(([app,r])=>{const selected=ns.runtimeEffectiveManifests?.[app];const m=r.versions[String(selected?.revision??r.currentRevision)];return m?[m.request]:[];});
 const priorSecrets=new Map(requests.flatMap(r=>r.secrets).map(s=>[vaultName(scope,'secret',s.purpose),s]));
 const secrets:SecretSelection[]=Object.entries(ns.secrets).flatMap(([name,versions])=>{
  const last=versions.at(-1);if(!last||last.tags?.keySet||name.startsWith('tk-'))return[];
  const prior=priorSecrets.get(name),p=policy(ns,name,applications),purpose=last.tags?.purpose??prior?.purpose,mapping=p.mapping??last.tags?.envName??prior?.mapping;
  if(!purpose||!mapping||vaultName(scope,'secret',purpose)!==name)return[];
  return[{purpose:identifier(purpose),mapping:envName(mapping),...credentialName(ns,purpose),version:p.version??(last.tags?.envName?'latest':prior?.version)??'latest'}];
 });
 const sets=new Map<string,KeyPlan>();for(const r of requests)for(const k of r.keySets){const old=sets.get(k.reference);if(old&&JSON.stringify(old)!==JSON.stringify(k))fail(409,'ConflictingTenantKeyDefinitions');sets.set(k.reference,structuredClone(k));}
 for(const versions of Object.values(ns.secrets)){const tags=versions.at(-1)?.tags;if(!tags?.keySet||sets.has(tags.keySet))continue;const layout=tenantKeySet(scope,tags.keySet);const roles=layout.entries.map(e=>({role:e.role,versions:ns.secrets[e.name]}));if(roles.some(r=>!r.versions?.length))fail(409,'IncompleteTenantKeySet');
  const wrapping=roles.find(r=>r.role==='wrapping')!.versions!;if(wrapping.length!==1)fail(409,'MissingTenantKeyHistory');const index=roles.find(r=>r.role==='index')!.versions!.at(-1)!,control=roles.find(r=>r.role==='control')!.versions!.at(-1)!;const label=wrapping[0]!.tags?.envName?.match(/_V(\d+)$/)?.[1]??'1';
  sets.set(layout.reference,{reference:layout.reference,currentWrappingVersion:label,wrappingVersions:[{keyVersion:label,vaultVersion:wrapping[0]!.version}],mappings:{wrapping:envName(wrapping[0]!.tags?.envName),index:envName(index.tags?.envName),control:envName(control.tags?.envName)},indexVersion:index.version,controlVersion:control.version});
 }
 return{tenant:scope.tenant,secrets,keySets:[...sets.values()],generation:ns.generation};
}
export function inheritedConfiguration(scope:Scope,refs:RuntimeReferences,root:Namespace,tenants:Map<string,Namespace>=new Map()):RuntimeConfigurationDocument {
 return{kind:'runtime-configuration',schemaVersion:1,id:refs.id,applications:inheritedApplications(scope,root,refs.applications),tenants:refs.tenants.map(t=>({...t,...(tenants.has(t.tenant)?inheritedTenant({...scope,tenant:t.tenant},tenants.get(t.tenant)!,t.applications):{secrets:[],keySets:[]})}))};
}
