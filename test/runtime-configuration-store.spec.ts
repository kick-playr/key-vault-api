import type {Scope,Namespace} from '../src/types.js';
import{fixture}from'./helpers.js';import{MongoStore}from'../src/store.js';import{RuntimeConfigurationService}from'../src/runtime-configuration.js';import{newSecret}from'../src/vault.js';import{vaultName}from'../src/manifest.js';import{VaultError}from'../src/errors.js';
it('stages invisible tenant links, fences concurrent edits, and exposes them only after shared commit',async()=>{
 const f=await fixture(),store=await MongoStore.open(f.config),writer=await MongoStore.open(f.config);const shared={environment:'dev',tenant:'_shared'},tenant={environment:'dev',tenant:'a'};
 try{
  const process=newSecret({value:'mail'}),database=newSecret({value:'mongodb://fixture.invalid/a'});await store.transaction(shared,ns=>{ns.secrets[vaultName(shared,'secret','mail')]=[process];});await store.transaction(tenant,ns=>{ns.secrets[vaultName(tenant,'secret','db')]=[database];});
  const configuration={kind:'runtime-configuration',schemaVersion:1,id:'dev',applications:{'club-api':{displayName:'Club API',description:'',secrets:[{purpose:'mail',mapping:'MAIL_PWD',version:process.version}]}},tenants:[{tenant:'a',applications:['club-api'],secrets:[{purpose:'db',mapping:'MONGODB_URI',version:database.version}],keySets:[]}]};
  let failShared=true,observed=false;
  const facade={read:store.read.bind(store),transaction:async<T>(s:Scope,fn:(namespace:Namespace)=>T|Promise<T>,options?:{runtimePublicationId:string}):Promise<T>=>{
   if(s.tenant==='_shared'){
    expect(await writer.read(tenant,ns=>ns!.resourceAssociations)).toBeUndefined();
    await expect(writer.transaction(tenant,ns=>{ns.generation++;})).rejects.toThrow('RuntimePublicationPending');observed=true;
    if(failShared)throw new VaultError(409,'ForcedConflict');
   }
   return store.transaction(s,fn,options);
  }};
  const service=new RuntimeConfigurationService(facade);
  await expect(service.save(shared,{expectedRevision:0,configuration},async()=>{})).rejects.toThrow('ForcedConflict');
  expect(await store.read(shared,ns=>ns!.runtimeConfiguration)).toBeUndefined();expect(await writer.read(tenant,ns=>ns!.resourceAssociations)).toBeUndefined();
  // Known failed attempts release their holds without exposing staged associations.
  await writer.transaction(tenant,ns=>{ns.audit.push({time:1,action:'after-failure',name:'metadata'});});
  failShared=false;await service.save(shared,{expectedRevision:0,configuration},async()=>{});expect(observed).toBe(true);
  const ref='secrets/'+vaultName(tenant,'secret','db');expect(await writer.read(tenant,ns=>ns!.resourceAssociations?.[ref]?.memberships['club-api'])).toBe(database.version);
  await writer.transaction(tenant,ns=>{ns.generation++;});expect(await writer.read(tenant,ns=>ns!.resourceAssociations?.[ref]?.envName)).toBe('MONGODB_URI');
 }finally{await store.close();await writer.close();await f.cleanup();}
});
