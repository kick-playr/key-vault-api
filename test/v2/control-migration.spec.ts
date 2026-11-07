import { randomBytes } from 'node:crypto';
import { BSON } from 'mongodb';
import { ControlMigrationService, CONTROL_COLLECTIONS, decodeControlRuntime, encodeControlRuntime } from '../../src/v2/control-migration.js';

function fixture() {
  const indexMap = new Map<string,any[]>();
  const databases = new Map<string,Map<string,any[]>>();
  const clone = (v: any) => BSON.EJSON.parse(BSON.EJSON.stringify(v,{relaxed:false}),{relaxed:true});
  function collection(db: string, name: string) {
    if (!databases.has(db)) databases.set(db,new Map());
    const d = databases.get(db)!;
    if (!d.has(name)) d.set(name,[]);
    const rows = d.get(name)!;
    const indexKey=db+'/'+name;
    if(!indexMap.has(indexKey))indexMap.set(indexKey,[{name:'_id_',key:{_id:1}}]);
    return {
      listIndexes:()=>({toArray:async()=>indexMap.get(indexKey)!}),
      createIndexes:async(indexes:any[])=>{indexMap.get(indexKey)!.push(...indexes);},
      find: () => ({limit: () => ({toArray:async()=>clone(rows)})}),
      findOne: async (f: any) => clone(rows.find(r=>r._id===f._id) ?? null),
      insertOne: async (r:any) => {rows.push(clone(r));},
      countDocuments:async()=>rows.length,
      updateOne:async(f:any,u:any)=>{Object.assign(rows.find(r=>r._id===f._id),u.$set);},
    };
  }
  const client = {db:(db:string)=>({collection:(n:string)=>collection(db,n),listCollections:()=>({toArray:async()=>[...(databases.get(db)?.keys() ?? [])].map(name=>({name,type:'collection',options:{}}))}),createCollection:async(n:string)=>collection(db,n)}),startSession:()=>({withTransaction:async(fn:any)=>fn(),endSession:async()=>{}})};
  const options = {sourceDatabase:'source',targetDatabase:'control-kick-playr',environment:'development',wrappingKey:randomBytes(32),reviewKey:randomBytes(32),additionalAuthorizedParties:['http://localhost:4001']};
  const payload = {explorer:{issuer:'https://platform.example',adminSubjects:['user_admin'],authorizedParties:['http://localhost:3000'],clubRealms:[{issuer:'https://club.example',authorizedParties:['https://club.example'],jwtKey:'public-key'}]},other:{secret:'preserved-secret'}};
  const source = (n:string) => databases.get('source')!.get(n)!;
  const target = (n:string) => databases.get('control-kick-playr')!.get(n)!;
  for (const name of CONTROL_COLLECTIONS) collection('source',name);
  source('tenantWorkflowConfiguration').push(encodeControlRuntime(payload,options.wrappingKey,'source'));
  source('tenantDefinitions').push({_id:'tenant',id:'club',revision:4,createdAt:new Date(100),authority:{subject:'manager'}});
  source('tenantExplorerConfiguration').push({_id:'config',credentials:{},integrations:[]});
  return {service:new ControlMigrationService(client as any,options),source,target,options,payload};
}

test('copies preserved metadata, rewraps encrypted configuration, seeds trusted identities and resumes',async()=>{
  const f=fixture(), before=BSON.EJSON.stringify(f.source('tenantWorkflowConfiguration'));
  const review=await f.service.preview();
  expect(JSON.stringify(review)).not.toContain('preserved-secret');
  await f.service.stage(review.digest,'job');
  await f.service.stage(review.digest,'job');
  expect((await f.service.verify('job')).phase).toBe('verified');
  expect(f.target('tenantDefinitions')).toEqual(f.source('tenantDefinitions'));
  expect(BSON.EJSON.stringify(f.source('tenantWorkflowConfiguration'))).toBe(before);
  const row=f.target('tenantWorkflowConfiguration')[0];
  expect(row.ciphertext).not.toBe(f.source('tenantWorkflowConfiguration')[0].ciphertext);
  expect(decodeControlRuntime(row,f.options.wrappingKey,'control-kick-playr')).toEqual(f.payload);
  expect(()=>decodeControlRuntime(row,f.options.wrappingKey,'source')).toThrow();
  expect(f.target('vault_identity_policies')[0]).toMatchObject({environment:'development',issuer:'https://platform.example',adminSubjects:['user_admin'],revision:1,enabled:true});
  expect(f.target('vault_identity_realms')).toHaveLength(2);
  expect(f.target('vault_identity_realms')[1]).toMatchObject({jwksUrl:'https://club.example/.well-known/jwks.json',authorizedParties:['https://club.example','http://localhost:4001']});
});
test('rejects source drift and differing target rows including envelope tampering',async()=>{
  const f=fixture(), r=await f.service.preview();
  await f.service.stage(r.digest,'job');
  f.target('tenantDefinitions')[0].revision++;
  await expect(f.service.stage(r.digest,'job')).rejects.toThrow('target conflict');
  f.target('tenantDefinitions')[0].revision--;
  f.target('tenantWorkflowConfiguration')[0].tag=randomBytes(16).toString('base64');
  await expect(f.service.verify('job')).rejects.toThrow();
  f.source('tenantDefinitions')[0].revision++;
  await expect(f.service.stage(r.digest,'job')).rejects.toThrow('source changed');
  await expect(f.service.verify('job')).rejects.toThrow('source changed');
});
test('fails closed on plaintext, credentials, unsupported origins and extra target records',async()=>{
  const f=fixture();
  f.source('tenantExplorerConfiguration')[0].credentials={password:'never-copy'};
  await expect(f.service.preview()).rejects.toThrow('credential-bearing');
  f.source('tenantExplorerConfiguration')[0].credentials={};
  const r=await f.service.preview(); await f.service.stage(r.digest,'job');
  f.target('tenantDefinitions').push({_id:'unexpected'});
  await expect(f.service.verify('job')).rejects.toThrow('target conflict');
  f.source('tenantWorkflowConfiguration')[0]= {_id:'runtime:development',...f.payload};
  await expect(f.service.preview()).rejects.toThrow();
});
test('review digest binds private key, source and explicit additional origins',async()=>{
  const f=fixture(), digest=(await f.service.preview()).digest;
  f.options.additionalAuthorizedParties=[];
  expect((await f.service.preview()).digest).not.toBe(digest);
  f.options.additionalAuthorizedParties=['http://evil.example'];
  await expect(f.service.preview()).rejects.toThrow();
});
