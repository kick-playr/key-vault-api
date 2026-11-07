import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { BSON, MongoClient } from 'mongodb';
import { CONTROL_COLLECTIONS, ControlMigrationService, decodeControlRuntime, encodeControlRuntime } from '../../src/v2/control-migration.js';

let child: ChildProcess, client: MongoClient, directory: string;
beforeAll(async()=>{
  directory=await mkdtemp(join(tmpdir(),'control-migration-replica-'));
  const server=createServer(); await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  const port=(server.address() as any).port; await new Promise<void>(r=>server.close(()=>r()));
  child=spawn(process.env.MONGOD_BINARY ?? 'mongod',['--bind_ip','127.0.0.1','--port',String(port),'--dbpath',directory,'--replSet','migration-test','--noauth','--quiet','--wiredTigerCacheSizeGB','0.25'],{stdio:'ignore'});
  const direct=new MongoClient(`mongodb://127.0.0.1:${port}/?directConnection=true`,{serverSelectionTimeoutMS:300});
  const deadline=Date.now()+15000;
  while(true) { try {await direct.connect();await direct.db('admin').command({ping:1});break;}catch {if(Date.now()>deadline)throw Error('Test Mongo unavailable');await new Promise(r=>setTimeout(r,100));}}
  await direct.db('admin').command({replSetInitiate:{_id:'migration-test',members:[{_id:0,host:`127.0.0.1:${port}`} ]}});
  while(!(await direct.db('admin').command({hello:1})).isWritablePrimary) {if(Date.now()>deadline)throw Error('Test replica unavailable');await new Promise(r=>setTimeout(r,100));}
  await direct.close();
  client=new MongoClient(`mongodb://127.0.0.1:${port}/?replicaSet=migration-test`);await client.connect();
},20000);
afterAll(async()=>{
  await client?.close();
  if(child?.pid && child.exitCode===null){const done=new Promise<void>(r=>child.once('exit',()=>r()));child.kill('SIGTERM');await done;}
  if(directory)await rm(directory,{recursive:true,force:true});
});

test('native transaction copies unique fences/options, rebinds control metadata, and rolls back conflicts',async()=>{
  const source=client.db('source'),target=client.db('control-kick-playr'),key=randomBytes(32);
  for(const name of CONTROL_COLLECTIONS)await source.createCollection(name,name==='tenantDefinitions'?{validator:{id:{$type:'string'}},validationLevel:'strict'}:{});
  await source.collection('tenantDefinitions').createIndex({id:1,environment:1},{unique:true,name:'tenant_environment'});
  await source.collection<any>('tenantDefinitions').insertOne({_id:'a',id:'fcrww',environment:'development',revision:1,small:new BSON.Int32(8),long:BSON.Long.fromString('42')});
  const payload={tenants:[{id:'fcrww',mongoUri:'vault:MONGODB_URI'}],explorer:{issuer:'https://platform.example',adminSubjects:['user_admin'],authorizedParties:['http://localhost:3000'],clubRealms:[],keyBindings:{bindings:[{tenantId:'fcrww',controlDatabase:'source',profile:'local-real',variables:{wrapping:'WRAPPING',index:'INDEX',control:'CONTROL'}}]}}};
  await source.collection<any>('tenantWorkflowConfiguration').insertOne(encodeControlRuntime(payload,key,'source'));
  const service=new ControlMigrationService(client,{sourceDatabase:'source',targetDatabase:'control-kick-playr',environment:'development',wrappingKey:key,reviewKey:randomBytes(32),tenantDatabaseTargets:{fcrww:'fcrww-kick-playr'}});
  const review=await service.preview();await service.stage(review.digest,'job');await service.verify('job');
  const preserved=await target.collection<any>('tenantDefinitions').findOne({_id:'a'},{promoteValues:false,promoteLongs:false});
  expect(preserved.small).toBeInstanceOf(BSON.Int32);
  expect(preserved.long).toBeInstanceOf(BSON.Long);
  const decoded=decodeControlRuntime((await target.collection('tenantWorkflowConfiguration').findOne({}))!,key,'control-kick-playr');
  expect(decoded.tenants).toEqual(payload.tenants);
  expect(decoded.explorer.keyBindings.bindings[0].controlDatabase).toBe('control-kick-playr');
  expect((await target.collection('tenantDefinitions').listIndexes().toArray()).find(i=>i.name==='tenant_environment')?.unique).toBe(true);
  expect((await target.listCollections({name:'tenantDefinitions'},{nameOnly:false}).toArray())[0]?.options?.validator).toEqual({id:{$type:'string'}});
  await expect(target.collection<any>('tenantDefinitions').insertOne({_id:'duplicate',id:'fcrww',environment:'development'})).rejects.toThrow();
  await target.collection<any>('tenantDefinitions').updateOne({_id:'a'},{$set:{revision:2}});
  await expect(service.stage(review.digest,'job')).rejects.toThrow('target conflict');
  expect((await source.collection<any>('tenantDefinitions').findOne({_id:'a'}))?.revision).toBe(1);
  await target.collection('tenantDefinitions').dropIndex('tenant_environment');
  await target.collection('tenantDefinitions').createIndex({environment:1,id:1},{unique:true,name:'tenant_environment'});
  await expect(service.verify('job')).rejects.toThrow('index conflict');
  await source.createCollection('unknown');await expect(service.preview()).rejects.toThrow('Unreviewed');
},20000);
