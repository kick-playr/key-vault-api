import { createHash } from 'node:crypto';
import { V2MongoStore } from '../../src/v2/mongo-store.js';
import { Authorization } from '../../src/v2/authorization.js';
import { LinkService } from '../../src/v2/links.js';
import { InstanceService } from '../../src/v2/instances.js';
import { KeyRotationService } from '../../src/v2/key-rotations.js';
import { ResourceService } from '../../src/v2/resources.js';
import { IntegrationSchemas } from '../../src/v2/integration-schemas.js';
import { createWorkloadOperator } from '../../src/v2/workload-operator.js';
import { BootstrapService } from '../../src/v2/bootstrap.js';
import { replicaFixture } from './mongo-fixture.js';
import type { ResourceRecord, ResourceVersion, ResourceScope } from '../../src/v2/records.js';
const env='development', actor={issuer:'test',subject:'admin'};
const scope=(id:string):ResourceScope=>({environment:env,ownerType:'application',ownerId:id});
let fixture:Awaited<ReturnType<typeof replicaFixture>>,store:V2MongoStore;
const checked:string[]=[];
const authorization=new Authorization({roles:async(_actor,owner)=>{checked.push(owner.ownerId);return {revision:'1',globalAdmin:owner.ownerId!=='denied',clubAdminTenantIds:[]}},fence:async()=>{}},{read:async()=>null});
let links:LinkService,bootstrap:BootstrapService;
beforeAll(async()=>{
 fixture=await replicaFixture();store=await V2MongoStore.open({mongoUri:fixture.uri,masterKey:Buffer.alloc(32,9)});links=new LinkService(store,authorization);bootstrap=new BootstrapService(store);
 await store.transaction(async tx=>{
  await tx.db.collection('vault_application_environments').insertMany(['source','target','unlinked','denied','alternate'].map(applicationId=>({applicationId,environment:env,enabled:true,revision:1})),{session:tx.session});
  for(const applicationId of ['source','target','unlinked'])await store.grants.insertOne({_id:applicationId,applicationId,environment:env,tokenHash:createHash('sha256').update(password(applicationId)).digest('hex'),grantClass:'application',capabilities:['secrets:read','keys:export'],enabled:true,revision:1,createdAt:0},{session:tx.session});
 });
 for(const [id,ownerId,kind] of [['shared','source','secret'],['key','source','encryption-key'],['replacement','alternate','encryption-key'],['denied-resource','denied','secret']] as const){
  const owner=scope(ownerId),value=Buffer.from(kind==='secret'?'shared-secret':Buffer.alloc(32,3).toString('base64'));
  const resource:ResourceRecord={...owner,_id:id,name:id,kind,contentType:'text/plain',valueFormat:kind==='secret'?'text':'base64',schemaIdentity:kind==='secret'?'secret:text@1':'key:base64@1',enabled:true,revision:1,currentVersionId:id+'-v1',currentVersionNumber:1,custody:'workload-only'};
  const version:ResourceVersion={...owner,_id:id+'-v1',resourceId:id,versionNumber:1,kind,contentType:resource.contentType,valueFormat:resource.valueFormat,schemaIdentity:resource.schemaIdentity,createdAt:0,createdBy:'test',value:store.sealValue(owner,id,id+'-v1',resource.schemaIdentity,value)};
  await store.transaction(async tx=>{await store.resources.insertOne(resource,{session:tx.session});await store.versions.insertOne(version,{session:tx.session})});value.fill(0);
 }
},30000);
afterAll(async()=>{await store?.close();await fixture?.close()});
function password(id:string){return id[0]!.repeat(43)}
const input=(applicationId:string,resourceId='shared',accessName='SHARED_SECRET')=>({applicationId,resourceId,accessName,versionPolicy:'latest'});
async function view(app:string,etag?:string){return bootstrap.snapshot('Bearer '+password(app),app,env,etag)}
it('shares one same-environment resource with dual authorization and preserves it through target batch save',async()=>{
 await links.create(actor,scope('source'),input('source'));
 checked.length=0;
 await links.create(actor,scope('source'),input('target'));
 await expect(links.create(actor,scope('source'),input('unlinked','shared','DIFFERENT_NAME'))).rejects.toThrow('Vault access denied');
 expect(checked).toEqual(expect.arrayContaining(['source','target']));
 await expect(links.create(actor,scope('source'),input('denied'))).rejects.toThrow('Vault access denied');
 await expect(links.create(actor,scope('target'),input('target','denied-resource'))).rejects.toThrow('Vault access denied');
 await expect(links.create(actor,{...scope('source'),environment:'test'},input('target'))).rejects.toThrow();
 const source=await view('source'),target=await view('target'),unlinked=await view('unlinked');
 expect(source.status).toBe(200);expect(target.status).toBe(200);
 if(source.status!==200||target.status!==200||unlinked.status!==200)throw Error();
 expect(source.snapshot.application.values[0]).toEqual(target.snapshot.application.values[0]);
 expect(target.snapshot.application.values[0]!.value).toBe('shared-secret');
 expect(unlinked.snapshot.application.values).toEqual([]);
 const listed=await links.list(actor,scope('target'),'target');
 expect(listed.sharedResources).toEqual(expect.arrayContaining([expect.objectContaining({_id:'shared',ownerId:'source'})]));
 await links.save(actor,scope('target'),'target',listed.deployment!.revision,[{resourceId:'shared',accessName:'SHARED_SECRET',versionPolicy:'latest',applicationId:'denied',tenantId:'victim'} as any]);
 const saved=await view('target');expect(saved.status===200&&saved.snapshot.application.values[0]!.resourceId).toBe('shared');
 await expect(links.save(actor,scope('target'),'target',listed.deployment!.revision+1,[{resourceId:'denied-resource',accessName:'SHARED_SECRET',versionPolicy:'latest'}])).rejects.toThrow('Vault access denied');
 expect((await links.list(actor,scope('target'),'target')).links.map(row=>row.resourceId)).toEqual(['shared']);
});
it('keeps persistent consumer key identity when resource ownership changes',async()=>{
 await links.create(actor,scope('source'),input('target','key','SHARED_WRAPPING_KEY_V1'));
 const listed=await links.list(actor,scope('target'),'target');
 await links.save(actor,scope('target'),'target',listed.deployment!.revision,[]);
 await expect(links.create(actor,scope('alternate'),input('target','replacement','SHARED_WRAPPING_KEY_V1'))).rejects.toThrow('coordinated rotation');
});
it('keeps one shared key rotation and requires acknowledgements from both consuming applications',async()=>{
 await links.create(actor,scope('source'),input('source','key','SHARED_WRAPPING_KEY_V1'));
 await links.create(actor,scope('source'),input('target','key','SHARED_WRAPPING_KEY_V1'));
 const instances=new InstanceService(store),source=await instances.register('Bearer '+password('source'),'source',env),target=await instances.register('Bearer '+password('target'),'target',env);
 const token='o'.repeat(43);
 await store.transaction(async tx=>{
  await store.grants.insertOne({_id:'operator',grantClass:'operator',environment:env,tokenHash:createHash('sha256').update(token).digest('hex'),capabilities:['rotations:admin'],enabled:true,revision:1,createdAt:0},{session:tx.session});
  await tx.db.collection<any>('vault_grant_scopes').insertOne({_id:'operator-source',grantId:'operator',...scope('source')},{session:tx.session});
 });
 const operator=await createWorkloadOperator(store,'Bearer '+token,scope('source')),rotations=new KeyRotationService(store,operator.authorization),resources=new ResourceService(store,operator.authorization,new IntegrationSchemas());
 const prepared=await resources.stageGeneratedKey(operator.actor,scope('source'),'key',1,rotations);
 const rotation=await store.transaction(tx=>tx.db.collection<any>('vault_key_rotations').findOne({_id:prepared.rotationId},{session:tx.session}));
 expect(rotation).not.toBeNull();
 const participants=await store.transaction(tx=>tx.db.collection('vault_key_rotation_participants').find({rotationId:prepared.rotationId},{session:tx.session}).toArray());
 expect(participants.map(row=>row.instanceId).sort()).toEqual([source.instanceId,target.instanceId].sort());
 const sourceView=await view('source'),targetView=await view('target');
 if(sourceView.status!==200||targetView.status!==200)throw Error();
 expect(sourceView.snapshot.application.values.find(row=>row.resourceId==='key')?.keyVersions).toEqual(targetView.snapshot.application.values.find(row=>row.resourceId==='key')?.keyVersions);
 await instances.acknowledge('Bearer '+password('source'),'source',env,{...source,rotationId:prepared.rotationId,versionId:rotation!.newVersionId});
 await expect(rotations.activate(operator.actor,scope('source'),prepared.rotationId)).rejects.toThrow('Waiting for instance key acknowledgements');
 await instances.acknowledge('Bearer '+password('target'),'target',env,{...target,rotationId:prepared.rotationId,versionId:rotation!.newVersionId});
 await expect(rotations.activate(operator.actor,scope('source'),prepared.rotationId)).resolves.toEqual({state:'active'});
});
it('invalidates the shared consumer view when the source deployment is disabled',async()=>{
 await links.create(actor,scope('source'),input('target'));
 const prior=await view('target');
 await store.transaction(async tx=>{await tx.db.collection('vault_application_environments').updateOne({applicationId:'source',environment:env},{$set:{enabled:false},$inc:{revision:1}},{session:tx.session})});
 const next=await view('target',prior.etag);expect(next.status).toBe(200);
 if(next.status!==200)throw Error();expect(next.snapshot.application.ready).toBe(false);expect(next.snapshot.application.values).toEqual([]);
});
