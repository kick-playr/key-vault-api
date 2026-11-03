import { ApplicationsService } from '../src/applications.js';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { MongoStore } from '../src/store.js';
import { formatStartupError } from '../src/errors.js';
import { scopeId } from '../src/types.js';
import { mongoUri } from './mongo.js';

describe('encrypted MongoDB store', () => {
  let store: MongoStore | undefined, second: MongoStore | undefined, client: MongoClient;
  let database: string;
  const key = randomBytes(32), scope = { environment: 'dev', tenant: 'a' };
  const config = () => ({ mongoUri: `${mongoUri}/${database}`, masterKey: key });
  const id = () => createHash('sha256').update(scopeId(scope)).digest('hex');
  beforeEach(async () => { database = 'test_' + randomUUID().replaceAll('-', ''); client = await new MongoClient(mongoUri).connect(); });
  afterEach(async () => { await store?.close(); await second?.close(); store = second = undefined; await client.db(database).dropDatabase(); await client.close(); });

  it('stores only ciphertext and reloads persisted state after reconnection', async () => {
    store = await MongoStore.open(config());
    await store.transaction(scope, ns => { ns.tombstones.push('secret-canary'); });
    const raw = await client.db(database).collection('vault_namespaces').findOne({ _id: id() } as never);
    expect(raw).toBeTruthy(); expect(JSON.stringify(raw)).not.toContain('secret-canary');
    expect(await client.db(database).collection('vault_metadata').countDocuments()).toBe(1);
    await store.close(); store = await MongoStore.open(config());
    expect(await store.read(scope, ns => ns?.tombstones)).toEqual(['secret-canary']);
  });
  it('rejects a bare MongoDB URL before creating fallback database collections', async () => {
    await expect(MongoStore.open({ mongoUri, masterKey: key }).then(opened => { store = opened; })).rejects.toThrow('InvalidBootstrap');
    expect(await client.db('local_key_vault').collection('vault_namespaces').countDocuments()).toBe(0);
    expect(await client.db('local_key_vault').collection('vault_metadata').countDocuments()).toBe(0);
    expect(await client.db('test').collection('vault_namespaces').countDocuments()).toBe(0);
  });
  it('rejects wrong master keys at startup and corrupted namespace ciphertext on read', async () => {
    store = await MongoStore.open(config());
    await expect(MongoStore.open({ ...config(), masterKey: randomBytes(32) })).rejects.toThrow('StoreUnavailable');
    await store.transaction(scope, ns => { ns.tombstones.push('protected'); });
    await client.db(database).collection('vault_namespaces').updateOne({ _id: id() } as never, { $set: { data: 'corrupt' } });
    await expect(store.read(scope, ns => ns)).rejects.toThrow('StoreUnavailable');
  });
  it('handles concurrent connections without lost updates and reads other writers immediately', async () => {
    [store, second] = await Promise.all([MongoStore.open(config()), MongoStore.open(config())]);
    await Promise.all(Array.from({ length: 12 }, (_, i) => (i % 2 ? store! : second!).transaction(scope, async ns => {
      await new Promise(resolve => setTimeout(resolve, 2)); ns.tombstones.push(String(i));
    })));
    expect((await second.read(scope, ns => ns?.tombstones))?.sort()).toEqual(Array.from({ length: 12 }, (_, i) => String(i)).sort());
    await store.transaction(scope, ns => { ns.tombstones.push('new'); });
    expect(await second.read(scope, ns => ns?.tombstones.at(-1))).toBe('new');
  });
  it('rolls back a failed callback and does not publish mutable references', async () => {
    store = await MongoStore.open(config());
    const result = await store.transaction(scope, ns => { ns.tombstones.push('before'); return ns; });
    result.tombstones.push('outside');
    await expect(store.transaction(scope, ns => { ns.tombstones.push('bad'); throw new Error('abort'); })).rejects.toThrow('abort');
    expect(await store.read(scope, ns => ns?.tombstones)).toEqual(['before']);
  });
  it('authenticates the namespace ID and revision so ciphertext cannot be swapped', async () => {
    store = await MongoStore.open(config());
    await store.transaction(scope, ns => { ns.tombstones.push('protected'); });
    const raw = await client.db(database).collection('vault_namespaces').findOne({ _id: id() } as never);
    const otherScope = { environment: 'dev', tenant: 'b' };
    await client.db(database).collection('vault_namespaces').insertOne({ ...raw, _id: createHash('sha256').update(scopeId(otherScope)).digest('hex') } as never);
    await expect(store.read(otherScope, ns => ns)).rejects.toThrow('StoreUnavailable');
    await client.db(database).collection('vault_namespaces').updateOne({ _id: id() } as never, { $inc: { revision: 1 } });
    await expect(store.read(scope, ns => ns)).rejects.toThrow('StoreUnavailable');
  });
  it('rejects an oversized namespace atomically before MongoDB document limits', async () => {
    store = await MongoStore.open(config());
    await store.transaction(scope, ns => { ns.tombstones.push('before'); });
    await expect(store.transaction(scope, ns => { ns.tombstones.push('x'.repeat(8 * 1024 * 1024)); })).rejects.toThrow('NamespaceTooLarge');
    expect(await store.read(scope, ns => ns?.tombstones)).toEqual(['before']);
  });
  it('fails closed after close and does not expose a MongoDB URI on connection failure', async () => {
    store = await MongoStore.open(config()); await store.close();
    await expect(store.read(scope, ns => ns)).rejects.toThrow('StoreUnavailable');
    await expect(MongoStore.open({ ...config(), mongoUri: 'mongodb://test-user:test-password@127.0.0.1:1/key-vault' })).rejects.toThrow(/^StoreUnavailable$/);
  });
  it('explains wrong master keys during startup without leaking key material', async () => {
    store = await MongoStore.open(config());
    try { second = await MongoStore.open({ ...config(), masterKey: randomBytes(32) }); throw new Error('Expected failure'); }
    catch (error) {
      const detail = formatStartupError(error);
      expect(detail).toContain('master-key verification'); expect(detail).toContain('VAULT_MASTER_KEY');
      expect(detail).not.toContain(key.toString('base64'));
    }
  });
  it('does not commit failed MongoDB writes or serve cached data after a failed read', async () => {
    store = await MongoStore.open(config());
    await store.transaction(scope, ns => { ns.tombstones.push('before'); });
    await client.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 }, data: { failCommands: ['update'], errorCode: 2 } });
    await expect(store.transaction(scope, ns => { ns.tombstones.push('uncommitted'); })).rejects.toThrow(/^StoreUnavailable$/);
    expect(await store.read(scope, ns => ns?.tombstones)).toEqual(['before']);
    await client.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 }, data: { failCommands: ['find'], errorCode: 2 } });
    await expect(store.read(scope, ns => ns?.tombstones)).rejects.toThrow(/^StoreUnavailable$/);
    expect(await store.read(scope, ns => ns?.tombstones)).toEqual(['before']);
  });
  it('blocks deletion during a reserved tenant reference and rejects a late link after deletion wins',async()=>{
    store=await MongoStore.open(config());second=await MongoStore.open(config());
    const shared={environment:'dev',tenant:'_shared'},app=new ApplicationsService(store),other=new ApplicationsService(second);
    await app.save(shared,'custom',{expectedRevision:0,displayName:'Custom',description:''});
    let reached!:()=>void,release!:()=>void;
    const blocked=new Promise<void>(r=>release=r),waiting=new Promise<void>(r=>reached=r);
    const collection=(store as any).collection,original=collection.insertOne.bind(collection);
    collection.insertOne=async(envelope:any,...args:any[])=>{if(envelope._id===id()){reached();await blocked;}return original(envelope,...args);};
    const writing=store.transaction(scope,ns=>{ns.resourceAssociations={'secrets/sample':{envName:'SAMPLE',memberships:{custom:'latest'}}};});
    try{await waiting;expect((await other.usage(shared,'custom')).pending).toBe(1);await expect(other.remove(shared,'custom',{expectedRevision:1,confirmName:'custom'})).rejects.toThrow('ApplicationInUse');}
    finally{release();await writing;}
    expect(await app.usage(shared,'custom')).toMatchObject({links:1,pending:0,inUse:true});
    await store.transaction(scope,ns=>{ns.resourceAssociations={};});
    let finish!:()=>void,started!:()=>void;
    const held=new Promise<void>(r=>finish=r),ready=new Promise<void>(r=>started=r);
    const late=store.transaction(scope,async ns=>{ns.resourceAssociations={'secrets/sample':{envName:'SAMPLE',memberships:{custom:'latest'}}};started();await held;});
    await ready;try{await other.remove(shared,'custom',{expectedRevision:1,confirmName:'custom'});}finally{finish();}
    await expect(late).rejects.toThrow('ApplicationNotFound');
    expect(await store.read(scope,ns=>ns?.resourceAssociations)).toEqual({});
  });
  it('does not treat a verified other-environment reference as current usage',async()=>{
    store=await MongoStore.open(config());const service=new ApplicationsService(store),shared={environment:'dev',tenant:'_shared'};
    for(const environment of ['dev','prod'])await service.save({environment,tenant:'_shared'},'custom',{expectedRevision:0,displayName:'Custom',description:''});
    await store.transaction({environment:'prod',tenant:'other'},ns=>{ns.resourceAssociations={'secrets/value':{envName:'VALUE',memberships:{custom:'latest'}}};});
    expect(await service.usage(shared,'custom')).toMatchObject({links:0,verified:true,inUse:false});
    await service.remove(shared,'custom',{expectedRevision:1,confirmName:'custom'});
    expect((await service.list({environment:'prod',tenant:'_shared'})).applications).toHaveLength(1);
  });

  it('blocks a late manifest enrollment for a deleted name while preserving never-modeled legacy publication',async()=>{
    store=await MongoStore.open(config());second=await MongoStore.open(config());const shared={environment:'dev',tenant:'_shared'};
    const app=new ApplicationsService(store);await app.save(shared,'custom',{expectedRevision:0,displayName:'Custom',description:''});
    await app.remove(shared,'custom',{expectedRevision:1,confirmName:'custom'});
    await expect(second.transaction(scope,ns=>{ns.runtimeManifests={custom:{currentRevision:1,versions:{'1':{scope,application:'custom'} as any}}};})).rejects.toThrow('ApplicationNotFound');
    expect(await second.read(scope,ns=>ns?.runtimeManifests)).toBeUndefined();
    await expect(second.transaction(shared,ns=>{ns.runtimeManifests={custom:{currentRevision:1,versions:{'1':{scope:shared,application:'custom'} as any}}};})).rejects.toThrow('ApplicationNotFound');
    await second.transaction(scope,ns=>{ns.runtimeManifests={legacy:{currentRevision:1,versions:{'1':{scope,application:'legacy'} as any}}};});
    await app.save(shared,'custom',{expectedRevision:2,displayName:'Recreated',description:''});
    await second.transaction(scope,ns=>{ns.runtimeManifests!.custom={currentRevision:1,versions:{'1':{scope,application:'custom'} as any}};});
    expect((await app.usage(shared,'custom')).manifests).toBe(1);
  });

});
