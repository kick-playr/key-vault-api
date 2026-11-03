import { ApplicationsService } from '../src/applications.js';
import { emptyNamespace, type Scope, type Namespace } from '../src/types.js';
import { newSecret } from '../src/vault.js';
const scope = { environment: 'development', tenant: '_shared' };
function fixture() {
  const states = new Map<string, Namespace>();
  const state = (s: Scope) => { const id = JSON.stringify(s); if (!states.has(id)) states.set(id, emptyNamespace()); return states.get(id)!; };
  const store = { applicationUsage:async(s:Scope,name:string)=>{let links=0,manifests=0,instances=0;for(const [id,ns]of states){if(JSON.parse(id).environment!==s.environment)continue;links+=Object.values(ns.resourceAssociations??{}).filter(r=>Object.hasOwn(r.memberships,name)).length;manifests+=ns.runtimeManifests?.[name]?1:0;instances+=Object.values(ns.runtimeInstances??{}).filter(r=>r.application===name&&r.expiresAt>Date.now()).length;}return{links,manifests,instances,verified:true};},read: async (s: Scope, fn: any) => structuredClone(fn(structuredClone(state(s)))), transaction: async (s: Scope, fn: any) => {
    const copy = structuredClone(state(s)); const result = await fn(copy); states.set(JSON.stringify(s), copy); return structuredClone(result);
  } };
  return { service: new ApplicationsService(store as any), state };
}
it('models editable apps and shared secret links with one canonical ENV name without exposing values', async () => {
  const f = fixture();
  f.state(scope).secrets['database'] = [newSecret({ value: 'SECRET_CANARY', tags: { purpose: 'database' } })];
  await f.service.save(scope, 'club-api', { expectedRevision: 0, displayName: 'Club API', description: 'Server' });
  await f.service.save(scope, 'explorer-api', { expectedRevision: 1, displayName: 'Explorer API', description: '' });
  await f.service.link(scope, 'club-api', 'secrets', 'database', { expectedRevision: 2, envName: 'DATABASE_URL', version: 'latest' });
  const result = await f.service.link(scope, 'explorer-api', 'secrets', 'database', { expectedRevision: 3, envName: 'DATABASE_URL', version: 'latest' });
  expect(result.applications.map(a => [a.name, a.resources[0]?.envName])).toEqual([['club-api', 'DATABASE_URL'], ['explorer-api', 'DATABASE_URL']]);
  expect(result.applications[0]!.resources[0]!.applications).toEqual(['club-api', 'explorer-api']);
  expect(JSON.stringify(result)).not.toContain('SECRET_CANARY');
  await expect(f.service.link(scope, 'explorer-api', 'secrets', 'database', { expectedRevision: 4, envName: 'OTHER_URL', version: 'latest' })).rejects.toThrow('CanonicalMappingConflict');
  await f.service.save(scope, 'club-api', { expectedRevision: 4, displayName: 'Renamed club API', description: 'Changed' });
  expect((await f.service.list(scope)).applications[0]!.displayName).toBe('Renamed club API');
});
it('preserves membership over new versions, supports exact pins, and unlinks without deleting bytes', async () => {
  const f = fixture(); const one = newSecret({ value: 'one' });
  f.state(scope).secrets['database'] = [one];
  await f.service.save(scope, 'club-api', { expectedRevision: 0, displayName: 'Club', description: '' });
  await f.service.link(scope, 'club-api', 'secrets', 'database', { expectedRevision: 1, envName: 'DATABASE_URL', version: one.version });
  f.state(scope).secrets['database']!.push(newSecret({ value: 'two' }));
  expect((await f.service.list(scope)).applications[0]!.resources[0]!.version).toBe(one.version);
  await f.service.link(scope, 'club-api', 'secrets', 'database', { expectedRevision: 2, envName: 'DATABASE_URL', version: 'latest' });
  expect((await f.service.list(scope)).applications[0]!.resources[0]!.version).not.toBe(one.version);
  await f.service.unlink(scope, 'club-api', 'secrets', 'database', { expectedRevision: 3 });
  expect((await f.service.list(scope)).applications[0]!.resources).toHaveLength(0);
  expect(f.state(scope).secrets['database']).toHaveLength(2);
});
it('rejects stale writes, duplicate mappings, missing versions and unsafe ENV names atomically', async () => {
  const f = fixture();
  f.state(scope).secrets['first'] = [newSecret({ value: 'one' })];
  f.state(scope).secrets['second'] = [newSecret({ value: 'two' })];
  await f.service.save(scope, 'club-api', { expectedRevision: 0, displayName: 'Club', description: '' });
  await f.service.link(scope, 'club-api', 'secrets', 'first', { expectedRevision: 1, envName: 'DATABASE_URL', version: 'latest' });
  await expect(f.service.link(scope, 'club-api', 'secrets', 'second', { expectedRevision: 1, envName: 'OTHER_URL', version: 'latest' })).rejects.toThrow('ApplicationRevisionConflict');
  await expect(f.service.link(scope, 'club-api', 'secrets', 'second', { expectedRevision: 2, envName: 'DATABASE_URL', version: 'latest' })).rejects.toThrow('MappingConflict');
  await expect(f.service.link(scope, 'club-api', 'secrets', 'second', { expectedRevision: 2, envName: 'NEXT_PUBLIC_KEY', version: 'latest' })).rejects.toThrow();
  await expect(f.service.link(scope, 'club-api', 'secrets', 'second', { expectedRevision: 2, envName: 'OTHER_URL', version: 'a'.repeat(32) })).rejects.toThrow('SecretNotFound');
  expect((await f.service.list(scope)).revision).toBe(2);
});
it('tenant views project only local memberships and app records can be created only in shared scope', async () => {
  const f = fixture(); const tenant = { ...scope, tenant: 'club' };
  await f.service.save(scope, 'club-api', { expectedRevision: 0, displayName: 'Club', description: '' });
  await f.service.save(scope, 'other-app', { expectedRevision: 1, displayName: 'Other', description: '' });
  expect((await f.service.list(tenant)).applications).toEqual([]);
  await expect(f.service.save(tenant, 'new-app', { expectedRevision: 0, displayName: 'New', description: '' })).rejects.toThrow('SharedScopeRequired');
  f.state(tenant).secrets['local'] = [newSecret({ value: 'tenant-secret' })];
  await f.service.link(tenant, 'club-api', 'secrets', 'local', { expectedRevision: 0, envName: 'LOCAL_KEY', version: 'latest' });
  expect((await f.service.list(tenant)).applications.map(a => a.name)).toEqual(['club-api']);
  expect((await f.service.list({ ...tenant, tenant: 'another' })).applications).toEqual([]);
});
it('protects application HTTP mutations with exact namespace write grants and audits without values', async () => {
  const { jest } = await import('@jest/globals');
  const { default: request } = await import('supertest');
  const { createHash, randomBytes } = await import('node:crypto');
  const { MongoStore } = await import('../src/store.js');
  const { createApp } = await import('../src/app.js');
  const token = 'application-fixture-aaaaaaaaaaaaaaaa';
  const ns = emptyNamespace(); ns.secrets['database'] = [newSecret({ value: 'HTTP_VALUE_CANARY' })];
  const grant = { id: 'a'.repeat(64), tokenHash: createHash('sha256').update(token).digest('hex'), ...scope, permissions: ['list', 'write'], enabled: true };
  const events: unknown[] = [];
  const store = { applicationUsage:async()=>({links:Object.values(ns.resourceAssociations??{}).filter(r=>Object.hasOwn(r.memberships,'club-api')).length,manifests:0,instances:0,verified:true}),readGrants: async () => [grant], read: async (_: unknown, fn: any) => structuredClone(fn(structuredClone(ns))), transaction: async (_: unknown, fn: any) => { const copy = structuredClone(ns); const result = await fn(copy); Object.assign(ns, copy); return structuredClone(result); }, appendAudit: async (event: unknown) => { events.push(event); }, close: async () => {} };
  const spy = jest.spyOn(MongoStore, 'open').mockResolvedValue(store as any);
  const app = await createApp({ mongoUri: 'mongodb://127.0.0.1:1/fixture', masterKey: randomBytes(32), baseUrl: 'http://127.0.0.1:4000', audit: { read: 'collection', write: 'collection', list: 'collection', crypto: 'off' } });
  spy.mockRestore(); await app.init();
  const call = (method: 'get' | 'put' | 'delete', path = '/local/applications') => request(app.getHttpServer())[method](path).set('Authorization', `Bearer ${token}`).set('x-vault-environment', scope.environment).set('x-vault-tenant', scope.tenant);
  try {
    await call('put', '/local/applications/club-api').send({ expectedRevision: 0, displayName: 'Club', description: '' }).expect(200);
    const result = await call('put', '/local/applications/club-api/resources/secrets/database').send({ expectedRevision: 1, envName: 'DATABASE_URL', version: 'latest' }).expect(200);
    expect(result.body.applications[0].resources[0].envName).toBe('DATABASE_URL');
    expect(JSON.stringify(result.body)).not.toContain('HTTP_VALUE_CANARY');
    await call('get', '/namespaces/development/_shared/local/applications').expect(200);
    await call('get').set('x-vault-tenant', 'other').expect(403);
    await call('get','/local/applications/club-api/usage').expect(200).expect(r=>expect(r.body.inUse).toBe(true));
    await call('delete','/local/applications/club-api').send({expectedRevision:2,confirmName:'club-api'}).expect(409);
    grant.permissions = ['list'];
    await call('delete','/local/applications/club-api').send({expectedRevision:2,confirmName:'club-api'}).expect(403);
    await call('put', '/local/applications/club-api').send({ expectedRevision: 2, displayName: 'Changed' }).expect(403);
    grant.permissions = ['write'];
    await call('get').expect(403);
    grant.permissions = ['list', 'write'];
    await call('delete', '/local/applications/club-api/resources/secrets/database').send({ expectedRevision: 2 }).expect(200);
    await call('delete','/local/applications/club-api').send({expectedRevision:3,confirmName:'other'}).expect(400);
    await call('delete','/local/applications/club-api').send({expectedRevision:2,confirmName:'club-api'}).expect(409);
    await call('delete','/local/applications/club-api').send({expectedRevision:3,confirmName:'club-api'}).expect(200);
    expect(ns.secrets.database![0]!.value).toBe('HTTP_VALUE_CANARY');
    await app.close();
    expect(events.some((e: any) => e.action === 'local.applications.write')).toBe(true);
    expect(JSON.stringify(events)).not.toContain('HTTP_VALUE_CANARY');
    expect(JSON.stringify(events)).not.toContain(token);
  } finally { await app.close(); }
});
it('accepts distinct operator catalog and tenant grants without granting cross-namespace access', async () => {
  const { jest } = await import('@jest/globals'); const { default: request } = await import('supertest');
  const { createHash, randomBytes } = await import('node:crypto');
  const { MongoStore } = await import('../src/store.js'); const { createApp } = await import('../src/app.js');
  const tenantScope = {...scope,tenant:'club'};
  const catalogToken = 'catalog-token-aaaaaaaaaaaaaaaaaaaaaaaa', tenantToken = 'tenant-token-bbbbbbbbbbbbbbbbbbbbbbbb';
  const shared = emptyNamespace(); shared.applications = {'club-api':{displayName:'Club',description:''}};
  const tenant = emptyNamespace(); tenant.secrets.local = [newSecret({value:'TENANT_CANARY'})];
  const grant = (token:string,s:Scope) => ({id: createHash('sha256').update(token).digest('hex'),tokenHash:createHash('sha256').update(token).digest('hex'),...s,permissions:['list','write'],enabled:true});
  const grants = [grant(catalogToken,scope),grant(tenantToken,tenantScope)];
  const store = {readGrants:async()=>grants,read:async(s:Scope,fn:any)=>structuredClone(fn(s.tenant==='_shared'?shared:tenant)),transaction:async(s:Scope,fn:any)=>fn(s.tenant==='_shared'?shared:tenant),appendAudit:async()=>{},close:async()=>{}};
  const spy=jest.spyOn(MongoStore,'open').mockResolvedValue(store as any);
  const app=await createApp({mongoUri:'mongodb://127.0.0.1:1/fixture',masterKey:randomBytes(32),baseUrl:'http://127.0.0.1:4000',audit:{list:'off',write:'off',read:'off',crypto:'off'}}); spy.mockRestore(); await app.init();
  const call=(bulk=false)=>request(app.getHttpServer()).put('/local/applications/club-api/resources'+(bulk?'':'/secrets/local')).set('Authorization',`Bearer ${tenantToken}`).set('x-vault-environment','development').set('x-vault-tenant','club');
  try {
    const body={expectedRevision:0,envName:'LOCAL_KEY',version:'latest'};
    await call().send(body).expect(403);
    await call().set('x-vault-catalog-token',catalogToken).send(body).expect(200);
    await call().set('x-vault-tenant','another').set('x-vault-catalog-token',catalogToken).send(body).expect(403);
    const batch={expectedRevision:1,updates:[{kind:'secrets',name:'local',selected:false}]};
    await call(true).send(batch).expect(403);
    await call(true).set('x-vault-catalog-token',catalogToken).send(batch).expect(200);
    expect(tenant.resourceAssociations!['secrets/local']!.memberships).toEqual({});
  } finally {await app.close();}
});
it.each(['LOCAL_KEYVAULT_AUTH_JSON','SECRETS_KEYS_STRATEGY','NODE_OPTIONS','NEXT_PUBLIC_KEY'])('never models runtime bootstrap variable %s as a secret mapping', async mapping=>{
  const f=fixture(); f.state(scope).secrets['bootstrap']=[newSecret({value:'private'})];
  await f.service.save(scope,'club-api',{expectedRevision:0,displayName:'Club',description:''});
  await expect(f.service.link(scope,'club-api','secrets','bootstrap',{expectedRevision:1,envName:mapping,version:'latest'})).rejects.toThrow();
});
it('saves selected secret/key link changes in one revision and rolls back invalid selections', async () => {
  const f=fixture(); const one=newSecret({value:'PRIVATE'}),two=newSecret({value:'PRIVATE2'});
  f.state(scope).secrets.first=[one]; f.state(scope).secrets.second=[two];
  await f.service.save(scope,'club-api',{expectedRevision:0,displayName:'Club',description:''});
  const changes=[{kind:'secrets',name:'first',selected:true,envName:'FIRST_KEY',version:'latest'},{kind:'secrets',name:'second',selected:true,envName:'SECOND_KEY',version:two.version}];
  const result=await f.service.updateLinks(scope,'club-api',{expectedRevision:1,updates:changes});
  expect(result.revision).toBe(2);expect(result.applications[0]!.resources).toHaveLength(2);expect(JSON.stringify(result)).not.toContain('PRIVATE');
  await expect(f.service.updateLinks(scope,'club-api',{expectedRevision:2,updates:[{kind:'secrets',name:'first',selected:false},{...changes[1],version:'f'.repeat(32)}]})).rejects.toThrow();
  expect((await f.service.list(scope)).applications[0]!.resources).toHaveLength(2);expect((await f.service.list(scope)).revision).toBe(2);
  await f.service.updateLinks(scope,'club-api',{expectedRevision:2,updates:[{kind:'secrets',name:'first',selected:false}]});
  expect((await f.service.list(scope)).applications[0]!.resources.map(r=>r.name)).toEqual(['second']);expect(f.state(scope).secrets.first).toHaveLength(1);
});

it('batch links non-exportable keys, keeps unloaded links and rejects stale or duplicate row writes',async()=>{
 const f=fixture(),key={version:'a'.repeat(32),attributes:{enabled:true,created:1,updated:1,recoveryLevel:'Purgeable' as const},privateKey:{kty:'RSA',d:'PRIVATE_CANARY'}};
 f.state(scope).keys.wrapping=[key];f.state(scope).secrets.unseen=[newSecret({value:'PRIVATE_CANARY'})];
 await f.service.save(scope,'club-api',{expectedRevision:0,displayName:'Club',description:''});
 await f.service.link(scope,'club-api','secrets','unseen',{expectedRevision:1,envName:'UNSEEN_KEY',version:'latest'});
 const update={kind:'keys',name:'wrapping',selected:true,envName:'WRAPPING_KEY',version:key.version};
 const result=await f.service.updateLinks(scope,'club-api',{expectedRevision:2,updates:[update]});
 expect(result.applications[0]!.resources).toHaveLength(2);expect(JSON.stringify(result)).not.toContain('PRIVATE_CANARY');
 await expect(f.service.updateLinks(scope,'club-api',{expectedRevision:2,updates:[update]})).rejects.toThrow('ApplicationRevisionConflict');
 await expect(f.service.updateLinks(scope,'club-api',{expectedRevision:3,updates:[update,update]})).rejects.toThrow();
 await expect(f.service.updateLinks(scope,'club-api',{expectedRevision:3,updates:[{...update,envName:'OTHER'}]})).rejects.toThrow('CanonicalMappingConflict');
 expect((await f.service.list(scope)).revision).toBe(3);
});
it('requires unused shared application, matching name and revision before removal, retaining secret bytes',async()=>{const f=fixture();await f.service.save(scope,'unused',{expectedRevision:0,displayName:'Unused',description:''});f.state(scope).secrets.keep=[newSecret({value:'KEEP'})];await expect(f.service.remove(scope,'unused',{expectedRevision:1,confirmName:'other'})).rejects.toThrow();await expect(f.service.remove(scope,'unused',{expectedRevision:0,confirmName:'unused'})).rejects.toThrow();const result=await f.service.remove(scope,'unused',{expectedRevision:1,confirmName:'unused'});expect(result.applications).toHaveLength(0);expect(f.state(scope).secrets.keep![0]!.value).toBe('KEEP');});
it('blocks removal for references or active consumers and refuses unavailable usage verification',async()=>{const f=fixture();await f.service.save(scope,'unused',{expectedRevision:0,displayName:'Unused',description:''});f.state(scope).runtimeInstances={live:{application:'unused',expiresAt:Date.now()+30000} as any};await expect(f.service.remove(scope,'unused',{expectedRevision:1,confirmName:'unused'})).rejects.toThrow('ApplicationInUse');});
it('counts tenant links and runtime enrollment as usage without returning tenant/resource details',async()=>{const f=fixture();await f.service.save(scope,'custom',{expectedRevision:0,displayName:'Custom',description:''});const tenant={...scope,tenant:'private-tenant'};f.state(tenant).resourceAssociations={'secrets/private-resource':{envName:'PRIVATE_ENV',memberships:{custom:'latest'}}};expect(await f.service.usage(scope,'custom')).toMatchObject({links:1,inUse:true});await expect(f.service.remove(scope,'custom',{expectedRevision:1,confirmName:'custom'})).rejects.toThrow('ApplicationInUse');expect(JSON.stringify(await f.service.usage(scope,'custom'))).not.toContain('private-tenant');await expect(f.service.remove(tenant,'custom',{expectedRevision:0,confirmName:'custom'})).rejects.toThrow('SharedScopeRequired');});
