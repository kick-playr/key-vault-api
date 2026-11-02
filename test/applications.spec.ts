import { ApplicationsService } from '../src/applications.js';
import { emptyNamespace, type Scope, type Namespace } from '../src/types.js';
import { newSecret } from '../src/vault.js';
const scope = { environment: 'development', tenant: '_shared' };
function fixture() {
  const states = new Map<string, Namespace>();
  const state = (s: Scope) => { const id = JSON.stringify(s); if (!states.has(id)) states.set(id, emptyNamespace()); return states.get(id)!; };
  const store = { read: async (s: Scope, fn: any) => structuredClone(fn(structuredClone(state(s)))), transaction: async (s: Scope, fn: any) => {
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
  const store = { readGrants: async () => [grant], read: async (_: unknown, fn: any) => structuredClone(fn(structuredClone(ns))), transaction: async (_: unknown, fn: any) => { const copy = structuredClone(ns); const result = await fn(copy); Object.assign(ns, copy); return structuredClone(result); }, appendAudit: async (event: unknown) => { events.push(event); }, close: async () => {} };
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
    grant.permissions = ['list'];
    await call('put', '/local/applications/club-api').send({ expectedRevision: 2, displayName: 'Changed' }).expect(403);
    grant.permissions = ['write'];
    await call('get').expect(403);
    grant.permissions = ['list', 'write'];
    await call('delete', '/local/applications/club-api/resources/secrets/database').send({ expectedRevision: 2 }).expect(200);
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
  const call=()=>request(app.getHttpServer()).put('/local/applications/club-api/resources/secrets/local').set('Authorization',`Bearer ${tenantToken}`).set('x-vault-environment','development').set('x-vault-tenant','club');
  try {
    const body={expectedRevision:0,envName:'LOCAL_KEY',version:'latest'};
    await call().send(body).expect(403);
    await call().set('x-vault-catalog-token',catalogToken).send(body).expect(200);
    await call().set('x-vault-tenant','another').set('x-vault-catalog-token',catalogToken).send(body).expect(403);
  } finally {await app.close();}
});
it.each(['LOCAL_KEYVAULT_AUTH_JSON','SECRETS_KEYS_STRATEGY','NODE_OPTIONS','NEXT_PUBLIC_KEY'])('never models runtime bootstrap variable %s as a secret mapping', async mapping=>{
  const f=fixture(); f.state(scope).secrets['bootstrap']=[newSecret({value:'private'})];
  await f.service.save(scope,'club-api',{expectedRevision:0,displayName:'Club',description:''});
  await expect(f.service.link(scope,'club-api','secrets','bootstrap',{expectedRevision:1,envName:mapping,version:'latest'})).rejects.toThrow();
});
