import { bindingDigest } from '@kick-playr/local-key-vault/runtime-client';
import { RuntimeManifestService, validatedManifest } from '../src/runtime-manifests.js';
import { auditOperation } from '../src/audit.js';
import { emptyNamespace } from '../src/types.js';

const scope = { environment: 'development', tenant: '_shared' };
function manifest(revision = 1) {
  const body = { schemaVersion: 1 as const, bindingRevision: revision, keySets: [], secrets: [{ mapping: 'SHARED_KEY', purpose: 'shared-key', version: '1'.repeat(32) }] };
  return { schemaVersion: 1 as const, application: 'explorer-api', scope, request: { ...body, bindingDigest: bindingDigest(body) }, tenants: [] };
}
function fixture() {
  let ns = emptyNamespace();
  let writes = 0;
  const store = { read: async (_: unknown, fn: any) => structuredClone(fn(JSON.parse(JSON.stringify(ns)))), transaction: async (_: unknown, fn: any) => {
    const copy = JSON.parse(JSON.stringify(ns)); const result = fn(copy); ns = copy; writes++; return structuredClone(result);
  } };
  return { service: new RuntimeManifestService(store as any), writes: () => writes };
}
it('retains pinned history and never rolls current backward on an idempotent retry', async () => {
  const f = fixture();
  await f.service.publish(scope, 'explorer-api', manifest());
  await f.service.publish(scope, 'explorer-api', manifest(3));
  await f.service.publish(scope, 'explorer-api', manifest());
  expect((await f.service.get(scope, 'explorer-api')).request.bindingRevision).toBe(3);
  expect((await f.service.get(scope, 'explorer-api', '1')).request.bindingRevision).toBe(1);
  await expect(f.service.publish(scope, 'explorer-api', manifest(2))).rejects.toThrow('ManifestConflict');
});
it('rejects changed revision contents, scope mismatch, private fields and oversize before writes', async () => {
  const f = fixture(); await f.service.publish(scope, 'explorer-api', manifest());
  const changed = manifest(); changed.tenants = [{ tenant: 'club', bindingRevision: 1, bindingDigest: 'a'.repeat(64) }] as any;
  await expect(f.service.publish(scope, 'explorer-api', changed)).rejects.toThrow('ManifestConflict');
  await expect(f.service.publish({ ...scope, tenant: 'other' }, 'explorer-api', manifest())).rejects.toThrow('Forbidden');
  await expect(f.service.publish(scope, 'other-api', manifest())).rejects.toThrow('Forbidden');
  await expect(f.service.publish(scope, 'explorer-api', { ...manifest(), value: 'PRIVATE_CANARY' })).rejects.toThrow('InvalidRuntimeManifest');
  expect(() => validatedManifest({ ...manifest(), value: 'x'.repeat(65536) })).toThrow('ManifestTooLarge');
  expect(f.writes()).toBe(1);
  await expect(f.service.get(scope, 'explorer-api', '0')).rejects.toThrow('InvalidRuntimeManifest');
  await expect(f.service.get(scope, 'missing')).rejects.toThrow('ManifestNotFound');
});
it('audits manifest routes without copying path canaries or bodies', () => {
  expect(auditOperation('GET', '/local/runtime-manifests/PRIVATE_CANARY/1')).toEqual({ category: 'read', action: 'local.runtime-manifests.get' });
  expect(auditOperation('PUT', '/namespaces/dev/_shared/local/runtime-manifests/explorer-api')).toEqual({ category: 'write', action: 'local.runtime-manifests.publish' });
});

it('enforces existing scoped bearer auth, read/write permissions and safe bounded bodies over HTTP', async () => {
  const { jest } = await import('@jest/globals');
  const { default: request } = await import('supertest');
  const { createHash, randomBytes } = await import('node:crypto');
  const { MongoStore } = await import('../src/store.js');
  const { createApp } = await import('../src/app.js');
  const token = 'manifest-fixture-token-aaaaaaaaaaaaaaaa';
  const ns = emptyNamespace();
  const grants = [{ id: 'a'.repeat(64), tokenHash: createHash('sha256').update(token).digest('hex'), ...scope, permissions: ['read', 'write'], enabled: true }];
  const events: unknown[] = [];
  const store = { readGrants: async () => grants, read: async (_: unknown, fn: any) => structuredClone(fn(JSON.parse(JSON.stringify(ns)))), transaction: async (_: unknown, fn: any) => structuredClone(fn(ns)), appendAudit: async (event: unknown) => { events.push(event); }, close: async () => {} };
  const spy = jest.spyOn(MongoStore, 'open').mockResolvedValue(store as any);
  const app = await createApp({ mongoUri: 'mongodb://127.0.0.1:1/fixture', masterKey: randomBytes(32), baseUrl: 'http://127.0.0.1:4000', audit: { read: 'collection', write: 'collection', list: 'off', crypto: 'off' } });
  spy.mockRestore(); await app.init();
  const call = (method: 'get' | 'put', path = '/local/runtime-manifests/explorer-api') => request(app.getHttpServer())[method](path).set('Authorization', `Bearer ${token}`).set('x-vault-environment', scope.environment).set('x-vault-tenant', scope.tenant);
  try {
    await call('put').send(manifest()).expect(200);
    await call('get').expect(200);
    await call('get', '/local/runtime-manifests/explorer-api/1').expect(200);
    await call('get').set('Authorization', 'Bearer invalid-private-canary').expect(401);
    await call('get').set('x-vault-tenant', 'other').expect(403);
    grants[0]!.permissions = ['read'];
    await call('put').send(manifest(2)).expect(403);
    grants[0]!.permissions = ['write'];
    await call('get').expect(403);
    grants[0]!.permissions = ['read', 'write'];
    const bad = await call('put').send({ ...manifest(), privateKey: 'PRIVATE_CANARY' }).expect(400);
    expect(JSON.stringify(bad.body)).not.toContain('PRIVATE_CANARY');
    await call('put').send({ ...manifest(), privateKey: 'x'.repeat(65536) }).expect(413);
    await call('get', '/secrets/missing?api-version=2025-07-01').expect(404);
    // Walk the real client -> HTTP auth/routes -> pinned snapshot seam with an
    // isolated store, rather than replacing the manifest/snapshot service.
    const { createSecretsRuntime } = await import('@kick-playr/local-key-vault/runtime-client');
    const { vaultName } = await import('../src/manifest.js');
    ns.secrets[vaultName(scope, 'secret', 'shared-key')] = [{ version: '1'.repeat(32), attributes: { enabled: true, created: 1, updated: 1, recoveryLevel: 'Purgeable' }, value: 'INTEGRATION_VALUE_CANARY', tags: { purpose: 'shared-key', envName: 'SHARED_KEY' } }];
    const methods: string[] = [];
    const runtime = createSecretsRuntime({ environment: { NODE_ENV: 'development', SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT', LOCAL_KEYVAULT_AUTH_JSON: JSON.stringify({ schemaVersion: 1, grants: [{ ...scope, token }] }) }, fetch: async (url, options) => {
      methods.push(options?.method ?? 'GET');
      const method = options?.method === 'POST' ? 'post' : 'get';
      let query = request(app.getHttpServer())[method](new URL(String(url)).pathname).set(options?.headers as Record<string, string>);
      if (options?.body) query = query.send(JSON.parse(options.body as string));
      const result = await query;
      return Response.json(result.body, { status: result.status });
    } });
    try {
      const loaded = await runtime.loadProcess('explorer-api', { allowedMappings: ['SHARED_KEY'], requiredMappings: ['SHARED_KEY'] });
      expect(loaded.mappings.SHARED_KEY).toBe('INTEGRATION_VALUE_CANARY');
      expect(methods).toEqual(['GET', 'POST']);
    } finally { runtime.close(); }
    await app.close();
    expect(JSON.stringify(events)).not.toContain('PRIVATE_CANARY');
    expect(JSON.stringify(events)).not.toContain('INTEGRATION_VALUE_CANARY');
    expect(JSON.stringify(events)).not.toContain(token);
  } finally { await app.close(); }
});

it('publisher reads metadata only, validates before writes and publishes tenant history before the atomic app batch', async () => {
  const { publishBindings } = await import('../src/publish-key-vault-bindings-cli.js');
  const { vaultName } = await import('../src/manifest.js');
  const shared = emptyNamespace(), tenant = emptyNamespace();
  const tenantScope = { ...scope, tenant: 'club' };
  const metadata = (purpose: string, envName: string) => {
    const v = { version: '1'.repeat(32), attributes: { enabled: true, created: 1, updated: 1, recoveryLevel: 'Purgeable' as const }, tags: { purpose, envName } };
    Object.defineProperty(v, 'value', { enumerable: true, get() { throw Error('PRIVATE_CANARY'); } });
    return v;
  };
  shared.secrets[vaultName(scope, 'secret', 'shared-key')] = [metadata('shared-key', 'SHARED_KEY')];
  tenant.secrets[vaultName(tenantScope, 'secret', 'tenant-key')] = [metadata('tenant-key', 'TENANT_KEY')];
  const writes: string[] = [];
  const store = { read: async (s: typeof scope, fn: any) => fn(s.tenant === '_shared' ? shared : tenant), transaction: async (s: typeof scope, fn: any) => { writes.push(s.tenant); return fn(s.tenant === '_shared' ? shared : tenant); } };
  const plan = { schemaVersion: 1, environment: scope.environment, applications: { 'explorer-api': { bindingRevision: 1, secrets: [{ mapping: 'SHARED_KEY', purpose: 'shared-key' }] }, 'other-api': { bindingRevision: 1, secrets: [{ mapping: 'SHARED_KEY', purpose: 'shared-key' }] } }, tenants: [{ tenant: 'club', bindingRevision: 1, secrets: [{ mapping: 'TENANT_KEY', purpose: 'tenant-key' }] }] };
  expect(await publishBindings(plan, store as any)).toEqual({ applications: 2, tenants: 1 });
  expect(writes).toEqual(['club', '_shared']);
  const current = shared.runtimeManifests!['explorer-api']!.versions['1']!;
  expect(current.tenants).toEqual([{ tenant: 'club', bindingRevision: 1, bindingDigest: tenant.runtimeManifests!['explorer-api']!.versions['1']!.request.bindingDigest }]);
  expect(Object.keys(shared.runtimeManifests!)).toHaveLength(2);
  writes.length = 0;
  const changed = structuredClone(plan); changed.tenants[0]!.bindingRevision = 2;
  await expect(publishBindings(changed, store as any)).rejects.toThrow('ManifestConflict');
  expect(writes).toEqual([]);
});
