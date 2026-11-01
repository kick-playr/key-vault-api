import { jest } from '@jest/globals';
import request from 'supertest';
import { createHash } from 'node:crypto';
import { createApp } from '../src/app.js';
import { MongoStore } from '../src/store.js';
import { RuntimeSnapshotService } from '../src/runtime-snapshot.js';
import { VaultService, newSecret } from '../src/vault.js';
import { tenantKeySet } from '../src/tenant-key-tree.js';
import { emptyNamespace } from '../src/types.js';
import { vaultName } from '../src/manifest.js';
import { bindingDigest } from '@kick-playr/local-key-vault/runtime-client';
import type { RuntimeSnapshotRequest } from '@kick-playr/local-key-vault/runtime-client';
const scope = { environment: 'development', tenant: 'club' };
function fixture() {
  const ns = emptyNamespace(); ns.generation = 4;
  const layout = tenantKeySet(scope, 'workflow-local:club:key');
  const mappings = { wrapping: 'CLUB_WRAPPING_KEY_V1', index: 'CLUB_INDEX_KEY', control: 'CLUB_CONTROL_KEY' };
  const versions = layout.entries.map(e => {
    const item = newSecret({ value: Buffer.alloc(32, e.role === 'wrapping' ? 1 : e.role === 'index' ? 2 : 3).toString('base64'), tags: { keySet: layout.reference, keyRole: e.role, logicalPath: e.logicalPath, envName: mappings[e.role] } });
    ns.secrets[e.name] = [item]; return item.version;
  });
  const request: RuntimeSnapshotRequest = { schemaVersion: 1, bindingRevision: 2, bindingDigest: '', keySets: [{ reference: layout.reference, mappings, wrappingVersions: [{ keyVersion: 'v1', vaultVersion: versions[0]! }], currentWrappingVersion: 'v1', indexVersion: versions[1]!, controlVersion: versions[2]! }], secrets: [] };
  request.bindingDigest = bindingDigest(request);
  let reads = 0;
  const store = { read: async (_: unknown, fn: (v: typeof ns) => unknown) => { reads++; return structuredClone(fn(structuredClone(ns))); }, transaction: () => { throw Error('write forbidden'); } };
  const service = new RuntimeSnapshotService(new VaultService(store as any, 'http://127.0.0.1:4000'));
  return { ns, service, store, request, layout, reads: () => reads };
}
describe('read-only pinned runtime snapshot', () => {
  it('returns all exact key versions using one namespace read and no mutations', async () => {
    const f = fixture(), before = structuredClone(f.ns);
    const snapshot = await f.service.snapshot(scope, f.request);
    expect(f.reads()).toBe(1); expect(f.ns).toEqual(before);
    expect(snapshot).toMatchObject({ schemaVersion: 1, ...scope, bindingRevision: 2, generation: 4, bindingDigest: f.request.bindingDigest });
    expect(snapshot.keySets[0]!.wrappingVersions[0]).toMatchObject({ keyVersion: 'v1', vaultVersion: f.request.keySets[0]!.wrappingVersions[0]!.vaultVersion });
  });
  it('keeps historical wrapping versions pinned across a newer concurrent rotation', async () => {
    const f = fixture(), name = f.layout.entries[0]!.name;
    f.ns.secrets[name]!.push(newSecret({ tags: f.ns.secrets[name]![0]!.tags, value: Buffer.alloc(32, 9).toString('base64') }));
    const snapshot = await f.service.snapshot(scope, f.request);
    expect(snapshot.keySets[0]!.wrappingVersions[0]!.value).toBe(Buffer.alloc(32, 1).toString('base64'));
  });
  it('fails the entire set on a disabled historical version or mapping mismatch', async () => {
    const f = fixture(); f.ns.secrets[f.layout.entries[0]!.name]![0]!.attributes.enabled = false;
    await expect(f.service.snapshot(scope, f.request)).rejects.toMatchObject({ status: 403 });
    const g = fixture(); g.ns.secrets[g.layout.entries[1]!.name]![0]!.tags!.envName = 'OTHER_KEY';
    await expect(g.service.snapshot(scope, g.request)).rejects.toMatchObject({ status: 409 });
  });
  it('reads ordinary process secrets by their existing purpose name and exact version without reconciliation', async () => {
    const f = fixture(), item = newSecret({ value: 'test-database-credential', tags: { purpose: 'database' } });
    f.ns.secrets[vaultName(scope, 'secret', 'database')] = [item];
    f.request.secrets.push({ mapping: 'DATABASE_CREDENTIAL', purpose: 'database', version: item.version });
    f.request.bindingDigest = bindingDigest(f.request);
    const result = await f.service.snapshot(scope, f.request);
    expect(result.secrets).toEqual([{ ...f.request.secrets[0], value: item.value, attributes: item.attributes }]);
    expect(f.reads()).toBe(1);
    item.attributes.exp = 1;
    await expect(f.service.snapshot(scope, f.request)).rejects.toMatchObject({ status: 403 });
    delete f.ns.secrets[vaultName(scope, 'secret', 'database')];
    await expect(f.service.snapshot(scope, f.request)).rejects.toMatchObject({ status: 404 });
  });
  it('rejects latest selectors, unknown fields, duplicate mappings and bad digest before reads', async () => {
    const f = fixture();
    for (const change of [ { ...f.request, extra: 1 }, { ...f.request, bindingDigest: 'a'.repeat(64) }, { ...f.request, keySets: [{ ...f.request.keySets[0], indexVersion: 'latest' }] } ]) {
      await expect(f.service.snapshot(scope, change)).rejects.toMatchObject({ status: 400 });
    }
    expect(f.reads()).toBe(0);
  });
});

it('exposes read-only HTTP and namespace aliases under exact read grant without list/write', async () => {
  const f = fixture(), token = 'test-only-reader-xxxxxxxxxxxxxxxxxxxxxxxxx';
  const store = Object.assign(f.store, {
    readGrants: async () => [{ ...scope, id: 'fixture', tokenHash: createHash('sha256').update(token).digest('hex'), enabled: true, permissions: ['read'] }],
    close: async () => undefined,
  });
  const spy = jest.spyOn(MongoStore, 'open').mockResolvedValue(store as any);
  const app = await createApp({ mongoUri: 'mongodb://127.0.0.1/test_fixture', masterKey: Buffer.alloc(32, 7), baseUrl: 'http://127.0.0.1:4000' });
  try {
    await app.init();
    const call = (path: string, tenant = scope.tenant) => request(app.getHttpServer()).post(path).set('Host', '127.0.0.1:4000').set('Authorization', `Bearer ${token}`).set('x-vault-environment', scope.environment).set('x-vault-tenant', tenant).send(f.request);
    const response = await call('/local/runtime-snapshot').expect(200);
    expect(response.headers['cache-control']).toBe('no-store'); expect(response.body.tenant).toBe(scope.tenant);
    await call('/namespaces/development/club/local/runtime-snapshot').expect(200);
    await request(app.getHttpServer()).post('/local/runtime-snapshot').set('Host', '127.0.0.1:4000').set('Authorization', `Bearer ${token}`).set('x-vault-environment', scope.environment).set('x-vault-tenant', scope.tenant).set('Content-Type', 'application/json').send(' '.repeat(65536) + JSON.stringify(f.request)).expect(413);
    await call('/local/runtime-snapshot', 'other').expect(403);
    await call('/namespaces/development/other/local/runtime-snapshot').expect(403);
    await request(app.getHttpServer()).post('/local/runtime-snapshot').set('Host', '127.0.0.1').expect(401);
    const doc = await request(app.getHttpServer()).get('/docs-json').set('Host', '127.0.0.1').expect(200);
    expect(doc.body.paths['/local/runtime-snapshot'].post.requestBody.content['application/json'].schema.$ref).toBe('#/components/schemas/RuntimeSnapshotRequest');
    expect(doc.body.paths['/local/runtime-snapshot'].post.parameters.some((p: any) => p.name === 'api-version')).toBe(false);
  } finally { await app.close(); spy.mockRestore(); }
});
