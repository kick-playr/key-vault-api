import { existsSync } from 'node:fs';
import { bindingDigest, parseSnapshotRequest } from '@kick-playr/local-key-vault/runtime-client';
import { emptyNamespace } from '../src/types.js';
import { vaultName } from '../src/manifest.js';
import { tenantKeySet } from '../src/tenant-key-tree.js';
import { jest } from '@jest/globals';
import { MongoClient } from 'mongodb';
import { MongoStore } from '../src/store.js';

function fixture() {
  const shared = { environment: 'development', tenant: '_shared' }, scope = { environment: 'development', tenant: 'fcrww' };
  const process = emptyNamespace(), tenant = emptyNamespace(), version = '1'.repeat(32);
  const attrs = { enabled: true, created: 1, updated: 1, recoveryLevel: 'Purgeable' as const };
  const metadata = (tags: Record<string, string>) => {
    const item = { version, attributes: { ...attrs }, tags };
    Object.defineProperty(item, 'value', { get() { throw Error('Secret material must never be inspected'); } });
    return item;
  };
  process.secrets[vaultName(shared, 'secret', 'shared-key')] = [metadata({ purpose: 'shared-key', envName: 'SHARED_KEY' })];
  const layout = tenantKeySet(scope, 'workflow-local:fcrww:key');
  for (const entry of layout.entries) tenant.secrets[entry.name] = [metadata({ keySet: layout.reference, keyRole: entry.role, logicalPath: entry.logicalPath, envName: 'CLUB_' + entry.role.toUpperCase() + '_KEY' })];
  let reads = 0;
  const store = { read: async (selected: typeof scope, callback: (ns: typeof tenant) => unknown) => { reads++; return callback(selected.tenant === '_shared' ? process : tenant); } };
  const plan = { schemaVersion: 1, environment: 'development', applications: { 'explorer-api': { bindingRevision: 1, secrets: [{ mapping: 'SHARED_KEY', purpose: 'shared-key' }] } }, tenants: [{ tenant: 'fcrww', bindingRevision: 2, keySets: [{ reference: layout.reference, currentWrappingVersion: 'v1' }], secrets: [] }] };
  return { shared, scope, process, tenant, version, layout, plan, store, reads: () => reads };
}

async function api() {
  expect(existsSync(new URL('../src/runtime-manifest-plan.ts', import.meta.url))).toBe(true);
  return import('../src/runtime-manifest-plan.js');
}
it('pins unambiguous metadata, derives mappings and computes canonical digests without reading secrets', async () => {
  const tool = await api(), f = fixture();
  const result = await tool.createBindings(f.plan, f.store as any);
  expect(f.reads()).toBe(2);
  const app = result.applications['explorer-api']!;
  expect(app.scope).toEqual(f.shared);
  expect(app.request.secrets[0]).toEqual({ mapping: 'SHARED_KEY', purpose: 'shared-key', version: f.version });
  const tenant = result.tenants[0]!;
  expect(tenant.request.bindingRevision).toBe(2);
  expect(tenant.request.keySets[0]).toMatchObject({ reference: f.layout.reference, currentWrappingVersion: 'v1', wrappingVersions: [{ keyVersion: 'v1', vaultVersion: f.version }], mappings: { wrapping: 'CLUB_WRAPPING_KEY', index: 'CLUB_INDEX_KEY', control: 'CLUB_CONTROL_KEY' } });
  for (const entry of [app, tenant]) {
    expect(entry.request.bindingDigest).toBe(bindingDigest(entry.request));
    expect(parseSnapshotRequest(entry.request)).toEqual(entry.request);
  }
  expect(f.process.generation).toBe(0); expect(f.tenant.generation).toBe(0);
  expect(JSON.stringify(result)).not.toContain('value');
});

it('rejects ambiguous or inactive versions and preserves explicit historical application versions', async () => {
  const tool = await api(), f = fixture(), name = f.layout.entries[0]!.name;
  const old = f.tenant.secrets[name]![0]!;
  f.tenant.secrets[name]!.push({ version: '2'.repeat(32), attributes: { ...old.attributes }, tags: { ...old.tags } });
  await expect(tool.createBindings(f.plan, f.store as any)).rejects.toThrow('AmbiguousVersion');
  const plan: any = structuredClone(f.plan);
  plan.tenants[0].keySets[0].currentWrappingVersion = 'rotation-2026';
  plan.tenants[0].keySets[0].wrappingVersions = [{ keyVersion: 'v1', vaultVersion: f.version }, { keyVersion: 'rotation-2026', vaultVersion: '2'.repeat(32) }];
  const result = await tool.createBindings(plan, f.store as any);
  expect(result.tenants[0]!.request.keySets[0]!.wrappingVersions).toHaveLength(2);
  old.attributes.enabled = false;
  await expect(tool.createBindings(plan, f.store as any)).rejects.toThrow('Forbidden');
});

it('rejects malformed, foreign or value-bearing plans before any database reads', async () => {
  const tool = await api();
  for (const mutate of [
    (p: any) => { p.applications['explorer-api'].secrets[0].value = 'secret-canary'; },
    (p: any) => { p.tenants[0].bindingRevision = 0; },
    (p: any) => { p.tenants.push(structuredClone(p.tenants[0])); },
    (p: any) => { p.tenants[0].keySets[0].reference = 'workflow-local:other:key'; },
    (p: any) => { p.applications['explorer-api'].secrets[0].version = 'latest'; },
  ]) {
    const f = fixture(), plan: any = structuredClone(f.plan); mutate(plan);
    await expect(tool.createBindings(plan, f.store as any)).rejects.toThrow();
    expect(f.reads()).toBe(0);
  }
});

it('rejects a missing required resource rather than producing partial manifest metadata', async () => {
  const tool = await api(), f = fixture();
  delete f.tenant.secrets[f.layout.entries[1]!.name];
  await expect(tool.createBindings(f.plan, f.store as any)).rejects.toThrow();
});

it('refuses initializing missing vault metadata while preserving ordinary store initialization', async () => {
  let marker: any = null, inserts = 0;
  const database = { collection: () => ({ findOne: async () => marker, insertOne: async (value: unknown) => { inserts++; marker = value; } }) };
  const connect = jest.spyOn(MongoClient.prototype, 'connect').mockResolvedValue({} as MongoClient);
  const db = jest.spyOn(MongoClient.prototype, 'db').mockReturnValue(database as any);
  const close = jest.spyOn(MongoClient.prototype, 'close').mockResolvedValue(undefined);
  try {
    const config = { mongoUri: 'mongodb://127.0.0.1:1/isolated-metadata-test', masterKey: Buffer.alloc(32, 2) };
    await expect(MongoStore.open(config, { createVerifier: false })).rejects.toThrow('StoreUnavailable');
    expect(inserts).toBe(0);
    const initialized = await MongoStore.open(config);
    await initialized.close();
    expect(inserts).toBe(1);
  } finally { connect.mockRestore(); db.mockRestore(); close.mockRestore(); }
});

it('rejects expanded metadata that exceeds the runtime configuration size limit', async () => {
  const tool = await api();
  const secrets = Array.from({ length: 100 }, (_, i) => ({ mapping: 'M'.repeat(120) + i, purpose: 'p'.repeat(120) + i }));
  const plan = { schemaVersion: 1, environment: 'development', applications: Object.fromEntries(Array.from({ length: 16 }, (_, i) => ['app' + i, { bindingRevision: 1, secrets }])),
    tenants: Array.from({ length: 32 }, (_, i) => ({ tenant: 'club' + i, bindingRevision: 1, keySets: Array.from({ length: 33 }, (_, k) => ({ reference: `set${k}:club${i}:key`, currentWrappingVersion: 'v1' })), secrets: [] })) };
  expect(Buffer.byteLength(JSON.stringify(plan))).toBeLessThan(1024 * 1024);
  const store = { read: async (scope: { environment: string; tenant: string }, callback: (ns: ReturnType<typeof emptyNamespace>) => unknown) => {
    const ns = emptyNamespace(), attributes = { enabled: true, created: 1, updated: 1, recoveryLevel: 'Purgeable' as const };
    if (scope.tenant === '_shared') for (const s of secrets) ns.secrets[vaultName(scope, 'secret', s.purpose)] = [{ version: '1'.repeat(32), attributes }];
    else for (let k = 0; k < 33; k++) for (const part of tenantKeySet(scope, `set${k}:${scope.tenant}:key`).entries) ns.secrets[part.name] = [{ version: '1'.repeat(32), attributes, tags: { keySet: `set${k}:${scope.tenant}:key`, keyRole: part.role, logicalPath: part.logicalPath, envName: 'K'.repeat(115) + k + '_' + part.role.toUpperCase() } }];
    return callback(ns);
  } };
  await expect(tool.createBindings(plan, store as any)).rejects.toThrow('BindingsTooLarge');
});
