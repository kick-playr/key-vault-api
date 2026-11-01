import { randomBytes } from 'node:crypto';
import { fixture, call, token } from './helpers.js';
import { MongoStore } from '../src/store.js';
import { importFcrwwKeys } from '../src/import-fcrww-keys.js';
import { tenantKeySet } from '../src/tenant-key-tree.js';

const scope = { environment: 'dev', tenant: 'a' };
const input = () => ({ WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1: randomBytes(32).toString('base64'), WORKFLOW_REAL_FCRWW_INDEX_KEY: randomBytes(32).toString('base64'), WORKFLOW_REAL_FCRWW_CONTROL_KEY: randomBytes(32).toString('base64') });
describe('tenant key naming and tree', () => {
  it('names scoped key sets deterministically without flattening reference collisions', () => {
    const layout = tenantKeySet(scope, 'workflow-local:a:key');
    expect(layout.reference).toBe('workflow-local:a:key');
    expect(layout.entries.map(e => e.path)).toEqual(['wrapping/v1', 'index', 'control']);
    for (const e of layout.entries) expect(e.name).toMatch(/^[a-zA-Z0-9-]{1,127}$/);
    expect(tenantKeySet(scope, layout.reference)).toEqual(layout);
    expect(tenantKeySet(scope, 'workflow-real:a:key').entries[0]!.name).not.toBe(layout.entries[0]!.name);
    expect(tenantKeySet({ ...scope, environment: 'preview' }, layout.reference).entries[0]!.name).not.toBe(layout.entries[0]!.name);
    expect(() => tenantKeySet(scope, 'workflow-local:b:key')).toThrow('InvalidKeySetName');
    expect(() => tenantKeySet(scope, 'workflow-local:a:secret')).toThrow('InvalidKeySetName');
    expect(() => tenantKeySet(scope, 'workflow/local:a:key')).toThrow('InvalidKeySetName');
  });
  it('exposes the logical tree with exact env mappings and metadata only under list permission', async () => {
    const f = await fixture(), store = await MongoStore.open(f.config);
    const listToken = 'tree-list-only-xxxxxxxxxxxxxxxxxxxxxxxxxxxx';
    const listB = 'tree-list-b-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
    try {
      await f.addGrants([{ ...scope, token: listToken, permissions: ['list'] }, { ...scope, tenant: 'b', token: listB, permissions: ['list'] }]);
      const keys = input(); await importFcrwwKeys(store, scope, token, keys, 'workflow-local:a:key');
      const res = await call(f.app, 'get', '/local/key-tree').set('Authorization', `Bearer ${listToken}`).expect(200);
      expect(res.body).toMatchObject({ ...scope, keySets: [{ name: 'workflow-local:a:key', profile: 'workflow-local' }] });
      const children = res.body.keySets[0].children;
      expect(children[0].name).toBe('wrapping');
      expect(children[0].children[0]).toMatchObject({ name: 'v1', envName: 'WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1' });
      expect(children[1]).toMatchObject({ name: 'index', envName: 'WORKFLOW_REAL_FCRWW_INDEX_KEY' });
      expect(children[2]).toMatchObject({ name: 'control', envName: 'WORKFLOW_REAL_FCRWW_CONTROL_KEY' });
      for (const key of Object.values(keys)) expect(JSON.stringify(res.body)).not.toContain(key);
      expect(JSON.stringify(res.body)).not.toContain('"value"');
      await importFcrwwKeys(store, scope, token, keys, 'workflow-real:a:key');
      const multiple = await call(f.app, 'get', '/local/key-tree').set('Authorization', `Bearer ${listToken}`).expect(200);
      expect(multiple.body.keySets.map((set: { name: string }) => set.name)).toEqual(['workflow-local:a:key', 'workflow-real:a:key']);
      await call(f.app, 'get', '/local/key-tree').expect(403);
      await call(f.app, 'get', '/local/key-tree', 'b').expect(403);
      const empty = await call(f.app, 'get', '/local/key-tree', 'b').set('Authorization', `Bearer ${listToken}`);
      expect(empty.status).toBe(403);
      const isolated = await call(f.app, 'get', '/local/key-tree', 'b').set('Authorization', `Bearer ${listB}`).expect(200);
      expect(isolated.body).toEqual({ environment: 'dev', tenant: 'b', keySets: [] });
      await call(f.app, 'get', '/local/key-tree').set('Authorization', 'Bearer invalid').expect(401);
      await call(f.app, 'get', '/namespaces/dev/b/local/key-tree').set('Authorization', `Bearer ${listToken}`).expect(403);
    } finally { await store.close(); await f.cleanup(); }
  });
});
