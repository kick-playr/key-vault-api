import { randomBytes } from 'node:crypto';
import { fixture, token } from './helpers.js';
import { MongoStore } from '../src/store.js';
import { tenantKeySet } from '../src/tenant-key-tree.js';
import { VaultService } from '../src/vault.js';
import { importFcrwwKeys, promptFcrwwKeys, confirmFcrwwKeys, promptKeySetName } from '../src/import-fcrww-keys.js';

const scope = { environment: 'dev', tenant: 'a' };
const layout = tenantKeySet(scope, 'workflow-local:a:key');
const values = () => ({
  WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1: randomBytes(32).toString('base64'),
  WORKFLOW_REAL_FCRWW_INDEX_KEY: randomBytes(32).toString('base64'),
  WORKFLOW_REAL_FCRWW_CONTROL_KEY: randomBytes(32).toString('base64'),
});
describe('FCRWW key import', () => {
  let f: Awaited<ReturnType<typeof fixture>>, store: MongoStore, vault: VaultService;
  beforeEach(async () => { f = await fixture(); store = await MongoStore.open(f.config); vault = new VaultService(store, f.config.baseUrl); });
  afterEach(async () => { await store.close(); await f.cleanup(); });
  it('asks for the key-set name and rejects another tenant before asking for values', async () => {
    expect(await promptKeySetName(scope, async label => { expect(label).toContain('workflow-local:a:key'); return 'workflow-local:a:key'; })).toBe('workflow-local:a:key');
    await expect(promptKeySetName(scope, async () => 'workflow-local:b:key')).rejects.toThrow('InvalidKeySetName');
  });
  it('collects the three keys from explicit prompts without reading environment values', async () => {
    const expected = values(), labels: string[] = [], answers = Object.values(expected);
    const entered = await promptFcrwwKeys(async (label: string) => { labels.push(label); return answers[labels.length - 1]!; });
    expect(labels).toHaveLength(3);
    expect(labels[0]).toContain('wrapping'); expect(labels[1]).toContain('index'); expect(labels[2]).toContain('control');
    expect(entered).toEqual(expected);
  });
  it('shows exactly the final three characters per key before accepting confirmation', async () => {
    const input = values(), lines: string[] = [];
    await confirmFcrwwKeys(input, scope, async label => {
      expect(lines).toEqual([
        `workflow-local:a:key/wrapping/v1 -> WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1: ...${input.WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1.slice(-3)}`,
        `workflow-local:a:key/index -> WORKFLOW_REAL_FCRWW_INDEX_KEY: ...${input.WORKFLOW_REAL_FCRWW_INDEX_KEY.slice(-3)}`,
        `workflow-local:a:key/control -> WORKFLOW_REAL_FCRWW_CONTROL_KEY: ...${input.WORKFLOW_REAL_FCRWW_CONTROL_KEY.slice(-3)}`,
      ]);
      expect(label).toContain('dev/a'); return 'yes';
    }, line => { lines.push(line); });
    for (const key of Object.values(input)) expect(lines.join('')).not.toContain(key.slice(0, -3));
  });
  it('cancels before import without explicit yes and validates keys before showing suffixes', async () => {
    const input = values(), lines: string[] = [];
    for (const answer of ['', 'no', 'y']) {
      const run = async () => {
        await confirmFcrwwKeys(input, scope, async () => answer, line => { lines.push(line); });
        return importFcrwwKeys(store, scope, token, input);
      };
      await expect(run()).rejects.toThrow('InputCancelled');
      expect(await store.read(scope, ns => ns)).toBeUndefined();
    }
    lines.length = 0;
    await expect(confirmFcrwwKeys({ ...input, WORKFLOW_REAL_FCRWW_INDEX_KEY: 'invalid' }, scope, async () => 'yes', line => { lines.push(line); })).rejects.toThrow('InvalidImportKeys');
    expect(lines).toEqual([]);
  });
  it('preserves all original key strings, returns metadata only and does not rotate on repeat import', async () => {
    const input = values();
    const result = await importFcrwwKeys(store, scope, token, input);
    expect(result.imported).toBe(3); expect(result.skipped).toBe(0);
    for (const v of Object.values(input)) expect(JSON.stringify(result)).not.toContain(v);
    expect((await vault.get(scope, 'secrets', layout.entries[0]!.name)).value).toBe(input.WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1);
    expect((await vault.get(scope, 'secrets', layout.entries[1]!.name)).value).toBe(input.WORKFLOW_REAL_FCRWW_INDEX_KEY);
    expect((await vault.get(scope, 'secrets', layout.entries[2]!.name)).value).toBe(input.WORKFLOW_REAL_FCRWW_CONTROL_KEY);
    const before = await store.read(scope, ns => ns);
    expect(await importFcrwwKeys(store, scope, token, input)).toMatchObject({ imported: 0, skipped: 3 });
    expect(await store.read(scope, ns => ns)).toEqual(before);
  });
  it('rejects malformed, missing or reused keys before writing any secret', async () => {
    const good = values();
    for (const input of [{ ...good, WORKFLOW_REAL_FCRWW_INDEX_KEY: '' }, { ...good, WORKFLOW_REAL_FCRWW_INDEX_KEY: 'secret-canary-invalid' }, { ...good, WORKFLOW_REAL_FCRWW_INDEX_KEY: good.WORKFLOW_REAL_FCRWW_CONTROL_KEY }]) {
      await expect(importFcrwwKeys(store, scope, token, input)).rejects.toThrow('InvalidImportKeys');
    }
    expect(await store.read(scope, ns => ns)).toBeUndefined();
  });
  it('requires the correct grant and both read/write permissions without writing on failure', async () => {
    const input = values(), reader = 'import-reader-xxxxxxxxxxxxxxxxxxxxxxxxxxxx';
    await f.addGrants([{ token: reader, ...scope, permissions: ['read'] }]);
    await expect(importFcrwwKeys(store, scope, reader, input)).rejects.toThrow('Forbidden');
    await expect(importFcrwwKeys(store, scope, 'invalid', input)).rejects.toThrow('Unauthorized');
    await expect(importFcrwwKeys(store, { ...scope, tenant: 'b' }, token, input)).rejects.toThrow('Forbidden');
    expect(await store.read(scope, ns => ns)).toBeUndefined();
  });
  it('refuses conflicting existing values atomically and preserves the original state', async () => {
    await vault.create(scope, 'secrets', layout.entries[1]!.name, { value: 'existing-canary' });
    const before = await store.read(scope, ns => ns);
    await expect(importFcrwwKeys(store, scope, token, values())).rejects.toThrow('ImportConflict');
    expect(await store.read(scope, ns => ns)).toEqual(before);
  });
  it('does not reactivate disabled or deleted target secrets', async () => {
    const input = values();
    await vault.create(scope, 'secrets', layout.entries[1]!.name, { value: input.WORKFLOW_REAL_FCRWW_INDEX_KEY, attributes: { enabled: false } });
    let before = await store.read(scope, ns => ns);
    await expect(importFcrwwKeys(store, scope, token, input)).rejects.toThrow('ImportConflict');
    expect(await store.read(scope, ns => ns)).toEqual(before);
    await vault.delete(scope, 'secrets', layout.entries[1]!.name);
    before = await store.read(scope, ns => ns);
    await expect(importFcrwwKeys(store, scope, token, input)).rejects.toThrow('ImportConflict');
    expect(await store.read(scope, ns => ns)).toEqual(before);
  });
  it('imports concurrent identical requests without generating extra versions', async () => {
    const input = values(), second = await MongoStore.open(f.config);
    try {
      const results = await Promise.all([importFcrwwKeys(store, scope, token, input), importFcrwwKeys(second, scope, token, input)]);
      expect(results.reduce((n, r) => n + r.imported, 0)).toBe(3);
      const counts = await store.read(scope, ns => Object.values(ns!.secrets).map(versions => versions.length));
      expect(counts).toEqual([1, 1, 1]);
    } finally { await second.close(); }
  });

});
