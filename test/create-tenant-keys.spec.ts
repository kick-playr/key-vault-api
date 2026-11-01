import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, token } from './helpers.js';
import { MongoStore } from '../src/store.js';
import { VaultService } from '../src/vault.js';
import { createTenantKeys, promptTenantKeySetup, parseTenantKeyArgs, collectTenantKeyValues } from '../src/create-tenant-keys.js';

const scope = { environment: 'dev', tenant: 'a' }, reference = 'workflow-local:a:key';
const names = ['CUSTOM_WRAPPING_KEY_V1', 'CUSTOM_INDEX_KEY', 'CUSTOM_CONTROL_KEY'] as const;
describe('new tenant key creation', () => {
  let f: Awaited<ReturnType<typeof fixture>>, store: MongoStore;
  beforeEach(async () => { f = await fixture(); store = await MongoStore.open(f.config); });
  afterEach(async () => { await store.close(); await f.cleanup(); });
  it('asks only for scope and key-set name, deriving all three env mappings automatically', async () => {
    const answers = ['development', 'fcrww', 'workflow-local:fcrww:key'], labels: string[] = [];
    const setup = await promptTenantKeySetup(async label => { labels.push(label); return answers[labels.length - 1]!; });
    expect(labels).toHaveLength(3);
    expect(setup).toEqual({ scope: { environment: 'development', tenant: 'fcrww' }, reference: 'workflow-local:fcrww:key', envNames: [
      'WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1', 'WORKFLOW_REAL_FCRWW_INDEX_KEY', 'WORKFLOW_REAL_FCRWW_CONTROL_KEY',
    ] });
  });
  it('accepts metadata parameters but asks for the tenant and key values when missing', async () => {
    const options = parseTenantKeyArgs(['--environment', 'dev', '--name', reference]);
    const metadataLabels: string[] = [];
    const setup = await promptTenantKeySetup(async label => { metadataLabels.push(label); return 'a'; }, options);
    expect(setup.scope).toEqual(scope); expect(setup.reference).toBe(reference);
    expect(metadataLabels).toHaveLength(1); expect(metadataLabels[0]).toContain('Tenant');
    const labels: string[] = [];
    const entered = await collectTenantKeyValues(names, options, async label => { labels.push(label); return 'entered-'+labels.length; });
    expect(entered).toEqual({ CUSTOM_WRAPPING_KEY_V1: 'entered-1', CUSTOM_INDEX_KEY: 'entered-2', CUSTOM_CONTROL_KEY: 'entered-3' });
    expect(labels).toHaveLength(3);
    expect(() => parseTenantKeyArgs(['--wrapping-key', 'private-canary'])).toThrow('InvalidCommand');
    expect(() => parseTenantKeyArgs(['--generate', '--env-file', '.env'])).toThrow('InvalidCommand');
    expect(() => parseTenantKeyArgs(['--tenant'])).toThrow('InvalidCommand');
  });
  it('reads keys only from an explicitly selected dotenv and prompts for missing entries without changing the file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'tenant-keys-env-'));
    try {
      const file = join(dir, '.env'), content = `${names[0]}='file-value'\n${names[1]}=\nUNRELATED=ignored\n`;
      await writeFile(file, content);
      const labels: string[] = [];
      const entered = await collectTenantKeyValues(names, parseTenantKeyArgs(['--env-file', file]), async label => { labels.push(label); return 'prompted-'+labels.length; });
      expect(entered).toEqual({ CUSTOM_WRAPPING_KEY_V1: 'file-value', CUSTOM_INDEX_KEY: 'prompted-1', CUSTOM_CONTROL_KEY: 'prompted-2' });
      expect(labels).toHaveLength(2); expect(labels[0]).toContain('INDEX');
      expect(await readFile(file, 'utf8')).toBe(content);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
  it('persists supplied values exactly instead of generating replacements', async () => {
    const values = Object.fromEntries(names.map((name, index) => [name, Buffer.alloc(32, index + 1).toString('base64')]));
    const result = await createTenantKeys(store, scope, token, reference, names, async entered => { expect(entered).toEqual(values); }, values);
    const vault = new VaultService(store, f.config.baseUrl);
    for (const leaf of result.secrets) expect((await vault.get(scope, 'secrets', leaf.name)).value).toBe(values[leaf.envName]);
  });
  it('rejects invalid supplied key values before confirmation or writes', async () => {
    await expect(createTenantKeys(store, scope, token, reference, names, async () => { throw new Error('Unexpected confirmation'); }, { CUSTOM_WRAPPING_KEY_V1: 'invalid' })).rejects.toThrow('InvalidImportKeys');
    expect(await store.read(scope, ns => ns)).toBeUndefined();
  });
  it('generates distinct 256-bit keys, confirms before commit and persists mappings without printing full values', async () => {
    let generated: NodeJS.ProcessEnv = {};
    const result = await createTenantKeys(store, scope, token, reference, names, async values => {
      expect(await store.read(scope, ns => ns)).toBeUndefined(); generated = values;
      const raw = names.map(name => Buffer.from(values[name]!, 'base64'));
      expect(raw.every(key => key.length === 32)).toBe(true);
      expect(new Set(raw.map(key => key.toString('hex'))).size).toBe(3);
    });
    expect(result.created).toBe(3);
    const vault = new VaultService(store, f.config.baseUrl);
    for (const leaf of result.secrets) {
      const saved = await vault.get(scope, 'secrets', leaf.name);
      expect(saved.value).toBe(generated[leaf.envName]);
      expect(saved.tags).toMatchObject({ envName: leaf.envName, keySet: reference });
      expect(JSON.stringify(result)).not.toContain(generated[leaf.envName]!);
    }
  });
  it('refuses existing key sets and invalid mappings without changing committed keys', async () => {
    await createTenantKeys(store, scope, token, reference, names, async () => {});
    const before = await store.read(scope, ns => ns);
    await expect(createTenantKeys(store, scope, token, reference, names, async () => {})).rejects.toThrow('KeySetAlreadyExists');
    await expect(createTenantKeys(store, scope, token, reference, ['SAME', 'SAME', 'OTHER'], async () => {})).rejects.toThrow('InvalidKeyMappings');
    await expect(createTenantKeys(store, scope, token, reference, ['NEXT_PUBLIC_KEY', 'INDEX_KEY', 'CONTROL_KEY'], async () => {})).rejects.toThrow('InvalidKeyMappings');
    expect(await store.read(scope, ns => ns)).toEqual(before);
  });
  it('does not create keys on cancelled confirmation or insufficient/wrong namespace grants', async () => {
    await expect(createTenantKeys(store, scope, token, reference, names, async () => { throw new Error('InputCancelled'); })).rejects.toThrow('InputCancelled');
    await f.addGrants([{ ...scope, token: 'creation-readonly-xxxxxxxxxxxxxxxxxxxxxxxx', permissions: ['read'] }]);
    await expect(createTenantKeys(store, scope, 'creation-readonly-xxxxxxxxxxxxxxxxxxxxxxxx', reference, names, async () => {})).rejects.toThrow('Forbidden');
    await expect(createTenantKeys(store, { ...scope, tenant: 'b' }, token, 'workflow-local:b:key', names, async () => {})).rejects.toThrow('Forbidden');
    expect(await store.read(scope, ns => ns)).toBeUndefined();
  });
  it('permits only one concurrent creation of a named key set', async () => {
    const second = await MongoStore.open(f.config);
    try {
      const results = await Promise.allSettled([createTenantKeys(store, scope, token, reference, names, async () => {}), createTenantKeys(second, scope, token, reference, names, async () => {})]);
      expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
      expect((results.find(r => r.status === 'rejected') as PromiseRejectedResult).reason.message).toBe('KeySetAlreadyExists');
      expect(await store.read(scope, ns => Object.values(ns!.secrets).map(v => v.length))).toEqual([1, 1, 1]);
    } finally { await second.close(); }
  });
});
