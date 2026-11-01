import { mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { EncryptedStore } from '../src/store';

describe('encrypted store', () => {
  let dir: string;
  let store: EncryptedStore | undefined;
  const key = randomBytes(32);
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vault-test-')); });
  afterEach(async () => { await store?.close(); store = undefined; await rm(dir, { recursive: true, force: true }); });
  const config = () => ({ path: join(dir, 'data.vault'), masterKey: key });

  it('persists encrypted values across restart with restricted permissions', async () => {
    store = await EncryptedStore.open(config());
    await store.transaction(state => { state.namespaces.demo = { marker: 'secret-canary' } as never; });
    expect((await readFile(config().path, 'utf8'))).not.toContain('secret-canary');
    expect((await stat(config().path)).mode & 0o777).toBe(0o600);
    await store.close();
    store = await EncryptedStore.open(config());
    expect(store.read(s => s.namespaces.demo)).toEqual({ marker: 'secret-canary' });
  });
  it('rejects wrong master keys and corrupted ciphertext without leaking contents', async () => {
    store = await EncryptedStore.open(config());
    await store.close(); store = undefined;
    await expect(EncryptedStore.open({ ...config(), masterKey: randomBytes(32) })).rejects.toThrow('StoreUnavailable');
    await writeFile(config().path, '{corrupt', { mode: 0o600 });
    await expect(EncryptedStore.open(config())).rejects.toThrow('StoreUnavailable');
  });
  it('allows exactly one process owner', async () => {
    store = await EncryptedStore.open(config());
    await expect(EncryptedStore.open(config())).rejects.toThrow('StoreLocked');
    await store.transaction(s => { s.namespaces.ok = {} as never; });
  });
  it('serializes concurrent commits and rolls back thrown mutations', async () => {
    store = await EncryptedStore.open(config());
    await Promise.all(Array.from({ length: 20 }, (_, i) => store!.transaction(s => { s.namespaces[String(i)] = {} as never; })));
    await expect(store.transaction(s => { s.namespaces.bad = {} as never; throw new Error('abort'); })).rejects.toThrow('abort');
    expect(Object.keys(store.read(s => s.namespaces))).toHaveLength(20);
    await store.close(); store = await EncryptedStore.open(config());
    expect(Object.keys(store.read(s => s.namespaces))).toHaveLength(20);
  });
  it('does not expose mutable references through reads or transaction results', async () => {
    store = await EncryptedStore.open(config());
    const result = await store.transaction(s => { s.namespaces.a = {} as never; return s.namespaces; });
    delete result.a;
    const read = store.read(s => s.namespaces); delete read.a;
    expect(store.read(s => s.namespaces.a)).toEqual({});
  });
  it('leaves previous memory and disk state intact when a commit cannot be persisted', async () => {
    store = await EncryptedStore.open(config());
    await store.transaction(s => { s.namespaces.before = {} as never; });
    await rename(config().path, config().path + '.backup');
    await mkdir(config().path);
    await expect(store.transaction(s => { s.namespaces.after = {} as never; })).rejects.toThrow('StoreUnavailable');
    expect(store.read(s => s.namespaces.after)).toBeUndefined();
    await rm(config().path, { recursive: true }); await rename(config().path + '.backup', config().path);
    await store.close(); store = await EncryptedStore.open(config());
    expect(store.read(s => s.namespaces.before)).toEqual({});
    expect(store.read(s => s.namespaces.after)).toBeUndefined();
  });
  it('rejects symlink store files', async () => {
    await writeFile(join(dir, 'target'), 'nope', { mode: 0o600 });
    await symlink(join(dir, 'target'), config().path);
    await expect(EncryptedStore.open(config())).rejects.toThrow('UnsafeStorePath');
  });
});
