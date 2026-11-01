import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { FileHandle, lstat, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fail } from './errors';
import { StoreState } from './types';

export interface StoreConfig { path: string; masterKey: Buffer }
export class EncryptedStore {
  private state: StoreState = { schema: 1, namespaces: {} };
  private queue: Promise<unknown> = Promise.resolve();
  private closed = false;
  private lock?: FileHandle;
  private constructor(private readonly config: StoreConfig) {}

  static async open(config: StoreConfig): Promise<EncryptedStore> {
    if (config.masterKey.length !== 32) fail(500, 'InvalidBootstrap');
    const store = new EncryptedStore({ path: resolve(config.path), masterKey: Buffer.from(config.masterKey) });
    let locked = false;
    try {
      const dir = dirname(store.config.path);
      await mkdir(dir, { recursive: true, mode: 0o700 });
      const ds = await lstat(dir);
      if (!ds.isDirectory() || ds.isSymbolicLink() || (ds.mode & 0o077) !== 0 ||
          (process.getuid && ds.uid !== process.getuid())) fail(500, 'UnsafeStorePath');
      try { store.lock = await open(store.config.path + '.lock', 'wx', 0o600); locked = true; }
      catch (e) { if ((e as NodeJS.ErrnoException).code === 'EEXIST') fail(503, 'StoreLocked'); throw e; }
      await store.lock.writeFile(String(process.pid)); await store.lock.sync();
      try {
        const st = await lstat(store.config.path);
        if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1 || (st.mode & 0o077) !== 0 ||
            (process.getuid && st.uid !== process.getuid())) fail(500, 'UnsafeStorePath');
        const envelope = JSON.parse(await readFile(store.config.path, 'utf8'));
        if (envelope.schema !== 1) throw new Error();
        const decipher = createDecipheriv('aes-256-gcm', store.config.masterKey, Buffer.from(envelope.iv, 'base64'));
        decipher.setAAD(Buffer.from('local-vault-v1'));
        decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
        const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]);
        const state = JSON.parse(plaintext.toString('utf8'));
        if (state.schema !== 1 || !state.namespaces || typeof state.namespaces !== 'object') throw new Error();
        store.state = state;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
        await store.persist(store.state);
      }
      return store;
    } catch (e) {
      if (locked) { await store.lock?.close(); await unlink(store.config.path + '.lock').catch(() => undefined); }
      store.config.masterKey.fill(0);
      if (e instanceof Error && ['StoreLocked', 'UnsafeStorePath'].includes(e.message)) throw e;
      fail(503, 'StoreUnavailable');
    }
  }

  read<T>(fn: (state: StoreState) => T): T {
    if (this.closed) fail(503, 'StoreUnavailable');
    return structuredClone(fn(structuredClone(this.state)));
  }

  transaction<T>(fn: (state: StoreState) => T | Promise<T>): Promise<T> {
    const operation = this.queue.then(async () => {
      if (this.closed) fail(503, 'StoreUnavailable');
      const draft = structuredClone(this.state);
      const result = await fn(draft);
      try { await this.persist(draft); } catch { fail(503, 'StoreUnavailable'); }
      this.state = draft;
      return structuredClone(result);
    });
    this.queue = operation.catch(() => undefined);
    return operation;
  }

  private async persist(state: StoreState) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.config.masterKey, iv);
    cipher.setAAD(Buffer.from('local-vault-v1'));
    const data = Buffer.concat([cipher.update(JSON.stringify(state), 'utf8'), cipher.final()]);
    const envelope = JSON.stringify({ schema: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') });
    const temporary = this.config.path + '.' + randomBytes(12).toString('hex') + '.tmp';
    let handle: FileHandle | undefined;
    try {
      handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      await handle.writeFile(envelope); await handle.sync(); await handle.close(); handle = undefined;
      await rename(temporary, this.config.path);
    } finally { await handle?.close(); await unlink(temporary).catch(() => undefined); }
  }

  async close() {
    await this.queue;
    if (this.closed) return;
    this.closed = true;
    await this.lock?.close(); await unlink(this.config.path + '.lock'); this.config.masterKey.fill(0);
  }
}
