import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadBootstrapConfig } from '../src/config.js';
import { formatStartupError, VaultError } from '../src/errors.js';

describe('.env bootstrap configuration', () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vault-env-test-')); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });
  const values = () => ({
    VAULT_MASTER_KEY: Buffer.alloc(32, 1).toString('base64'),
    VAULT_MONGODB_URI: 'mongodb://127.0.0.1:27017/key-vault',
    VAULT_GRANTS: JSON.stringify([{ token: 'test-only-token-aaaaaaaaaaaaaaaaaaaaaaaa', environment: 'dev', tenant: 'a', permissions: ['read'] }]),
  });
  const contents = () => Object.entries(values()).map(([k, v]) => `${k}='${v}'`).join('\n');
  it('loads quoted JSON grants and bootstrap values from .env without changing process.env', async () => {
    const path = join(dir, '.env');
    await writeFile(path, contents() + '\nVAULT_BASE_URL=http://127.0.0.1:4000 # local API\n');
    const before = process.env.VAULT_MASTER_KEY;
    const config = loadBootstrapConfig(path, {});
    expect(config.baseUrl).toBe('http://127.0.0.1:4000');
    expect(config.masterKey).toEqual(Buffer.alloc(32, 1));
    expect(config.grants[0]?.tenant).toBe('a');
    expect(process.env.VAULT_MASTER_KEY).toBe(before);
  });
  it('gives exported values precedence over file values', async () => {
    const path = join(dir, '.env'); await writeFile(path, contents());
    const config = loadBootstrapConfig(path, { VAULT_BASE_URL: 'http://127.0.0.1:4100', VAULT_MASTER_KEY: Buffer.alloc(32, 2).toString('base64') });
    expect(config.baseUrl).toBe('http://127.0.0.1:4100');
    expect(config.masterKey).toEqual(Buffer.alloc(32, 2));
  });
  it('allows an absent .env when bootstrap is supplied externally', () => {
    expect(loadBootstrapConfig(join(dir, 'missing'), values()).baseUrl).toBe('http://127.0.0.1:4000');
  });
  it('fails safely for invalid bootstrap or unreadable file paths without echoing secrets', async () => {
    const path = join(dir, '.env');
    await writeFile(path, contents() + '\nVAULT_GRANTS=secret-canary-invalid-json\n');
    expect(() => loadBootstrapConfig(path, {})).toThrow(/^InvalidBootstrap$/);
    await mkdir(join(dir, 'directory'));
    expect(() => loadBootstrapConfig(join(dir, 'directory'), values())).toThrow(/^InvalidBootstrap$/);
  });
  it('identifies the invalid bootstrap variable without exposing its value', () => {
    for (const [name, value] of [['VAULT_MASTER_KEY', 'private-canary'], ['VAULT_GRANTS', 'private-canary'], ['VAULT_MONGODB_URI', 'private-canary'], ['VAULT_BASE_URL', 'private-canary']]) {
      try { loadBootstrapConfig(join(dir, 'missing'), { ...values(), [name!]: value }); throw new Error('Expected validation failure'); }
      catch (error) {
        expect(error).toBeInstanceOf(VaultError);
        const detail = formatStartupError(error);
        expect(detail).toContain(name); expect(detail).not.toContain('private-canary');
      }
    }
  });
  it('preserves safe error names and nested connection codes without dumping raw messages', () => {
    const error = Object.assign(new Error('mongodb://user:password-canary@host'), {
      name: 'MongoServerSelectionError', reason: { servers: new Map([['host', { error: Object.assign(new Error('token-canary'), { code: 'ECONNREFUSED' }) }]]) },
    });
    const detail = formatStartupError(error);
    expect(detail).toContain('MongoServerSelectionError'); expect(detail).toContain('ECONNREFUSED');
    expect(detail).not.toContain('password-canary'); expect(detail).not.toContain('token-canary');
  });
  it.each([
    'mongodb://127.0.0.1:27017',
    'mongodb://127.0.0.1:27017/',
    'mongodb://127.0.0.1:27017/?authSource=key-vault',
    'mongodb+srv://example.invalid/?retryWrites=true',
    'mongodb://user:password-canary@localhost:27017',
    'mongodb://localhost:27017/%20',
  ])('rejects a MongoDB URL without an explicit database (%#)', uri => {
    let failure: unknown;
    try { loadBootstrapConfig(join(dir, 'missing'), { ...values(), VAULT_MONGODB_URI: uri }); } catch (error) { failure = error; }
    expect(failure).toBeInstanceOf(VaultError);
    const detail = formatStartupError(failure);
    expect(detail).toContain('VAULT_MONGODB_URI'); expect(detail).toContain('database');
    expect(detail).not.toContain('password-canary');
  });
});
