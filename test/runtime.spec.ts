import { call, fixture, otherToken, token } from './helpers.js';
import { RuntimeVault } from '../src/runtime.js';

const tenantManifest = { schemaVersion: 1, entries: [{ purpose: 'database', kind: 'secret', scope: 'tenant', envName: 'APP_DATABASE_URL' }] };
describe('server runtime loading', () => {
  let f: Awaited<ReturnType<typeof fixture>>;
  let client: RuntimeVault;
  beforeEach(async () => {
    f = await fixture(); await f.app.listen(0, '127.0.0.1');
    const address = f.app.getHttpServer().address();
    client = new RuntimeVault({ baseUrl: `http://127.0.0.1:${address.port}`, token: s => s.tenant === 'b' ? otherToken : token, ttlMs: 100 });
  });
  afterEach(async () => { delete process.env.APP_DATABASE_URL; delete process.env.APP_SHARED; await f.cleanup(); });
  const a = { environment: 'dev', tenant: 'a' }, b = { environment: 'dev', tenant: 'b' };
  it('initializes complete immutable snapshots without cross-tenant process.env writes', async () => {
    expect(() => client.get(a)).toThrow('RuntimeNotReady');
    const [one, two] = await Promise.all([
      client.initialize(a, tenantManifest, 1, { database: 'tenant-a' }),
      client.initialize(b, tenantManifest, 1, { database: 'tenant-b' }),
    ]);
    expect(one.mappings.APP_DATABASE_URL).toBe('tenant-a');
    expect(two.mappings.APP_DATABASE_URL).toBe('tenant-b');
    expect(client.get(a).mappings.APP_DATABASE_URL).toBe('tenant-a');
    expect(process.env.APP_DATABASE_URL).toBeUndefined();
    expect(Object.isFrozen(one.mappings)).toBe(true);
  });
  it('expires cached snapshots and invalidates on outage without returning last-known-good data', async () => {
    await client.initialize(a, tenantManifest, 1, { database: 'secret' });
    await new Promise(resolve => setTimeout(resolve, 120));
    expect(() => client.get(a)).toThrow('RuntimeNotReady');
    await client.refresh(a, tenantManifest, 1);
    await f.app.close();
    await expect(client.refresh(a, tenantManifest, 1)).rejects.toThrow('RuntimeRefreshFailed');
    expect(() => client.get(a)).toThrow('RuntimeNotReady');
  });
  it('does not accept stale revision events or serve a revoked secret after refresh', async () => {
    await client.initialize(a, tenantManifest, 2, { database: 'new' });
    await expect(client.refresh(a, tenantManifest, 1)).rejects.toThrow('StaleRevision');
    const name = (await import('../src/manifest.js')).vaultName(a, 'secret', 'database');
    await call(f.app, 'delete', `/secrets/${name}?api-version=2025-07-01`).expect(200);
    await expect(client.refresh(a, tenantManifest, 2)).rejects.toThrow('RuntimeRefreshFailed');
    expect(() => client.get(a)).toThrow('RuntimeNotReady');
  });
  it('only exports process-scoped allowlisted values and validates all conflicts before writing', async () => {
    const shared = { schemaVersion: 1, entries: [
      { purpose: 'one', kind: 'secret', scope: 'process', envName: 'APP_SHARED' },
      { purpose: 'two', kind: 'secret', scope: 'process', envName: 'APP_DATABASE_URL' },
    ] };
    process.env.APP_DATABASE_URL = 'existing';
    await expect(client.initializeProcess('dev', shared, 1, { one: 'new', two: 'different' })).rejects.toThrow('EnvironmentConflict');
    expect(process.env.APP_SHARED).toBeUndefined(); expect(process.env.APP_DATABASE_URL).toBe('existing');
    delete process.env.APP_DATABASE_URL;
    await client.initializeProcess('dev', shared, 1, { one: 'new', two: 'different' });
    expect(process.env.APP_SHARED).toBe('new');
    const unsafe = { schemaVersion: 1, entries: [{ purpose: 'one', kind: 'secret', scope: 'process', envName: 'NODE_OPTIONS' }] };
    await expect(client.initializeProcess('dev', unsafe, 2, { one: '--inspect' })).rejects.toThrow();
  });
  it('blocks reads immediately during refresh and invalidates on invalid refresh input', async () => {
    await client.initialize(a, tenantManifest, 1, { database: 'secret' });
    const pending = client.refresh(a, tenantManifest, 1);
    expect(() => client.get(a)).toThrow('RuntimeNotReady');
    await pending;
    await expect(client.refresh(a, { schemaVersion: 99, entries: [] }, 1)).rejects.toThrow('RuntimeRefreshFailed');
    expect(() => client.get(a)).toThrow('RuntimeNotReady');
  });
  it('rejects NUL-containing process values before writing any mapping', async () => {
    const shared = { schemaVersion: 1, entries: [
      { purpose: 'one', kind: 'secret', scope: 'process', envName: 'APP_SHARED' },
      { purpose: 'two', kind: 'secret', scope: 'process', envName: 'APP_DATABASE_URL' },
    ] };
    await expect(client.initializeProcess('dev', shared, 1, { one: 'valid', two: 'before\0after' })).rejects.toThrow('InvalidEnvironmentValue');
    expect(process.env.APP_SHARED).toBeUndefined(); expect(process.env.APP_DATABASE_URL).toBeUndefined();
  });
  it('retains a failed newer event revision so an older event cannot restore stale readiness', async () => {
    await client.initialize(a, tenantManifest, 1, { database: 'old' });
    await expect(client.refresh(a, tenantManifest, 2)).rejects.toThrow('RuntimeRefreshFailed');
    await expect(client.refresh(a, tenantManifest, 1)).rejects.toThrow('StaleRevision');
    expect(() => client.get(a)).toThrow('RuntimeNotReady');
  });
});
