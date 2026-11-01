import { api, call, fixture } from './helpers';
import { vaultName } from '../src/manifest';

export const manifest = { schemaVersion: 1, entries: [
  { purpose: 'data-encryption', kind: 'key', scope: 'tenant', envName: 'DATA_KEY_ID', kty: 'RSA', keySize: 2048, keyOps: ['encrypt', 'decrypt'] },
  { purpose: 'database', kind: 'secret', scope: 'tenant', envName: 'DATABASE_URL' },
] };
describe('automatic manifest provisioning', () => {
  let f: Awaited<ReturnType<typeof fixture>>;
  beforeEach(async () => { f = await fixture(); });
  afterEach(async () => { await f.cleanup(); });
  const reconcile = (revision = 1, secrets: Record<string, string> = { database: 'db-canary' }) =>
    call(f.app, 'post', '/local/reconcile').send({ revision, manifest, secrets });
  it('gives a new tenant deterministic names and mappings; concurrent retries never rotate', async () => {
    const responses = await Promise.all(Array.from({ length: 5 }, () => reconcile().expect(200)));
    const kid = responses[0]!.body.mappings.DATA_KEY_ID;
    expect(responses.every(r => r.body.mappings.DATA_KEY_ID === kid)).toBe(true);
    expect(responses[0]!.body.mappings.DATABASE_URL).toBe('db-canary');
    const name = vaultName({ environment: 'dev', tenant: 'a' }, 'key', 'data-encryption');
    expect(name).toMatch(/^kv-[a-f0-9]{64}$/);
    const versions = await call(f.app, 'get', `/keys/${name}/versions` + api).expect(200);
    expect(versions.body.value).toHaveLength(1);
    await f.app.close();
    const { createApp } = await import('../src/app'); f.app = await createApp(f.config); await f.app.init();
    expect((await reconcile().expect(200)).body.mappings.DATA_KEY_ID).toBe(kid);
    expect(vaultName({ environment: 'dev', tenant: 'b' }, 'key', 'data-encryption')).not.toBe(name);
  });
  it('rolls back incomplete provisioning and rejects stale/conflicting revision payloads', async () => {
    await reconcile(1, {}).expect(409);
    const keyName = vaultName({ environment: 'dev', tenant: 'a' }, 'key', 'data-encryption');
    await call(f.app, 'get', `/keys/${keyName}` + api).expect(404);
    await reconcile().expect(200);
    await reconcile(1, { database: 'different' }).expect(409);
    await reconcile(2, { database: 'rotated' }).expect(200);
    await reconcile(1).expect(409);
    const snap = await call(f.app, 'post', '/local/snapshot').send({ manifest }).expect(200);
    expect(snap.body.mappings.DATABASE_URL).toBe('rotated');
  });
  it('does not regenerate a deleted or disabled required key', async () => {
    const result = await reconcile().expect(200);
    const keyName = vaultName({ environment: 'dev', tenant: 'a' }, 'key', 'data-encryption');
    const version = result.body.mappings.DATA_KEY_ID.split('/').pop();
    await call(f.app, 'patch', `/keys/${keyName}/${version}` + api).send({ attributes: { enabled: false } }).expect(200);
    await reconcile(2).expect(403);
    await call(f.app, 'delete', `/keys/${keyName}` + api).expect(200);
    await reconcile(2).expect(409);
  });
  it('rejects duplicate mappings, tenant/process scope confusion and unsafe environment names', async () => {
    for (const entries of [
      [...manifest.entries, manifest.entries[0]],
      [{ ...manifest.entries[0], envName: 'NEXT_PUBLIC_KEY' }],
      [{ ...manifest.entries[0], scope: 'process' }],
    ]) {
      await call(f.app, 'post', '/local/reconcile').send({ revision: 1, manifest: { schemaVersion: 1, entries }, secrets: {} }).expect(400);
    }
  });
  it('reconciles safely across two Nest servers and observes rotation/revocation from either writer', async () => {
    const { createApp } = await import('../src/app');
    const second = await createApp(f.config); await second.init();
    try {
      const responses = await Promise.all(Array.from({ length: 6 }, (_, i) => call(i % 2 ? second : f.app, 'post', '/local/reconcile')
        .send({ revision: 1, manifest, secrets: { database: 'shared' } }).expect(200)));
      const kid = responses[0]!.body.mappings.DATA_KEY_ID;
      expect(responses.every(r => r.body.mappings.DATA_KEY_ID === kid)).toBe(true);
      const name = vaultName({ environment: 'dev', tenant: 'a' }, 'key', 'data-encryption');
      expect((await call(second, 'get', `/keys/${name}/versions` + api).expect(200)).body.value).toHaveLength(1);
      const secretName = vaultName({ environment: 'dev', tenant: 'a' }, 'secret', 'database');
      await call(second, 'put', `/secrets/${secretName}` + api).send({ value: 'rotated' }).expect(200);
      expect((await call(f.app, 'post', '/local/snapshot').send({ manifest }).expect(200)).body.mappings.DATABASE_URL).toBe('rotated');
      await call(second, 'patch', `/keys/${name}/${kid.split('/').pop()}` + api).send({ attributes: { enabled: false } }).expect(200);
      await call(f.app, 'post', '/local/snapshot').send({ manifest }).expect(403);
    } finally { await second.close(); }
  });
});
