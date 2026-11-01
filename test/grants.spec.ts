import { jest } from '@jest/globals';
import { createDecipheriv } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { fixture, call, api, token } from './helpers.js';
import { MongoStore } from '../src/store.js';
import { runGrantCommand } from '../src/grants-cli.js';
import { GrantService } from '../src/grants.js';

describe('database grants', () => {
  let f: Awaited<ReturnType<typeof fixture>>, store: MongoStore, grants: GrantService;
  beforeEach(async () => { f = await fixture(); store = await MongoStore.open(f.config); grants = new GrantService(store); });
  afterEach(async () => { await store.close(); await f.cleanup(); });
  it('applies new grants, permission changes and revocation to a running API across connections', async () => {
    const created = await grants.create({ environment: 'dev', tenant: 'a' }, ['list']);
    const req = (path: string, tenant = 'a') => call(f.app, 'get', path, tenant).set('Authorization', `Bearer ${created.token}`);
    await req('/secrets' + api).expect(200);
    await req('/secrets' + api, 'b').expect(403);
    await call(f.app, 'put', '/secrets/item' + api).send({ value: 'value' }).expect(200);
    await req('/secrets/item' + api).expect(403);
    await grants.setPermissions(created.id, ['read']);
    await req('/secrets/item' + api).expect(200);
    await req('/secrets' + api).expect(403);
    await grants.revoke(created.id);
    await req('/secrets/item' + api).expect(401);
  });
  it('stores encrypted hashes, never plaintext tokens, and only lists safe metadata', async () => {
    const created = await grants.create({ environment: 'dev', tenant: 'a' }, ['read']);
    const client = await new MongoClient(f.config.mongoUri).connect();
    try {
      const raw = await client.db().collection('vault_grants').findOne({ _id: 'grants:registry' } as never);
      expect(raw).toBeTruthy(); expect(Object.keys(raw!).sort()).toEqual(['_id', 'schema', 'revision', 'iv', 'tag', 'data'].sort());
      const decipher = createDecipheriv('aes-256-gcm', f.config.masterKey, Buffer.from(raw!.iv, 'base64'));
      decipher.setAAD(Buffer.from(JSON.stringify(['mongodb-vault-v1', raw!._id, raw!.revision])));
      decipher.setAuthTag(Buffer.from(raw!.tag, 'base64'));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(raw!.data, 'base64')), decipher.final()]).toString();
      expect(plaintext).toContain('tokenHash'); expect(plaintext).not.toContain(created.token); expect(plaintext).not.toContain(token);
      const listed = JSON.stringify(await grants.list());
      expect(listed).not.toContain('tokenHash'); expect(listed).not.toContain(created.token);
    } finally { await client.close(); }
    await store.close(); store = await MongoStore.open(f.config); grants = new GrantService(store);
    await expect(grants.authorize(`Bearer ${created.token}`, { environment: 'dev', tenant: 'a' }, ['read'])).resolves.toBeUndefined();
  });
  it('imports atomically and never restores revoked grants or previous permissions on a repeat import', async () => {
    const input = [{ token: 'migration-canary-xxxxxxxxxxxxxxxxxxxxxxxx', environment: 'dev', tenant: 'a', permissions: ['read', 'write'] }];
    expect(await grants.import(input)).toEqual({ imported: 1, skipped: 0 });
    const migrated = (await grants.list()).find(g => g.tenant === 'a' && g.permissions.length === 2)!;
    await grants.setPermissions(migrated.id, ['list']); await grants.revoke(migrated.id);
    expect(await grants.import(input)).toEqual({ imported: 0, skipped: 1 });
    await expect(grants.authorize(`Bearer ${input[0]!.token}`, { environment: 'dev', tenant: 'a' })).rejects.toThrow('Unauthorized');
    const before = await grants.list();
    await expect(grants.import([{ ...input[0], token: 'new-migration-xxxxxxxxxxxxxxxxxxxxxxxx' }, { ...input[0], permissions: ['admin'] }])).rejects.toThrow('InvalidGrants');
    expect(await grants.list()).toEqual(before);
  });
  it('preserves combined permissions from duplicate legacy entries for one token and namespace', async () => {
    const grant = { token: 'duplicate-legacy-xxxxxxxxxxxxxxxxxxxxxxxx', environment: 'dev', tenant: 'duplicate' };
    expect(await grants.import([{ ...grant, permissions: ['read'] }, { ...grant, permissions: ['write'] }])).toEqual({ imported: 1, skipped: 1 });
    await expect(grants.authorize(`Bearer ${grant.token}`, grant, ['read', 'write'])).resolves.toBeUndefined();
    expect(await grants.import([{ ...grant, permissions: ['crypto'] }])).toEqual({ imported: 0, skipped: 1 });
    await expect(grants.authorize(`Bearer ${grant.token}`, grant, ['crypto'])).rejects.toThrow('Forbidden');
  });
  it('supports concurrent management without lost grants and fails closed on a failed database read', async () => {
    const otherStore = await MongoStore.open(f.config);
    try {
      const other = new GrantService(otherStore);
      await Promise.all(Array.from({ length: 8 }, (_, i) => (i % 2 ? grants : other).create({ environment: 'dev', tenant: `concurrent-${i}` }, ['list'])));
    } finally { await otherStore.close(); }
    expect((await grants.list()).filter(g => g.tenant.startsWith('concurrent-'))).toHaveLength(8);
    const client = await new MongoClient(f.config.mongoUri).connect();
    try {
      await client.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 }, data: { failCommands: ['find'], errorCode: 2 } });
      await call(f.app, 'get', '/secrets' + api).expect(503);
      await client.db().collection('vault_grants').updateOne({ _id: 'grants:registry' } as never, { $set: { data: 'corrupt' } });
      await call(f.app, 'get', '/secrets' + api).expect(503);
    } finally { await client.close(); }
  });
  it('runs CLI creation/import/list/permissions/revoke without printing tokens after creation', async () => {
    const output: string[] = [], print = (value: string) => { output.push(value); };
    await runGrantCommand(['create', 'dev', 'cli', 'read,list'], grants, {}, print);
    const created = JSON.parse(output.pop()!);
    expect(created.token).toHaveLength(43);
    await runGrantCommand(['list'], grants, {}, print);
    expect(output.join('')).not.toContain(created.token);
    await runGrantCommand(['permissions', created.id, 'list'], grants, {}, print);
    await grants.authorize(`Bearer ${created.token}`, { environment: 'dev', tenant: 'cli' }, ['list']);
    await runGrantCommand(['revoke', created.id], grants, {}, print);
    await expect(grants.authorize(`Bearer ${created.token}`, { environment: 'dev', tenant: 'cli' })).rejects.toThrow('Unauthorized');
    const legacy = { VAULT_GRANTS: JSON.stringify([{ token: 'cli-import-canary-xxxxxxxxxxxxxxxxxxxxxxxx', environment: 'dev', tenant: 'cli-import', permissions: ['list'] }]) };
    await runGrantCommand(['import'], grants, legacy, print);
    expect(output.at(-1)).toContain('"imported": 1');
    expect(output.join('')).not.toContain('cli-import-canary');
    await expect(runGrantCommand(['import'], grants, { VAULT_GRANTS: 'secret-canary-invalid-json' }, print)).rejects.toThrow('InvalidGrants');
    await expect(runGrantCommand(['create', 'extra'], grants, {}, print)).rejects.toThrow('InvalidCommand');
    await expect(grants.create({ environment: '*', tenant: 'a' }, ['read'])).rejects.toThrow('InvalidGrants');
    await expect(grants.setPermissions(created.id, ['admin'])).rejects.toThrow('InvalidGrants');
    await expect(grants.setPermissions(created.id, [])).rejects.toThrow('InvalidGrants');
    await expect(grants.revoke('bad-id')).rejects.toThrow('InvalidGrants');
  });
  it('rotates a grant atomically through the CLI, preserving access and preventing old-token re-import', async () => {
    const original = await grants.create({ environment: 'dev', tenant: 'a' }, ['list']);
    const output: string[] = [];
    await runGrantCommand(['rotate', original.id], grants, {}, value => { output.push(value); });
    const rotated = JSON.parse(output[0]!);
    expect(output).toHaveLength(1);
    expect(rotated.token).toHaveLength(43); expect(rotated.token).not.toBe(original.token);
    expect(rotated.id).not.toBe(original.id);
    expect(rotated).toMatchObject({ environment: 'dev', tenant: 'a', permissions: ['list'], enabled: true });
    await call(f.app, 'get', '/secrets' + api).set('Authorization', `Bearer ${original.token}`).expect(401);
    await call(f.app, 'get', '/secrets' + api).set('Authorization', `Bearer ${rotated.token}`).expect(200);
    await call(f.app, 'get', '/secrets' + api, 'b').set('Authorization', `Bearer ${rotated.token}`).expect(403);
    await call(f.app, 'get', '/secrets/unknown' + api).set('Authorization', `Bearer ${rotated.token}`).expect(403);
    expect(await grants.import([{ ...original, token: original.token }])).toEqual({ imported: 0, skipped: 1 });
    await expect(grants.authorize(`Bearer ${original.token}`, original)).rejects.toThrow('Unauthorized');
    const listed = await grants.list();
    expect(listed.find(g => g.id === original.id)?.enabled).toBe(false);
    expect(JSON.stringify(listed)).not.toContain(rotated.token);
  });
  it('rejects rotating revoked/unknown/invalid grants without creating replacements or printing tokens', async () => {
    const original = await grants.create({ environment: 'dev', tenant: 'a' }, ['read']);
    await grants.revoke(original.id);
    const before = await grants.list(), print = jest.fn();
    await expect(runGrantCommand(['rotate', original.id], grants, {}, print)).rejects.toThrow('GrantRevoked');
    await expect(runGrantCommand(['rotate', 'f'.repeat(64)], grants, {}, print)).rejects.toThrow('GrantNotFound');
    await expect(runGrantCommand(['rotate', 'bad-id'], grants, {}, print)).rejects.toThrow('InvalidGrants');
    await expect(runGrantCommand(['rotate'], grants, {}, print)).rejects.toThrow('InvalidCommand');
    expect(await grants.list()).toEqual(before); expect(print).not.toHaveBeenCalled();
  });
  it('allows only one concurrent rotation of a grant across connections', async () => {
    const original = await grants.create({ environment: 'dev', tenant: 'a' }, ['list']);
    const otherStore = await MongoStore.open(f.config);
    try {
      const results = await Promise.allSettled([grants.rotate(original.id), new GrantService(otherStore).rotate(original.id)]);
      expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
      const rejected = results.find(r => r.status === 'rejected') as PromiseRejectedResult;
      expect(rejected.reason.message).toBe('GrantRevoked');
      const success = results.find(r => r.status === 'fulfilled') as PromiseFulfilledResult<{ token: string }>;
      await grants.authorize(`Bearer ${success.value.token}`, original, ['list']);
      await expect(grants.authorize(`Bearer ${original.token}`, original)).rejects.toThrow('Unauthorized');
      expect((await grants.list()).filter(g => g.tenant === 'a' && g.permissions.join() === 'list' && g.enabled)).toHaveLength(1);
    } finally { await otherStore.close(); }
  });
  it('fails closed when no grants exist and never consults legacy environment grants', async () => {
    const client = await new MongoClient(f.config.mongoUri).connect();
    try { await client.db().collection('vault_grants').deleteMany({}); } finally { await client.close(); }
    await call(f.app, 'get', '/secrets' + api).expect(401);
  });
});
