import request from 'supertest';
import { api, call, fixture } from './helpers.js';

const listToken = 'inventory-only-test-xxxxxxxxxxxxxxxxxxxxxxxx';
const listTokenB = 'inventory-only-test-bbbbbbbbbbbbbbbbbbbbbbbb';
describe('metadata inventory', () => {
  let f: Awaited<ReturnType<typeof fixture>>;
  beforeEach(async () => {
    f = await fixture(); await f.app.close();
    await f.addGrants([{ token: listToken, environment: 'dev', tenant: 'a', permissions: ['list'] }]);
    await f.addGrants([{ token: listTokenB, environment: 'dev', tenant: 'b', permissions: ['list'] }]);
    const { createApp } = await import('../src/app.js'); f.app = await createApp(f.config); await f.app.init();
  });
  afterEach(async () => { await f.cleanup(); });
  const listing = (path: string) => call(f.app, 'get', path).set('Authorization', `Bearer ${listToken}`);
  const follow = (link: string) => new URL(link).pathname + new URL(link).search;
  it('lists metadata using a separate permission without exposing values or allowing secret reads', async () => {
    await call(f.app, 'put', '/secrets/database' + api).send({ value: 'private-canary', tags: { purpose: 'database' } }).expect(200);
    await call(f.app, 'put', '/secrets/other' + api, 'b').send({ value: 'tenant-b' }).expect(200);
    const page = await listing('/secrets' + api).expect(200);
    expect(page.body.value).toHaveLength(1);
    expect(page.body.value[0].id).toBe('http://127.0.0.1:4000/namespaces/dev/a/secrets/database');
    expect(page.body.value[0].tags).toEqual({ purpose: 'database' });
    expect(page.body.value[0].value).toBeUndefined(); expect(JSON.stringify(page.body)).not.toContain('private-canary');
    await listing('/secrets/database' + api).expect(403);
    await call(f.app, 'post', '/local/snapshot').set('Authorization', `Bearer ${listToken}`).send({}).expect(403);
    await call(f.app, 'post', '/keys/unknown/version/encrypt' + api).set('Authorization', `Bearer ${listToken}`).send({}).expect(403);
    await call(f.app, 'put', '/secrets/not-allowed' + api).set('Authorization', `Bearer ${listToken}`).send({ value: 'x' }).expect(403);
    await call(f.app, 'get', '/secrets' + api).expect(403); // Existing read permission does not imply list.
    await request(f.app.getHttpServer()).get('/local/inventory').expect(401);
    await listing('/namespaces/dev/b/secrets' + api).expect(403);
  });
  it('paginates deterministically and rejects cursor tampering, changed filters and concurrent mutations', async () => {
    for (const name of ['c', 'a', 'b']) await call(f.app, 'put', `/secrets/${name}` + api).send({ value: 'hidden' }).expect(200);
    const first = await listing('/secrets' + api + '&maxresults=1').expect(200);
    expect(first.body.value[0].id).toMatch(/\/a$/);
    const second = await listing(follow(first.body.nextLink)).expect(200);
    expect(second.body.value[0].id).toMatch(/\/b$/);
    const last = await listing(follow(second.body.nextLink)).expect(200);
    expect(last.body.value[0].id).toMatch(/\/c$/); expect(last.body.nextLink).toBeUndefined();
    const altered = new URL(first.body.nextLink); altered.searchParams.set('$skiptoken', 'tampered');
    await listing(follow(altered.href)).expect(400);
    const resized = new URL(first.body.nextLink); resized.searchParams.set('maxresults', '2');
    await listing(follow(resized.href)).expect(400);
    const otherScope = first.body.nextLink.replace('/dev/a/', '/dev/b/');
    await call(f.app, 'get', follow(otherScope), 'b').set('Authorization', `Bearer ${listTokenB}`).expect(400);
    await listing(follow(first.body.nextLink.replace('/secrets?', '/keys?'))).expect(400);
    await call(f.app, 'put', '/secrets/new' + api).send({ value: 'new' }).expect(200);
    await listing(follow(first.body.nextLink)).expect(409);
    for (const limit of ['0', '26', '1.5', 'x']) await listing('/secrets' + api + '&maxresults=' + limit).expect(400);
  });
  it('returns empty inventories and defaults to pages of at most 25 objects', async () => {
    expect((await listing('/local/inventory').expect(200)).body).toEqual({ value: [] });
    for (let i = 0; i < 26; i++) await call(f.app, 'put', `/secrets/secret-${i}` + api).send({ value: 'hidden' }).expect(200);
    const first = await listing('/local/inventory').expect(200);
    expect(first.body.value).toHaveLength(25);
    expect((await listing(follow(first.body.nextLink)).expect(200)).body.value).toHaveLength(1);
    const changed = new URL(first.body.nextLink); changed.searchParams.set('kind', 'secret');
    await listing(follow(changed.href)).expect(400);
    await listing('/secrets' + api + '&maxresults=1&maxresults=2').expect(400);
    await listing('/secrets' + api + '&purpose=unknown').expect(400);
  });
  it('filters combined inventory and retains disabled/expired objects for auditing', async () => {
    await call(f.app, 'post', '/keys/encryption/create' + api).send({ kty: 'RSA', tags: { purpose: 'data' } }).expect(200);
    await call(f.app, 'put', '/secrets/db-old' + api).send({ value: 'hidden', attributes: { enabled: false, exp: 1 }, tags: { purpose: 'database', owner: 'team' } }).expect(200);
    await call(f.app, 'put', '/secrets/db-new' + api).send({ value: 'hidden', tags: { purpose: 'database' } }).expect(200);
    const all = await listing('/local/inventory').expect(200);
    expect(all.body.value).toHaveLength(3);
    expect(JSON.stringify(all.body)).not.toContain('hidden');
    expect(all.body.value.find((x: any) => x.kind === 'key').privateKey).toBeUndefined();
    const filtered = await listing('/local/inventory?kind=secret&namePrefix=db-&purpose=database&enabled=false&expiresBefore=2&tagName=owner&tagValue=team').expect(200);
    expect(filtered.body.value.map((x: any) => x.name)).toEqual(['db-old']);
    expect(filtered.body.value[0].version).toMatch(/^[a-f0-9]{32}$/);
    await listing('/local/inventory?enabled=invalid').expect(400);
    await listing('/local/inventory?tagName=owner').expect(400);
    await listing('/local/inventory?kind=invalid').expect(400);
    const keys = await listing('/keys' + api).expect(200);
    expect(keys.body.value[0].kid).toMatch(/\/keys\/encryption$/);
    expect(keys.body.value[0].key).toBeUndefined();
  });
  it('makes newly provisioned hashed objects discoverable by purpose without changing key IDs on retry', async () => {
    const manifest = { schemaVersion: 1, entries: [{ purpose: 'data-encryption', kind: 'key', scope: 'tenant', envName: 'DATA_KEY_ID', kty: 'RSA' }] };
    const payload = { revision: 1, manifest };
    const result = await call(f.app, 'post', '/local/reconcile').send(payload).expect(200);
    const retry = await call(f.app, 'post', '/local/reconcile').send(payload).expect(200);
    expect(retry.body.mappings.DATA_KEY_ID).toBe(result.body.mappings.DATA_KEY_ID);
    const page = await listing('/local/inventory?purpose=data-encryption').expect(200);
    expect(page.body.value).toHaveLength(1); expect(page.body.value[0].versionId).toBe(result.body.mappings.DATA_KEY_ID);
  });
});
