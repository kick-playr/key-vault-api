import request from 'supertest';
import { api, call, fixture, token } from './helpers';

describe('Azure subset HTTP contract', () => {
  let f: Awaited<ReturnType<typeof fixture>>;
  beforeEach(async () => { f = await fixture(); });
  afterEach(async () => { await f.cleanup(); });
  it('requires auth and exact tenant grants before looking up data', async () => {
    await request(f.app.getHttpServer()).get('/secrets/example' + api).expect(401);
    await request(f.app.getHttpServer()).get('/secrets/example' + api).set('Authorization', `Bearer ${token}`)
      .set('x-vault-environment', 'dev').set('x-vault-tenant', 'b').expect(403);
  });
  it('sets new secret versions, retains old values and isolates tenants', async () => {
    const one = await call(f.app, 'put', '/secrets/password' + api).send({ value: 'first', contentType: 'password', tags: { owner: 'dev' } }).expect(200);
    expect(one.body).toMatchObject({ value: 'first', attributes: { enabled: true, recoveryLevel: 'Purgeable' } });
    expect(one.body.id).toMatch(/^http:\/\/127.0.0.1:4567\/namespaces\/dev\/a\/secrets\/password\/[a-f0-9]{32}$/);
    const two = await call(f.app, 'put', '/secrets/password' + api).send({ value: 'second' }).expect(200);
    expect(two.body.id).not.toBe(one.body.id);
    const version = one.body.id.split('/').pop();
    expect((await call(f.app, 'get', '/secrets/password/' + version + api).expect(200)).body.value).toBe('first');
    expect((await call(f.app, 'get', '/secrets/password' + api).expect(200)).body.value).toBe('second');
    await call(f.app, 'get', '/secrets/password' + api, 'b').expect(404);
    const list = await call(f.app, 'get', '/secrets/password/versions' + api).expect(200);
    expect(list.body.value).toHaveLength(2); expect(JSON.stringify(list.body)).not.toContain('first');
    await call(f.app, 'patch', '/secrets/password/' + version + api).send({ attributes: { enabled: false } }).expect(200);
    await call(f.app, 'get', '/secrets/password/' + version + api).expect(403);
    await call(f.app, 'delete', '/secrets/password' + api).expect(200);
    await call(f.app, 'get', '/secrets/password' + api).expect(404);
  });
  it('rejects malformed input, unsupported versions/options and expired secrets safely', async () => {
    for (const body of [{ value: 123 }, { value: 'canary', surprise: 'canary' }, { value: 'x', attributes: { enabled: 'yes' } }]) {
      const res = await call(f.app, 'put', '/secrets/example' + api).send(body).expect(400);
      expect(JSON.stringify(res.body)).not.toContain('canary'); expect(res.body.error.code).toBe('BadParameter');
    }
    await call(f.app, 'put', '/secrets/example?api-version=7.4').send({ value: 'x' }).expect(400);
    await call(f.app, 'put', '/secrets/example' + api).send({ value: 'expired', attributes: { exp: 1 } }).expect(200);
    await call(f.app, 'get', '/secrets/example' + api).expect(403);
  });
  it('keeps RSA private keys inside the vault and decrypts old versions after rotation', async () => {
    const key = await call(f.app, 'post', '/keys/data/create' + api).send({ kty: 'RSA', key_size: 2048, key_ops: ['encrypt', 'decrypt'] }).expect(200);
    expect(key.body.key).toMatchObject({ kty: 'RSA', e: 'AQAB', key_ops: ['encrypt', 'decrypt'] });
    expect(key.body.key.d).toBeUndefined(); expect(key.body.key.p).toBeUndefined();
    const version = key.body.key.kid.split('/').pop();
    const encrypted = await call(f.app, 'post', `/keys/data/${version}/encrypt` + api)
      .send({ alg: 'RSA-OAEP-256', value: Buffer.from('message').toString('base64url') }).expect(200);
    await call(f.app, 'post', '/keys/data/create' + api).send({ kty: 'RSA', key_size: 2048 }).expect(200);
    const plain = await call(f.app, 'post', `/keys/data/${version}/decrypt` + api).send({ alg: 'RSA-OAEP-256', value: encrypted.body.value }).expect(200);
    expect(Buffer.from(plain.body.value, 'base64url').toString()).toBe('message');
    await call(f.app, 'patch', `/keys/data/${version}` + api).send({ attributes: { enabled: false } }).expect(200);
    await call(f.app, 'post', `/keys/data/${version}/decrypt` + api).send({ alg: 'RSA-OAEP-256', value: encrypted.body.value }).expect(403);
    await call(f.app, 'post', '/keys/ec/create' + api).send({ kty: 'EC' }).expect(400);
  });
  it('handles object-prototype-like names as ordinary vault names', async () => {
    await call(f.app, 'put', '/secrets/constructor' + api).send({ value: 'valid' }).expect(200);
    expect((await call(f.app, 'get', '/secrets/constructor' + api).expect(200)).body.value).toBe('valid');
  });
  it('rejects browser origins, namespace ID mismatches, malformed JSON and unauthorized crypto', async () => {
    await call(f.app, 'get', '/secrets/none' + api).set('Origin', 'https://untrusted.example').expect(403);
    await call(f.app, 'get', '/namespaces/dev/b/secrets/none' + api).expect(403);
    const malformed = await call(f.app, 'put', '/secrets/none' + api).set('Content-Type', 'application/json').send('{"value":"canary"').expect(400);
    expect(JSON.stringify(malformed.body)).not.toContain('canary');
  });
});
