import request from 'supertest';
import { api, call, fixture, token } from './helpers.js';
import { createApp } from '../src/app.js';

describe('least-privilege callers', () => {
  it('enforces read/write/crypto permissions separately and hides values from errors', async () => {
    const f = await fixture();
    try {
      await call(f.app, 'put', '/secrets/secret' + api).send({ value: 'restricted-canary' }).expect(200);
      await f.app.close();
      const reader = 'reader-test-only-cccccccccccccccccccccc';
      const writer = 'writer-test-only-dddddddddddddddddddddd';
      const crypto = 'crypto-test-only-eeeeeeeeeeeeeeeeeeeeee';
      await f.addGrants([
        { token: reader, environment: 'dev', tenant: 'a', permissions: ['read'] },
        { token: writer, environment: 'dev', tenant: 'a', permissions: ['write'] },
        { token: crypto, environment: 'dev', tenant: 'a', permissions: ['crypto'] },
      ]);
      f.app = await createApp(f.config); await f.app.init();
      const read = (method: 'get' | 'put' | 'post', path: string, auth = reader) => request(f.app.getHttpServer())[method](path)
        .set('Authorization', `Bearer ${auth}`).set('x-vault-environment', 'dev').set('x-vault-tenant', 'a');
      await read('get', '/secrets/secret' + api).expect(200);
      await read('put', '/secrets/secret' + api).send({ value: 'no' }).expect(403);
      await read('post', '/keys/key/version/encrypt' + api).send({ alg: 'RSA-OAEP-256', value: 'a' }).expect(403);
      const response = await read('get', '/secrets/secret' + api, writer).expect(403);
      expect(JSON.stringify(response.body)).not.toContain('restricted-canary');
      await read('post', '/local/reconcile', writer).send({}).expect(403);
      await read('get', '/secrets/secret' + api, token + 'invalid').expect(401);
      await read('put', '/secrets/decrypt' + api, token).send({ value: 'protected' }).expect(200);
      await read('get', '/secrets/decrypt' + api, crypto).expect(403);
      await read('put', '/secrets/encrypt' + api, crypto).send({ value: 'forbidden' }).expect(403);
      await request(f.app.getHttpServer()).delete('/secrets/decrypt' + api).set('Authorization', `Bearer ${crypto}`)
        .set('x-vault-environment', 'dev').set('x-vault-tenant', 'a').expect(403);
      const secret = await read('get', '/secrets/secret' + api).expect(200);
      const version = secret.body.id.split('/').pop();
      const patched = await request(f.app.getHttpServer()).patch(`/secrets/secret/${version}` + api)
        .set('Authorization', `Bearer ${writer}`).set('x-vault-environment', 'dev').set('x-vault-tenant', 'a')
        .send({ tags: { updated: 'yes' } }).expect(200);
      expect(patched.body.value).toBeUndefined();
      const key = await read('post', '/keys/key/create' + api, token).send({ kty: 'RSA' }).expect(200);
      const keyVersion = key.body.key.kid.split('/').pop();
      for (const path of [`/keys/key/${keyVersion}/encrypt/`, `/KEYS/key/${keyVersion}/encrypt`]) {
        await read('post', path + api, writer).send({ alg: 'RSA-OAEP-256', value: 'eA' }).expect(403);
      }
      await read('post', '/local/reconcile/', writer).send({}).expect(403);
      await read('post', '/LOCAL/reconcile', writer).send({}).expect(403);
    } finally { await f.cleanup(); }
  });
});

describe('connection authentication', () => {
  it('requires the entire exact token and selected namespace before confirming a connection', async () => {
    const f = await fixture();
    try {
      for (const malformed of [token + 'asdfasdfasfs', token.slice(0, -1), 'invalid-test-token-000000000000000000']) {
        const response = await call(f.app, 'get', '/local/session').set('Authorization', `Bearer ${malformed}`).expect(401);
        expect(JSON.stringify(response.body)).not.toContain(malformed);
      }
      expect((await call(f.app, 'get', '/local/session').expect(200)).body).toEqual({ authenticated: true, environment: 'dev', tenant: 'a' });
      await call(f.app, 'get', '/local/session').set('x-vault-tenant', 'b').expect(403);
      await call(f.app, 'get', '/namespaces/dev/b/local/session').expect(403);
      for (const permission of ['read','write','crypto','list'] as const) {
        const credential = `connection-test-${permission}-0000000000000000000000000`;
        await f.addGrants([{ token: credential, environment: 'dev', tenant: 'a', permissions: [permission] }]);
        await call(f.app, 'get', '/local/session').set('Authorization', `Bearer ${credential}`).expect(200);
      }
    } finally { await f.cleanup(); }
  });
});
