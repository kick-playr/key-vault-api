import { jest } from '@jest/globals';
import request from 'supertest';
import { createHash, randomBytes } from 'node:crypto';
import { createApp } from '../src/app.js';
import { loadConfig, VaultConfig } from '../src/config.js';
import { MongoStore } from '../src/store.js';
import { emptyNamespace } from '../src/types.js';
import { AuditEvent, AuditService, auditDestinations, auditOperation, parseAuditDestinations } from '../src/audit.js';
import { EventEmitter } from 'node:events';
import { GrantService } from '../src/grants.js';

const token = 'audit-test-only-token-aaaaaaaaaaaaaaaa';
const api = '?api-version=2025-07-01';
const info = jest.spyOn(console, 'info').mockImplementation(() => {});
const errors = jest.spyOn(console, 'error').mockImplementation(() => {});
afterAll(() => { info.mockRestore(); errors.mockRestore(); });
beforeEach(() => { info.mockClear(); errors.mockClear(); });
async function fixture(audit?: unknown) {
  const ns = emptyNamespace(), events: any[] = [];
  const grants = [{ id: 'a'.repeat(64), tokenHash: createHash('sha256').update(token).digest('hex'), environment: 'dev', tenant: 'club', permissions: ['read', 'write', 'list', 'crypto'], enabled: true }];
  const store = {
    readGrants: async () => grants,
    read: async (_scope: unknown, fn: (value: typeof ns) => unknown) => structuredClone(fn(ns)),
    transaction: async (_scope: unknown, fn: (value: typeof ns) => unknown) => structuredClone(await fn(ns)),
    appendAudit: async (event: unknown) => { events.push(structuredClone(event)); },
    close: async () => {},
  };
  const spy = jest.spyOn(MongoStore, 'open').mockResolvedValue(store as any);
  let app;
  try { app = await createApp({ mongoUri: 'mongodb://127.0.0.1:1/audit-fixture', masterKey: randomBytes(32), baseUrl: 'http://127.0.0.1:4000', ...(audit ? { audit } : {}) } as VaultConfig); await app.init(); }
  finally { spy.mockRestore(); }
  const call = (method: 'get' | 'head' | 'put' | 'post' | 'patch' | 'delete', path: string) => request(app.getHttpServer())[method](path).set('Authorization', `Bearer ${token}`).set('x-vault-environment', 'dev').set('x-vault-tenant', 'club');
  return { app, call, events, store, ns, grants };
}

it('rejects invalid ENV audit destinations instead of silently falling back', () => {
  const env = { VAULT_MASTER_KEY: Buffer.alloc(32).toString('base64'), VAULT_MONGODB_URI: 'mongodb://127.0.0.1:1/audit', VAULT_AUDIT_DESTINATIONS: '{"write":"typo"}' };
  expect(() => loadConfig(env)).toThrow('InvalidBootstrap');
});

it('persists writes/crypto, prints reads/lists, and excludes payloads and credentials', async () => {
  const f = await fixture();
  try {
    const put = await f.call('put', '/secrets/example' + api).send({ value: 'audit-secret-canary', tags: { private: 'audit-tag-canary' } }).expect(200);
    await f.call('get', '/secrets/example' + api + '&private=audit-query-canary').expect(200);
    await f.call('get', '/secrets' + api).expect(200);
    await f.call('get', '/secrets/example/versions' + api).expect(200);
    await f.call('post', '/local/runtime-snapshot').send({ secret: 'audit-body-canary' }).expect(400);
    const key = await f.call('post', '/keys/testkey/create' + api).send({ kty: 'RSA' }).expect(200);
    const version = key.body.key.kid.split('/').at(-1);
    const encrypted = await f.call('post', `/keys/testkey/${version}/encrypt` + api).send({ alg: 'RSA-OAEP-256', value: Buffer.from('audit-crypto-canary').toString('base64url') }).expect(200);
    await f.call('post', `/keys/testkey/${version}/decrypt` + api).send({ alg: 'RSA-OAEP-256', value: encrypted.body.value }).expect(200);
    await f.app.close();
    expect(f.events.map(e => e.category)).toEqual(['write', 'write', 'crypto', 'crypto']);
    expect(f.events.slice(-2).map(e => e.action)).toEqual(['keys.encrypt', 'keys.decrypt']);
    const printed = info.mock.calls.map(([line]) => JSON.parse(line as string));
    expect(printed.map(e => e.category)).toEqual(['read', 'list', 'list', 'read']);
    expect(f.events[0]).toMatchObject({ environment: 'dev', tenant: 'club', grantIds: ['a'.repeat(64)], action: 'secrets.set', name: 'example', status: 200, outcome: 'success' });
    expect(f.events[0].requestId).toBe(put.headers['x-vault-request-id']);
    expect(new Set([...f.events, ...printed].map(e => e.requestId)).size).toBe(8);
    expect(f.ns.generation).toBe(2);
    const output = JSON.stringify([f.events, info.mock.calls, errors.mock.calls]);
    for (const canary of [token, createHash('sha256').update(token).digest('hex'), encrypted.body.value, 'audit-secret-canary', 'audit-tag-canary', 'audit-query-canary', 'audit-body-canary', 'audit-crypto-canary', Buffer.from('audit-crypto-canary').toString('base64url')]) expect(output).not.toContain(canary);
  } finally { await f.app.close(); }
});

it('audits denied aliases once and never invents an authenticated grant', async () => {
  const f = await fixture();
  try {
    await f.call('post', '/namespaces/dev/club/KEYS/missing/version/encrypt/' + api).set('Authorization', 'Bearer invalid-audit-token-canary').send({ value: 'not-logged' }).expect(401);
    await f.call('get', '/namespaces/dev/club/SECRETS' + api).set('x-vault-tenant', 'other').expect(403);
    await f.app.close();
    expect(f.events).toHaveLength(1);
    expect(f.events[0]).toMatchObject({ category: 'crypto', action: 'keys.encrypt', status: 401, outcome: 'denied', grantIds: [] });
    expect(info.mock.calls).toHaveLength(1);
    expect(JSON.parse(info.mock.calls[0]![0] as string)).toMatchObject({ category: 'list', status: 403, grantIds: [] });
  } finally { await f.app.close(); }
});

it('supports destination overrides, both/off and safe sink failures', async () => {
  const f = await fixture({ write: 'both', crypto: 'off', read: 'collection', list: 'off' });
  try {
    await f.call('put', '/secrets/example' + api).send({ value: 'safe' }).expect(200);
    await f.call('get', '/secrets/example' + api).expect(200);
    await f.call('get', '/secrets' + api).expect(200);
    await f.call('post', '/keys/missing/version/decrypt' + api).send({}).expect(400);
    f.store.appendAudit = async () => { throw Error('audit-database-credential-canary'); };
    await f.call('put', '/secrets/next' + api).send({ value: 'safe' }).expect(200);
    await f.app.close();
    expect(f.events.map(e => e.category)).toEqual(['write', 'read']);
    expect(info.mock.calls).toHaveLength(2);
    expect(errors.mock.calls).toHaveLength(1);
    expect(JSON.stringify(errors.mock.calls)).not.toContain('audit-database-credential-canary');
  } finally { await f.app.close(); }
});

it('strictly validates every ENV category and preserves defaults for partial overrides', () => {
  expect(parseAuditDestinations(undefined)).toEqual({ read: 'console', list: 'console', write: 'collection', crypto: 'collection' });
  expect(parseAuditDestinations('{"crypto":"both"}')).toEqual({ read: 'console', list: 'console', write: 'collection', crypto: 'both' });
  for (const invalid of ['', '{', 'null', '[]', 'true', '{"unknown":"console"}', '{"read":null}', '{"write":"mongodb"}', '{"__proto__":"console"}'])
    expect(() => parseAuditDestinations(invalid)).toThrow('InvalidBootstrap');
});

it('audits HEAD routes that Express serves through GET handlers, including denials', async () => {
  const f = await fixture({ write: 'off' });
  try {
    await f.call('put', '/secrets/example' + api).send({ value: 'audit-head-canary' }).expect(200);
    const read = await f.call('head', '/secrets/example' + api).expect(200);
    await f.call('head', '/namespaces/dev/club/SECRETS/' + api).expect(200);
    await f.call('head', '/local/session').set('Authorization', 'Bearer invalid-head-canary').expect(401);
    await f.app.close();
    const events = info.mock.calls.map(([line]) => JSON.parse(line as string));
    expect(events.map(e => [e.category, e.status])).toEqual([['read', 200], ['list', 200], ['read', 401]]);
    expect(events[0].requestId).toBe(read.headers['x-vault-request-id']);
    expect(f.events).toHaveLength(0);
    expect(JSON.stringify(events)).not.toContain('audit-head-canary');
  } finally { await f.app.close(); }
});

it('classifies all HTTP families without changing authorization semantics', () => {
  const cases = [
    ['GET', '/keys', 'list'], ['GET', '/secrets/a/versions', 'list'],
    ['GET', '/keys/a/version', 'read'], ['GET', '/local/key-tree', 'list'],
    ['GET', '/local/inventory', 'list'], ['GET', '/local/session', 'read'],
    ['POST', '/local/snapshot', 'read'], ['POST', '/local/runtime-snapshot', 'read'],
    ['POST', '/local/reconcile', 'write'], ['POST', '/keys/a/create', 'write'],
    ['PUT', '/secrets/a', 'write'], ['PATCH', '/keys/a/version', 'write'],
    ['PATCH', '/secrets/a/version', 'write'], ['DELETE', '/keys/a', 'write'],
    ['DELETE', '/secrets/a', 'write'], ['POST', '/keys/a/version/encrypt', 'crypto'],
    ['POST', '/keys/a/version/decrypt', 'crypto'],
  ];
  for (const [method, path, category] of cases) {
    expect(auditOperation(method!, path!)?.category).toBe(category);
    expect(auditOperation(method!, '/namespaces/dev/club' + path!.toUpperCase() + '/')?.category).toBe(category);
  }
  for (const path of ['/swagger', '/unknown', '/keys/a/version/extra', '/keys/a/version/encrypt']) expect(auditOperation('GET', path)).toBeUndefined();
  expect(auditOperation('GET', '/secrets/audit%20unsafe')).not.toHaveProperty('name');
});

it('logs parser failures and permission denials with authenticated identity, not error text', async () => {
  const f = await fixture();
  try {
    await f.call('put', '/secrets/malformed' + api).set('Content-Type', 'application/json').send('{"secret":"audit-parser-canary"').expect(400);
    f.grants[0]!.permissions = ['read'];
    await f.call('delete', '/secrets/malformed' + api).expect(403);
    await f.app.close();
    expect(f.events.map(e => e.status)).toEqual([400, 403]);
    expect(f.events[1]).toMatchObject({ grantIds: ['a'.repeat(64)], environment: 'dev', tenant: 'club', outcome: 'denied' });
    expect(JSON.stringify(f.events)).not.toContain('audit-parser-canary');
    await expect(new GrantService(f.store as any).authorize(`Bearer ${token}`, { environment: 'dev', tenant: 'club' }, ['read'])).resolves.toBeUndefined();
  } finally { await f.app.close(); }
});

it('drains pending inserts before shutdown and emits one event for finish plus close', async () => {
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const events: AuditEvent[] = [];
  const audit = new AuditService(auditDestinations(), { appendAudit: async event => { await gate; events.push(event); } });
  const res = Object.assign(new EventEmitter(), { statusCode: 200, writableFinished: true, setHeader: () => {} });
  audit.attach({ method: 'PUT', path: '/secrets/one' } as any, res as any);
  res.emit('finish'); res.emit('close');
  let closed = false;
  const closing = audit.close().then(() => { closed = true; });
  await Promise.resolve();
  expect(closed).toBe(false);
  release(); await closing;
  expect(events).toHaveLength(1);
  const aborted = Object.assign(new EventEmitter(), { statusCode: 200, writableFinished: false, setHeader: () => {} });
  audit.attach({ method: 'POST', path: '/keys/one/version/decrypt' } as any, aborted as any);
  aborted.emit('close'); aborted.emit('finish');
  await audit.close();
  expect(events).toHaveLength(2);
  expect(events[1]).toMatchObject({ status: 499, outcome: 'aborted', grantIds: [] });
});

it('inserts into a separate audit collection without updating a namespace', async () => {
  const calls: any[] = [];
  const client = { db: () => ({ collection: (name: string) => ({ insertOne: async (value: unknown) => { calls.push({ name, value }); } }) }) };
  const store = new (MongoStore as any)(client, {}, 'test');
  const event = { requestId: 'audit-id', category: 'write', status: 200 };
  await store.appendAudit(event);
  expect(calls).toEqual([{ name: 'vault_audit', value: { ...event, _id: 'audit-id' } }]);
});
