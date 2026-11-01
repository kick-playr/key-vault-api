import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { randomBytes, randomUUID } from 'node:crypto';
import { createApp } from '../src/app.js';
import { VaultConfig } from '../src/config.js';
import { MongoClient } from 'mongodb';
import { mongoUri } from './mongo.js';

export const token = 'test-only-token-aaaaaaaaaaaaaaaaaaaaaaaa';
export const otherToken = 'test-only-token-bbbbbbbbbbbbbbbbbbbbbbbb';
export const api = '?api-version=2025-07-01';
export async function fixture() {
  const mongoDatabase = 'test_' + randomUUID().replaceAll('-', '');
  const config: VaultConfig = {
    mongoUri: `${mongoUri}/${mongoDatabase}`, masterKey: randomBytes(32), baseUrl: 'http://127.0.0.1:4000',
    grants: [
      { token, environment: 'dev', tenant: 'a', permissions: ['read', 'write', 'crypto'] },
      { token: otherToken, environment: 'dev', tenant: 'b', permissions: ['read', 'write', 'crypto'] },
      { token, environment: 'dev', tenant: '_shared', permissions: ['read', 'write', 'crypto'] },
    ],
  };
  const app = await createApp(config); await app.init();
  const result = { app, config, cleanup: async () => { await result.app.close(); const client = await new MongoClient(mongoUri).connect();
    try { await client.db(mongoDatabase).dropDatabase(); } finally { await client.close(); } } };
  return result;
}
export function call(app: INestApplication, method: 'get' | 'put' | 'post' | 'patch' | 'delete', path: string, tenant = 'a') {
  return request(app.getHttpServer())[method](path).set('Authorization', `Bearer ${tenant === 'b' ? otherToken : token}`)
    .set('x-vault-environment', 'dev').set('x-vault-tenant', tenant);
}
