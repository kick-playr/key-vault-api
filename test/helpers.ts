import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createApp } from '../src/app';
import { VaultConfig } from '../src/config';

export const token = 'test-only-token-aaaaaaaaaaaaaaaaaaaaaaaa';
export const otherToken = 'test-only-token-bbbbbbbbbbbbbbbbbbbbbbbb';
export const api = '?api-version=2025-07-01';
export async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'vault-api-'));
  const config: VaultConfig = {
    path: join(dir, 'store.vault'), masterKey: randomBytes(32), baseUrl: 'http://127.0.0.1:4567',
    grants: [
      { token, environment: 'dev', tenant: 'a', permissions: ['read', 'write', 'crypto'] },
      { token: otherToken, environment: 'dev', tenant: 'b', permissions: ['read', 'write', 'crypto'] },
      { token, environment: 'dev', tenant: '_shared', permissions: ['read', 'write', 'crypto'] },
    ],
  };
  const app = await createApp(config); await app.init();
  const result = { app, config, cleanup: async () => { await result.app.close(); await rm(dir, { recursive: true, force: true }); } };
  return result;
}
export function call(app: INestApplication, method: 'get' | 'put' | 'post' | 'patch' | 'delete', path: string, tenant = 'a') {
  return request(app.getHttpServer())[method](path).set('Authorization', `Bearer ${tenant === 'b' ? otherToken : token}`)
    .set('x-vault-environment', 'dev').set('x-vault-tenant', tenant);
}
