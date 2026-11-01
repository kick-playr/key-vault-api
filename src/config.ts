import { createHash, timingSafeEqual } from 'node:crypto';
import { requireCondition as check, fail } from './errors';
import { Scope } from './types';
import { scopePart } from './validation';
export type Permission = 'read' | 'write' | 'crypto';
export interface Grant extends Scope { token: string; permissions: Permission[] }
export interface VaultConfig { mongoUri: string; mongoDatabase: string; masterKey: Buffer; baseUrl: string; grants: Grant[] }
export function validateConfig(config: VaultConfig): VaultConfig {
  try {
    check(typeof config.mongoUri === 'string' && /^mongodb(?:\+srv)?:\/\/\S+$/.test(config.mongoUri));
    check(typeof config.mongoDatabase === 'string' && /^[a-zA-Z][a-zA-Z0-9_-]{0,62}$/.test(config.mongoDatabase));
    check(Buffer.isBuffer(config.masterKey) && config.masterKey.length === 32);
    const url = new URL(config.baseUrl);
    check(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.pathname === '/' && !url.search && !url.hash && !url.username && !url.password);
    check(Array.isArray(config.grants) && config.grants.length > 0);
    for (const grant of config.grants) {
      scopePart(grant.environment); scopePart(grant.tenant);
      check(typeof grant.token === 'string' && grant.token.length >= 32 && grant.token.trim() === grant.token);
      check(Array.isArray(grant.permissions) && grant.permissions.length > 0 && grant.permissions.every(p => ['read', 'write', 'crypto'].includes(p)));
    }
    return config;
  } catch { fail(500, 'InvalidBootstrap'); }
}
export function loadConfig(env = process.env): VaultConfig {
  try {
    const encoded = env.VAULT_MASTER_KEY ?? '';
    check(/^[A-Za-z0-9+/]{43}=$/.test(encoded));
    return validateConfig({ mongoUri: env.VAULT_MONGODB_URI ?? '', mongoDatabase: env.VAULT_MONGODB_DATABASE ?? 'local_key_vault', masterKey: Buffer.from(encoded, 'base64'),
      baseUrl: env.VAULT_BASE_URL ?? 'http://127.0.0.1:4567', grants: JSON.parse(env.VAULT_GRANTS ?? '') });
  } catch { fail(500, 'InvalidBootstrap'); }
}
export function authorize(config: VaultConfig, auth: unknown, scope: Scope, permission?: Permission) {
  if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) fail(401, 'Unauthorized');
  const digest = createHash('sha256').update(auth.slice(7)).digest();
  const matching = config.grants.filter(g => timingSafeEqual(createHash('sha256').update(g.token).digest(), digest));
  if (!matching.length) fail(401, 'Unauthorized');
  if (!matching.some(g => g.environment === scope.environment && g.tenant === scope.tenant && (permission === undefined || g.permissions.includes(permission)))) fail(403, 'Forbidden');
}
