import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { describeSystemError, fail, VaultError } from './errors.js';
import { Scope } from './types.js';
import { scopePart } from './validation.js';
import { databaseFromMongoUri } from './mongodb-url.js';
export type Permission = 'read' | 'write' | 'crypto' | 'list';
export interface Grant extends Scope { token: string; permissions: Permission[] }
export interface VaultConfig { mongoUri: string; masterKey: Buffer; baseUrl: string; grants: Grant[] }
function bootstrapCheck(condition: unknown, detail: string): asserts condition {
  if (!condition) fail(500, 'InvalidBootstrap', detail);
}
export function validateConfig(config: VaultConfig): VaultConfig {
  try {
    databaseFromMongoUri(config.mongoUri);
    bootstrapCheck(Buffer.isBuffer(config.masterKey) && config.masterKey.length === 32, 'VAULT_MASTER_KEY must be the base64 encoding of exactly 32 bytes.');
    let url: URL;
    try { url = new URL(config.baseUrl); } catch { fail(500, 'InvalidBootstrap', 'VAULT_BASE_URL must be a valid loopback URL, for example http://127.0.0.1:4000.'); }
    bootstrapCheck(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.pathname === '/' && !url.search && !url.hash && !url.username && !url.password, 'VAULT_BASE_URL must use http://127.0.0.1 with a port and no path, credentials or query parameters.');
    bootstrapCheck(Array.isArray(config.grants) && config.grants.length > 0, 'VAULT_GRANTS must be a non-empty JSON array of caller grants.');
    for (const grant of config.grants) {
      scopePart(grant.environment); scopePart(grant.tenant);
      bootstrapCheck(typeof grant.token === 'string' && grant.token.length >= 32 && grant.token.trim() === grant.token, 'VAULT_GRANTS tokens must contain at least 32 characters without surrounding whitespace.');
      bootstrapCheck(Array.isArray(grant.permissions) && grant.permissions.length > 0 && grant.permissions.every(p => ['read', 'write', 'crypto', 'list'].includes(p)), 'VAULT_GRANTS permissions must be a non-empty array containing read, write, crypto or list.');
    }
    return config;
  } catch (error) {
    if (error instanceof VaultError && error.code === 'InvalidBootstrap') throw error;
    fail(500, 'InvalidBootstrap', 'VAULT_GRANTS entries must have valid environment/tenant identifiers, a caller token and permissions.');
  }
}
export function loadConfig(env = process.env): VaultConfig {
  try {
    const encoded = env.VAULT_MASTER_KEY ?? '';
    bootstrapCheck(/^[A-Za-z0-9+/]{43}=$/.test(encoded), 'VAULT_MASTER_KEY is missing or invalid; supply the base64 encoding of exactly 32 bytes.');
    let grants: unknown;
    try { grants = JSON.parse(env.VAULT_GRANTS ?? ''); }
    catch { fail(500, 'InvalidBootstrap', 'VAULT_GRANTS is missing or invalid JSON; use a quoted JSON array of caller grants in .env.'); }
    return validateConfig({ mongoUri: env.VAULT_MONGODB_URI ?? '', masterKey: Buffer.from(encoded, 'base64'),
      baseUrl: env.VAULT_BASE_URL ?? 'http://127.0.0.1:4000', grants: grants as Grant[] });
  } catch (error) {
    if (error instanceof VaultError && error.code === 'InvalidBootstrap') throw error;
    fail(500, 'InvalidBootstrap', 'Unable to load bootstrap configuration; check the required variables in env.example.');
  }
}
export function loadBootstrapConfig(envFile = '.env', env = process.env): VaultConfig {
  let fromFile: NodeJS.ProcessEnv = {};
  try { fromFile = parseEnv(readFileSync(envFile, 'utf8')); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') fail(500, 'InvalidBootstrap', `Cannot read .env; check that it is a readable file. ${describeSystemError(error)}`); }
  return loadConfig({ ...fromFile, ...env });
}
export function authorize(config: VaultConfig, auth: unknown, scope: Scope, permission?: Permission) {
  if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) fail(401, 'Unauthorized');
  const digest = createHash('sha256').update(auth.slice(7)).digest();
  const matching = config.grants.filter(g => timingSafeEqual(createHash('sha256').update(g.token).digest(), digest));
  if (!matching.length) fail(401, 'Unauthorized');
  if (!matching.some(g => g.environment === scope.environment && g.tenant === scope.tenant && (permission === undefined || g.permissions.includes(permission)))) fail(403, 'Forbidden');
}
