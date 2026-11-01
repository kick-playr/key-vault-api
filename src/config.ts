import { readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { describeSystemError, fail, VaultError } from './errors.js';
import { Scope } from './types.js';
import { databaseFromMongoUri } from './mongodb-url.js';
import { auditDestinations, AuditDestinations, parseAuditDestinations } from './audit.js';
export type Permission = 'read' | 'write' | 'crypto' | 'list';
export interface Grant extends Scope { token: string; permissions: Permission[] }
export interface VaultConfig { mongoUri: string; masterKey: Buffer; baseUrl: string; audit?: AuditDestinations }
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
    return { ...config, audit: auditDestinations(config.audit) };
  } catch (error) {
    if (error instanceof VaultError && error.code === 'InvalidBootstrap') throw error;
    fail(500, 'InvalidBootstrap', 'Invalid bootstrap configuration; check env.example.');
  }
}
export function loadConfig(env = process.env): VaultConfig {
  try {
    const encoded = env.VAULT_MASTER_KEY ?? '';
    bootstrapCheck(/^[A-Za-z0-9+/]{43}=$/.test(encoded), 'VAULT_MASTER_KEY is missing or invalid; supply the base64 encoding of exactly 32 bytes.');
    return validateConfig({ mongoUri: env.VAULT_MONGODB_URI ?? '', masterKey: Buffer.from(encoded, 'base64'),
      baseUrl: env.VAULT_BASE_URL ?? 'http://127.0.0.1:4000', audit: parseAuditDestinations(env.VAULT_AUDIT_DESTINATIONS) });
  } catch (error) {
    if (error instanceof VaultError && error.code === 'InvalidBootstrap') throw error;
    fail(500, 'InvalidBootstrap', 'Unable to load bootstrap configuration; check the required variables in env.example.');
  }
}
export function loadBootstrapEnvironment(envFile = '.env', env = process.env): NodeJS.ProcessEnv {
  let fromFile: NodeJS.ProcessEnv = {};
  try { fromFile = parseEnv(readFileSync(envFile, 'utf8')); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') fail(500, 'InvalidBootstrap', `Cannot read .env; check that it is a readable file. ${describeSystemError(error)}`); }
  return { ...fromFile, ...env };
}
export function loadBootstrapConfig(envFile = '.env', env = process.env): VaultConfig {
  return loadConfig(loadBootstrapEnvironment(envFile, env));
}
