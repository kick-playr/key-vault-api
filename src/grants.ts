import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Grant, Permission } from './config.js';
import { fail } from './errors.js';
import { MongoStore } from './store.js';
import type { Scope } from './types.js';
import { scopePart } from './validation.js';

export interface GrantMetadata extends Scope { id: string; permissions: Permission[]; enabled: boolean }
export interface StoredGrant extends GrantMetadata { tokenHash: string }
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const metadata = ({ tokenHash: _, ...grant }: StoredGrant): GrantMetadata => structuredClone(grant);
export function validatePermissions(value: unknown): Permission[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 10000 ||
      !value.every(p => ['read', 'write', 'crypto', 'list'].includes(p))) fail(400, 'InvalidGrants');
  return [...new Set(value)];
}
function validateGrant(value: unknown): Grant {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(400, 'InvalidGrants');
    const g = value as Grant;
    if (typeof g.token !== 'string' || g.token.length < 32 || g.token.length > 4096 || /\s/.test(g.token)) fail(400, 'InvalidGrants');
    return { token: g.token, environment: scopePart(g.environment), tenant: scopePart(g.tenant), permissions: validatePermissions(g.permissions) };
  } catch { fail(400, 'InvalidGrants'); }
}
function stored(input: Grant): StoredGrant {
  const grant = validateGrant(input), tokenHash = hash(grant.token);
  return { id: hash(JSON.stringify([tokenHash, grant.environment, grant.tenant])), tokenHash,
    environment: grant.environment, tenant: grant.tenant, permissions: grant.permissions, enabled: true };
}
export class GrantService {
  constructor(private readonly store: MongoStore) {}
  async create(scope: Scope, permissions: unknown) {
    const token = randomBytes(32).toString('base64url');
    const grant = stored({ ...scope, permissions: validatePermissions(permissions), token });
    await this.store.transactionGrants(grants => { grants.push(grant); });
    return { ...metadata(grant), token };
  }
  async rotate(id: string) {
    if (!/^[a-f0-9]{64}$/.test(id)) fail(400, 'InvalidGrants');
    const token = randomBytes(32).toString('base64url');
    return this.store.transactionGrants(grants => {
      const previous = grants.find(g => g.id === id);
      if (!previous) fail(404, 'GrantNotFound');
      if (!previous.enabled) fail(409, 'GrantRevoked');
      const replacement = stored({ environment: previous.environment, tenant: previous.tenant, permissions: previous.permissions, token });
      previous.enabled = false;
      grants.push(replacement);
      return { ...metadata(replacement), token };
    });
  }
  async import(input: unknown) {
    if (!Array.isArray(input) || !input.length || input.length > 10000) fail(400, 'InvalidGrants');
    const candidates = new Map<string, StoredGrant>();
    for (const value of input) {
      const grant = stored(validateGrant(value)), previous = candidates.get(grant.id);
      if (previous) previous.permissions = [...new Set([...previous.permissions, ...grant.permissions])];
      else candidates.set(grant.id, grant);
    }
    return this.store.transactionGrants(grants => {
      const ids = new Set(grants.map(g => g.id)); let imported = 0;
      for (const grant of candidates.values()) if (!ids.has(grant.id)) { grants.push(grant); ids.add(grant.id); imported++; }
      return { imported, skipped: input.length - imported };
    });
  }
  async list(): Promise<GrantMetadata[]> { return (await this.store.readGrants()).map(metadata); }
  async revoke(id: string) { return this.update(id, grant => { grant.enabled = false; }); }
  async setPermissions(id: string, input: unknown) {
    const permissions = validatePermissions(input);
    return this.update(id, grant => { grant.permissions = permissions; });
  }
  private async update(id: string, fn: (grant: StoredGrant) => void) {
    if (!/^[a-f0-9]{64}$/.test(id)) fail(400, 'InvalidGrants');
    return this.store.transactionGrants(grants => {
      const grant = grants.find(g => g.id === id); if (!grant) fail(404, 'GrantNotFound');
      fn(grant); return metadata(grant);
    });
  }
  async authorize(auth: unknown, scope: Scope, permissions: Permission[] = []): Promise<void> {
    await this.authenticatedGrants(auth, scope, permissions);
  }
  async authenticatedGrants(auth: unknown, scope: Scope, permissions: Permission[] = []): Promise<GrantMetadata[]> {
    if (typeof auth !== 'string' || !auth.startsWith('Bearer ') || auth.length > 4103 || auth.length <= 7) fail(401, 'Unauthorized');
    const digest = Buffer.from(hash(auth.slice(7)), 'hex');
    const matching = (await this.store.readGrants()).filter(g => g.enabled && timingSafeEqual(Buffer.from(g.tokenHash, 'hex'), digest));
    if (!matching.length) fail(401, 'Unauthorized');
    if (!permissions.every(p => matching.some(g => g.environment === scope.environment && g.tenant === scope.tenant && g.permissions.includes(p))) ||
        !matching.some(g => g.environment === scope.environment && g.tenant === scope.tenant)) fail(403, 'Forbidden');
    return matching.filter(g => g.environment === scope.environment && g.tenant === scope.tenant).map(metadata);
  }
}
