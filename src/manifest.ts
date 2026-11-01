import { createHash } from 'node:crypto';
import { requireCondition as check } from './errors';
import { Scope } from './types';
import { envName, identifier, object } from './validation';
import { keyInput } from './vault';

export interface Entry {
  purpose: string; kind: 'key' | 'secret'; scope: 'tenant' | 'process'; envName: string;
  kty?: 'RSA'; keySize?: number; keyOps?: string[];
}
export interface Manifest { schemaVersion: 1; entries: Entry[] }
export function parseManifest(input: unknown, scope: Scope): Manifest {
  const body = object(input, ['schemaVersion', 'entries']);
  check(body.schemaVersion === 1 && Array.isArray(body.entries) && body.entries.length > 0 && body.entries.length <= 100);
  const purposes = new Set<string>(), mappings = new Set<string>();
  const entries = body.entries.map(raw => {
    const e = object(raw, ['purpose', 'kind', 'scope', 'envName', 'kty', 'keySize', 'keyOps']);
    const purpose = identifier(e.purpose), mapping = envName(e.envName);
    check(e.kind === 'key' || e.kind === 'secret');
    check(e.scope === (scope.tenant === '_shared' ? 'process' : 'tenant'));
    check(!purposes.has(purpose) && !mappings.has(mapping)); purposes.add(purpose); mappings.add(mapping);
    const common = { purpose, envName: mapping, kind: e.kind, scope: e.scope } as Entry;
    if (e.kind === 'key') {
      const parsed = keyInput({ kty: e.kty, key_size: e.keySize, key_ops: e.keyOps });
      return { ...common, kty: 'RSA' as const, keySize: parsed.size, keyOps: [...parsed.ops].sort() };
    }
    check(e.kty === undefined && e.keySize === undefined && e.keyOps === undefined);
    return common;
  });
  return { schemaVersion: 1, entries: entries.sort((a, b) => a.purpose.localeCompare(b.purpose)) };
}
export const digest = (input: unknown) => createHash('sha256').update(JSON.stringify(input)).digest('hex');
export const vaultName = (scope: Scope, kind: 'key' | 'secret', purpose: string) =>
  'kv-' + digest([scope.environment, scope.tenant, kind, purpose]);
