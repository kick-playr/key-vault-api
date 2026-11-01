import type { RuntimeManifest } from '@kick-playr/local-key-vault/runtime-client';
import type { JsonWebKey } from 'node:crypto';
export interface Attributes { enabled: boolean; created: number; updated: number; nbf?: number; exp?: number; recoveryLevel: 'Purgeable' }
export interface Version {
  version: string; attributes: Attributes; tags?: Record<string, string>; contentType?: string;
  value?: string; privateKey?: JsonWebKey; publicKey?: JsonWebKey; keySize?: number; keyOps?: string[];
}
export interface Namespace {
  generation: number; keys: Record<string, Version[]>; secrets: Record<string, Version[]>;
  tombstones: string[];
  runtimeManifests?: Record<string, { currentRevision: number; versions: Record<string, RuntimeManifest> }>;
  reconciliation?: { revision: number; digest: string; manifestDigest: string };
  audit: { time: number; action: string; name: string }[];
}
export interface Scope { environment: string; tenant: string }
export const scopeId = (scope: Scope) => JSON.stringify([scope.environment, scope.tenant]);
export function emptyNamespace(): Namespace {
  return { generation: 0, keys: {}, secrets: {}, tombstones: [], audit: [] };
}
