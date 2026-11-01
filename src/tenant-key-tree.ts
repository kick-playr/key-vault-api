import { createHash } from 'node:crypto';
import { fail } from './errors.js';
import type { Attributes, Scope } from './types.js';
import { scopePart } from './validation.js';
import { VaultService } from './vault.js';

const roles = [{ role: 'wrapping', path: 'wrapping/v1' }, { role: 'index', path: 'index' }, { role: 'control', path: 'control' }] as const;
export function tenantKeySet(scope: Scope, reference: string) {
  scopePart(scope.environment); scopePart(scope.tenant);
  const match = typeof reference === 'string' && /^([a-z0-9]+(?:-[a-z0-9]+)*):([^:]+):key$/.exec(reference);
  if (!match || match[1]!.length > 48 || match[2] !== scope.tenant) fail(400, 'InvalidKeySetName', 'Use <profile>:<selected-tenant>:key, for example workflow-local:fcrww:key. Profile must be lowercase kebab-case, at most 48 characters.');
  return { reference, profile: match[1]!, entries: roles.map(entry => ({ ...entry,
    name: `tk-${entry.role}-` + createHash('sha256').update(JSON.stringify([scope.environment, scope.tenant, reference, entry.path])).digest('hex'),
    logicalPath: `${reference}/${entry.path}`,
  })) };
}
export interface KeyTreeNode {
  name: string; children?: KeyTreeNode[]; envName?: string; secretName?: string;
  id?: string; version?: string; versionId?: string; attributes?: Attributes;
}
export class TenantKeyTreeService {
  constructor(private readonly vault: VaultService) {}
  tree(scope: Scope) {
    return this.vault.store.read(scope, ns => {
      const sets = new Map<string, { profile: string; leaves: Map<string, KeyTreeNode> }>();
      for (const [name, versions] of Object.entries(ns?.secrets ?? {})) {
        const item = versions.at(-1), tags = item?.tags;
        if (!item || !tags || typeof tags.keySet !== 'string' || !/^[A-Z][A-Z0-9_]{0,127}$/.test(tags.envName ?? '')) continue;
        let layout: ReturnType<typeof tenantKeySet>;
        try { layout = tenantKeySet(scope, tags.keySet); } catch { continue; }
        const entry = layout.entries.find(e => e.name === name && e.role === tags.keyRole && e.logicalPath === tags.logicalPath);
        if (!entry) continue;
        const set = sets.get(layout.reference) ?? { profile: layout.profile, leaves: new Map<string, KeyTreeNode>() };
        set.leaves.set(entry.path, { name: entry.path.split('/').at(-1)!, envName: tags.envName!, secretName: name,
          id: `${this.vault.baseUrl}/namespaces/${scope.environment}/${scope.tenant}/secrets/${name}`,
          version: item.version, versionId: this.vault.id(scope, 'secrets', name, item.version), attributes: item.attributes });
        sets.set(layout.reference, set);
      }
      return { ...scope, keySets: [...sets.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([name, set]) => ({
        name, profile: set.profile, children: roles.flatMap(entry => {
          const leaf = set.leaves.get(entry.path); if (!leaf) return [];
          return [entry.role === 'wrapping' ? { name: 'wrapping', children: [leaf] } : leaf];
        }),
      })) };
    });
  }
}
