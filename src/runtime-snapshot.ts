import { bindingDigest, parseSnapshotRequest } from '@kick-playr/local-key-vault/runtime-client';
import type { RuntimeSnapshot, RuntimeSnapshotRequest } from '@kick-playr/local-key-vault/runtime-client';
import { fail } from './errors.js';
import { vaultName } from './manifest.js';
import { tenantKeySet } from './tenant-key-tree.js';
import type { Namespace, Scope } from './types.js';
import { active, find, VaultService } from './vault.js';

/** Startup reads only. Every member is resolved from a single committed namespace. */
export class RuntimeSnapshotService {
  constructor(private readonly vault: VaultService) {}
  async snapshot(scope: Scope, input: unknown): Promise<RuntimeSnapshot> {
    let request: RuntimeSnapshotRequest;
    try {
      if (Buffer.byteLength(JSON.stringify(input)) > 65536) fail(413, 'RequestTooLarge');
      request = parseSnapshotRequest(input);
      for (const k of request.keySets) tenantKeySet(scope, k.reference);
    } catch (error) {
      if (error && typeof error === 'object' && 'status' in error && error.status === 413) throw error;
      fail(400, 'BadParameter');
    }
    return this.vault.store.read(scope, ns => this.resolve(scope, request, ns));
  }
  private resolve(scope: Scope, request: RuntimeSnapshotRequest, ns: Namespace | undefined): RuntimeSnapshot {
    if (!ns || !Number.isSafeInteger(ns.generation) || ns.generation < 0) fail(404, 'SecretNotFound');
    const read = (name: string, version: string) => {
      const item = find(ns, 'secrets', name, version); active(item);
      if (typeof item.value !== 'string') fail(409, 'BindingMismatch');
      return item;
    };
    const keySets = request.keySets.map(k => {
      const layout = tenantKeySet(scope, k.reference);
      const role = (kind: 'wrapping' | 'index' | 'control', version: string) => {
        const entry = layout.entries.find(e => e.role === kind)!;
        const item = read(entry.name, version), tags = item.tags;
        if (!tags || tags.keySet !== k.reference || tags.keyRole !== kind || tags.logicalPath !== entry.logicalPath || tags.envName !== k.mappings[kind]) fail(409, 'BindingMismatch');
        const bytes = Buffer.from(item.value!, 'base64');
        try { if (item.value!.length !== 44 || bytes.length !== 32 || bytes.toString('base64') !== item.value) fail(409, 'BindingMismatch'); } finally { bytes.fill(0); }
        return { vaultVersion: item.version, value: item.value!, attributes: { ...item.attributes } };
      };
      const wrappingVersions = k.wrappingVersions.map(v => ({ keyVersion: v.keyVersion, ...role('wrapping', v.vaultVersion) }));
      const index = role('index', k.indexVersion), control = role('control', k.controlVersion);
      if (index.value === control.value || wrappingVersions.some(v => v.value === index.value || v.value === control.value)) fail(409, 'BindingMismatch');
      return { reference: k.reference, mappings: { ...k.mappings }, currentWrappingVersion: k.currentWrappingVersion, wrappingVersions, index, control };
    });
    const secrets = request.secrets.map(s => {
      const item = read(vaultName(scope, 'secret', s.purpose), s.version);
      if (item.tags?.purpose !== undefined && item.tags.purpose !== s.purpose || item.tags?.envName !== undefined && item.tags.envName !== s.mapping) fail(409, 'BindingMismatch');
      return { ...s, value: item.value!, attributes: { ...item.attributes } };
    });
    const result: RuntimeSnapshot = { schemaVersion: 1, ...scope, bindingRevision: request.bindingRevision, bindingDigest: bindingDigest(request), generation: ns.generation, loadedAt: Date.now(), keySets, secrets };
    if (Buffer.byteLength(JSON.stringify(result)) > 4 * 1024 * 1024) fail(503, 'SnapshotUnavailable');
    return result;
  }
}
