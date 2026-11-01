import { timingSafeEqual } from 'node:crypto';
import { fail, requireCondition as check } from './errors.js';
import { digest, Manifest, parseManifest, vaultName } from './manifest.js';
import { Namespace, Scope } from './types.js';
import { object } from './validation.js';
import { active, changed, find, newKey, newSecret, VaultService } from './vault.js';

export interface Snapshot {
  environment: string; tenant: string; generation: number; revision: number;
  manifestDigest: string; expiresAt: number; mappings: Record<string, string>;
}
export class ProvisioningService {
  constructor(private readonly vault: VaultService) {}
  private snapshotOf(scope: Scope, ns: Namespace, manifest: Manifest): Snapshot {
    if (!ns.reconciliation || ns.reconciliation.manifestDigest !== digest(manifest)) fail(409, 'ManifestNotProvisioned');
    const mappings: Record<string, string> = {};
    for (const entry of manifest.entries) {
      const kind = entry.kind === 'key' ? 'keys' : 'secrets';
      const name = vaultName(scope, entry.kind, entry.purpose);
      const item = find(ns, kind, name); active(item);
      if (kind === 'keys' && (item.keySize !== entry.keySize || digest([...(item.keyOps ?? [])].sort()) !== digest(entry.keyOps))) fail(409, 'KeyPolicyMismatch');
      mappings[entry.envName] = kind === 'keys' ? this.vault.id(scope, kind, name, item.version) : item.value!;
    }
    return { ...scope, generation: ns.generation, revision: ns.reconciliation.revision, manifestDigest: digest(manifest), expiresAt: Date.now() + 30000, mappings };
  }
  async reconcile(scope: Scope, input: unknown) {
    const body = object(input, ['revision', 'manifest', 'secrets']);
    check(Number.isSafeInteger(body.revision) && (body.revision as number) > 0);
    const revision = body.revision as number, manifest = parseManifest(body.manifest, scope);
    const secretPurposes = manifest.entries.filter(e => e.kind === 'secret').map(e => e.purpose);
    const secrets = object(body.secrets ?? {}, secretPurposes);
    check(Object.values(secrets).every(s => typeof s === 'string' && Buffer.byteLength(s) <= 25600));
    const sortedSecrets = Object.fromEntries(Object.entries(secrets).sort(([a], [b]) => a.localeCompare(b)));
    const requestDigest = digest({ manifest, secrets: sortedSecrets });
    return this.vault.store.transaction(scope, async ns => {
      const old = ns.reconciliation;
      if (old && (revision < old.revision || revision === old.revision && old.digest !== requestDigest)) fail(409, 'RevisionConflict');
      if (old && revision === old.revision) return this.snapshotOf(scope, ns, manifest);
      for (const entry of manifest.entries) {
        const kind = entry.kind === 'key' ? 'keys' : 'secrets', name = vaultName(scope, entry.kind, entry.purpose);
        const existing = Object.hasOwn(ns[kind], name) ? ns[kind][name]?.at(-1) : undefined;
        if (existing) {
          active(existing);
          if (kind === 'keys' && (existing.keySize !== entry.keySize || digest([...(existing.keyOps ?? [])].sort()) !== digest(entry.keyOps))) fail(409, 'KeyPolicyMismatch');
          if (kind === 'secrets' && Object.hasOwn(secrets, entry.purpose)) {
            const a = Buffer.from(digest(existing.value)), b = Buffer.from(digest(secrets[entry.purpose]));
            if (!timingSafeEqual(a, b)) { ns.secrets[name]!.push(newSecret({ value: secrets[entry.purpose], tags: existing.tags })); changed(ns, 'reconcile:secret', name); }
          }
        } else {
          if (ns.tombstones.includes(`${kind}/${name}`)) fail(409, 'RevokedResource');
          if (kind === 'secrets' && !Object.hasOwn(secrets, entry.purpose)) fail(409, 'MissingProvidedSecret');
          const item = kind === 'keys'
            ? await newKey({ kty: entry.kty, key_size: entry.keySize, key_ops: entry.keyOps, tags: { purpose: entry.purpose } })
            : newSecret({ value: secrets[entry.purpose], tags: { purpose: entry.purpose } });
          ns[kind][name] = [item]; changed(ns, 'provision:' + kind, name);
        }
      }
      ns.reconciliation = { revision, digest: requestDigest, manifestDigest: digest(manifest) };
      changed(ns, 'reconcile', 'manifest');
      return this.snapshotOf(scope, ns, manifest);
    });
  }
  snapshot(scope: Scope, input: unknown) {
    const body = object(input, ['manifest']);
    const manifest = parseManifest(body.manifest, scope);
    return this.vault.store.read(scope, ns => {
      if (!ns) fail(409, 'ManifestNotProvisioned');
      return this.snapshotOf(scope, ns, manifest);
    });
  }
}
