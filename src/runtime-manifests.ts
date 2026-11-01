import { parseRuntimeManifest, type RuntimeManifest } from '@kick-playr/local-key-vault/runtime-client';
import { fail } from './errors.js';
import type { MongoStore } from './store.js';
import type { Namespace, Scope } from './types.js';

export const MAX_RUNTIME_MANIFEST_BYTES = 64 * 1024;
export function validatedManifest(input: unknown): RuntimeManifest {
  try {
    if (Buffer.byteLength(JSON.stringify(input)) > MAX_RUNTIME_MANIFEST_BYTES) fail(413, 'ManifestTooLarge');
    return parseRuntimeManifest(input);
  } catch (error) {
    if (error && typeof error === 'object' && 'status' in error && error.status === 413) throw error;
    fail(400, 'InvalidRuntimeManifest');
  }
}
function applicationName(application: string) {
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(application)) fail(400, 'InvalidRuntimeManifest');
}
function matches(scope: Scope, application: string, manifest: RuntimeManifest) {
  applicationName(application);
  if (manifest.application !== application || manifest.scope.environment !== scope.environment || manifest.scope.tenant !== scope.tenant) fail(403, 'Forbidden');
}
/** Apply a fully validated batch within one namespace CAS. History is immutable. */
export function publishManifests(namespace: Namespace, scope: Scope, manifests: RuntimeManifest[]) {
  const next = structuredClone(namespace.runtimeManifests ?? {});
  for (const manifest of manifests) {
    matches(scope, manifest.application, manifest);
    const revision = manifest.request.bindingRevision;
    const saved = Object.hasOwn(next, manifest.application) ? next[manifest.application] : undefined;
    const existing = saved?.versions[String(revision)];
    if (existing) {
      if (JSON.stringify(existing) !== JSON.stringify(manifest)) fail(409, 'ManifestConflict');
      continue;
    }
    if (saved && revision <= saved.currentRevision) fail(409, 'ManifestConflict');
    next[manifest.application] = { currentRevision: revision, versions: { ...saved?.versions, [String(revision)]: manifest } };
  }
  namespace.runtimeManifests = next;
}
export class RuntimeManifestService {
  constructor(private readonly store: Pick<MongoStore, 'read' | 'transaction'>) {}
  async publish(scope: Scope, application: string, input: unknown): Promise<RuntimeManifest> {
    const manifest = validatedManifest(input);
    matches(scope, application, manifest);
    return this.store.transaction(scope, ns => { publishManifests(ns, scope, [manifest]); return manifest; });
  }
  async get(scope: Scope, application: string, revision?: string): Promise<RuntimeManifest> {
    applicationName(application);
    if (revision !== undefined && (!/^[1-9][0-9]*$/.test(revision) || !Number.isSafeInteger(Number(revision)))) fail(400, 'InvalidRuntimeManifest');
    return this.store.read(scope, ns => {
      const all = ns?.runtimeManifests;
      const saved = all && Object.hasOwn(all, application) ? all[application] : undefined;
      const manifest = saved?.versions[revision ?? String(saved.currentRevision)];
      if (!manifest) fail(404, 'ManifestNotFound');
      const result = validatedManifest(manifest);
      matches(scope, application, result);
      return result;
    });
  }
}
