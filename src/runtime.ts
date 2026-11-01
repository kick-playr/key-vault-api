// Server-only entry point. Never import into a browser application.
import { digest, Manifest, parseManifest } from './manifest';
import { Snapshot } from './provisioning';
import { Scope, scopeId } from './types';
import { scopePart } from './validation';

export interface RuntimeConfig {
  baseUrl: string; token: (scope: Scope) => string; ttlMs?: number; timeoutMs?: number;
}
export type RuntimeSnapshot = Readonly<Omit<Snapshot, 'mappings'> & { mappings: Readonly<Record<string, string>> }>;

export class RuntimeVault {
  private readonly cache = new Map<string, RuntimeSnapshot>();
  private readonly queues = new Map<string, Promise<unknown>>();
  private readonly watermarks = new Map<string, { revision: number; generation: number }>();
  private readonly ttlMs: number;
  constructor(private readonly config: RuntimeConfig) {
    const url = new URL(config.baseUrl);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new Error('InvalidRuntimeConfig');
    this.ttlMs = config.ttlMs ?? 30000;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs <= 0 || this.ttlMs > 30000 ||
        config.timeoutMs !== undefined && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs <= 0 || config.timeoutMs > 30000)) throw new Error('InvalidRuntimeConfig');
  }
  get(scope: Scope): RuntimeSnapshot {
    if (this.queues.has(scopeId(scope))) throw new Error('RuntimeNotReady');
    const item = this.cache.get(scopeId(scope));
    if (!item || item.expiresAt <= Date.now()) { this.cache.delete(scopeId(scope)); throw new Error('RuntimeNotReady'); }
    return item;
  }
  initialize(scope: Scope, manifest: unknown, revision: number, secrets: Record<string, string> = {}): Promise<RuntimeSnapshot> {
    return this.load(scope, manifest, revision, '/local/reconcile', secrets);
  }
  refresh(scope: Scope, manifest: unknown, revision: number): Promise<RuntimeSnapshot> {
    return this.load(scope, manifest, revision, '/local/snapshot');
  }
  private load(scopeInput: Scope, input: unknown, revision: number, path: string, secrets?: Record<string, string>): Promise<RuntimeSnapshot> {
    // Capture inputs so caller mutation while queued cannot change tenant or manifest.
    const scope = { environment: scopeInput.environment, tenant: scopeInput.tenant };
    const id = scopeId(scope);
    this.cache.delete(id);
    let capturedInput: unknown, capturedSecrets: Record<string, string> | undefined, captureFailed = false;
    try { capturedInput = structuredClone(input); capturedSecrets = secrets === undefined ? undefined : structuredClone(secrets); }
    catch { captureFailed = true; }
    const operation = (this.queues.get(id) ?? Promise.resolve()).catch(() => undefined).then(async () => {
      const previous = this.watermarks.get(id);
      if (previous && revision < previous.revision) throw new Error('StaleRevision');
      // The old snapshot must not be used while a configuration event is refreshing it.
      this.cache.delete(id);
      try {
        scopePart(scope.environment); scopePart(scope.tenant);
        if (!Number.isSafeInteger(revision) || revision <= 0) throw new Error();
        this.watermarks.set(id, { revision, generation: previous?.generation ?? 0 });
        if (captureFailed) throw new Error();
        const manifest = parseManifest(capturedInput, scope);
        const response = await fetch(this.config.baseUrl.replace(/\/$/, '') + path, {
          method: 'POST', redirect: 'error', signal: AbortSignal.timeout(this.config.timeoutMs ?? 5000),
          headers: { Authorization: `Bearer ${this.config.token(scope)}`, 'Content-Type': 'application/json', 'x-vault-environment': scope.environment, 'x-vault-tenant': scope.tenant },
          body: JSON.stringify({ manifest, ...(capturedSecrets !== undefined && { revision, secrets: capturedSecrets }) }),
        });
        if (!response.ok) throw new Error();
        const raw: unknown = await response.json();
        const snapshot = this.validateSnapshot(raw, scope, manifest, revision, previous?.generation ?? 0);
        this.watermarks.set(id, { revision: snapshot.revision, generation: snapshot.generation });
        this.cache.set(id, snapshot);
        return snapshot;
      } catch { this.cache.delete(id); throw new Error('RuntimeRefreshFailed'); }
    });
    this.queues.set(id, operation);
    void operation.finally(() => { if (this.queues.get(id) === operation) this.queues.delete(id); }).catch(() => undefined);
    return operation;
  }
  private validateSnapshot(input: unknown, scope: Scope, manifest: Manifest, revision: number, generation: number): RuntimeSnapshot {
    if (!input || typeof input !== 'object') throw new Error();
    const s = input as Snapshot;
    if (s.environment !== scope.environment || s.tenant !== scope.tenant || s.manifestDigest !== digest(manifest) ||
        !Number.isSafeInteger(s.generation) || s.generation < generation || !Number.isSafeInteger(s.revision) || s.revision < revision ||
        !Number.isSafeInteger(s.expiresAt) || s.expiresAt <= Date.now() || !s.mappings || typeof s.mappings !== 'object' || Array.isArray(s.mappings)) throw new Error();
    if (Object.keys(s.mappings).length !== manifest.entries.length) throw new Error();
    const mappings: Record<string, string> = {};
    for (const entry of manifest.entries) {
      const value = s.mappings[entry.envName]; if (typeof value !== 'string') throw new Error();
      mappings[entry.envName] = value;
    }
    return Object.freeze({ ...scope, manifestDigest: s.manifestDigest, revision: s.revision, generation: s.generation,
      expiresAt: Math.min(s.expiresAt, Date.now() + this.ttlMs), mappings: Object.freeze(mappings) });
  }
  async initializeProcess(environment: string, manifest: unknown, revision: number, secrets: Record<string, string> = {}) {
    const snapshot = await this.initialize({ environment, tenant: '_shared' }, manifest, revision, secrets);
    const entries = Object.entries(snapshot.mappings);
    if (entries.some(([, value]) => value.includes('\0'))) throw new Error('InvalidEnvironmentValue');
    if (entries.some(([key, value]) => process.env[key] !== undefined && process.env[key] !== value)) throw new Error('EnvironmentConflict');
    for (const [key, value] of entries) process.env[key] = value;
    return snapshot;
  }
}
