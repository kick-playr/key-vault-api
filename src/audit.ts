import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { Request, Response } from 'express';
import { fail } from './errors.js';
import type { Scope } from './types.js';

export type AuditCategory = 'read' | 'write' | 'list' | 'crypto';
export type AuditDestination = 'console' | 'collection' | 'both' | 'off';
export type AuditDestinations = Record<AuditCategory, AuditDestination>;
const defaults: AuditDestinations = { read: 'console', list: 'console', write: 'collection', crypto: 'collection' };
export function auditDestinations(value: unknown = {}): AuditDestinations {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.entries(value).some(([key, destination]) => !Object.hasOwn(defaults, key) ||
        !['console', 'collection', 'both', 'off'].includes(destination as string)))
    fail(500, 'InvalidBootstrap', 'VAULT_AUDIT_DESTINATIONS must map read/list/write/crypto to console/collection/both/off.');
  return { ...defaults, ...value };
}
export function parseAuditDestinations(value: string | undefined): AuditDestinations {
  if (value === undefined) return auditDestinations();
  let parsed: unknown;
  try { parsed = JSON.parse(value); }
  catch { fail(500, 'InvalidBootstrap', 'VAULT_AUDIT_DESTINATIONS must be a JSON object.'); }
  return auditDestinations(parsed);
}
interface Operation { category: AuditCategory; action: string; name?: string; version?: string }
export interface AuditEvent extends Operation {
  schemaVersion: 1; event: 'vault.audit'; requestId: string; time: string;
  durationMs: number; environment?: string; tenant?: string; grantIds: string[];
  status: number; outcome: 'success' | 'denied' | 'failure' | 'aborted';
}
export type AuditRequest = Request & { vaultScope?: Scope; vaultGrantIds?: string[] };

// Match known route shapes, never raw URLs or query strings. Only validated
// resource identifiers can be copied into an event; payloads are never accessed.
export function auditOperation(method: string, path: string): Operation | undefined {
  if (method === 'HEAD') method = 'GET';
  path = path.replace(/^\/namespaces\/[^/]+\/[^/]+(?=\/)/i, '').replace(/\/$/, '');
  const local = /^\/local\/(session|key-tree|inventory|snapshot|runtime-snapshot|reconcile)$/i.exec(path);
  if (local) {
    const route = local[1]!.toLowerCase();
    if (method === 'GET' && ['session', 'key-tree', 'inventory'].includes(route))
      return { category: route === 'session' ? 'read' : 'list', action: `local.${route}` };
    if (method === 'POST' && ['snapshot', 'runtime-snapshot', 'reconcile'].includes(route))
      return { category: route === 'reconcile' ? 'write' : 'read', action: `local.${route}` };
    return;
  }
  const route = /^\/(keys|secrets)(?:\/([^/]+))?(?:\/([^/]+))?(?:\/(encrypt|decrypt))?$/i.exec(path);
  if (!route) return;
  const kind = route[1]!.toLowerCase(), name = route[2], segment = route[3], crypto = route[4]?.toLowerCase();
  const fields = {
    ...(name && /^[a-zA-Z0-9-]{1,127}$/.test(name) ? { name } : {}),
    ...(segment && /^[a-zA-Z0-9-]{1,127}$/.test(segment) && !['versions', 'create'].includes(segment.toLowerCase()) ? { version: segment } : {}),
  };
  if (method === 'POST' && kind === 'keys' && name && segment && crypto)
    return { category: 'crypto', action: `keys.${crypto}`, ...fields };
  if (crypto) return;
  if (method === 'GET') {
    if (!name || segment?.toLowerCase() === 'versions')
      return { category: 'list', action: `${kind}.${name ? 'versions' : 'list'}`, ...fields };
    return { category: 'read', action: `${kind}.get`, ...fields };
  }
  if (method === 'PUT' && kind === 'secrets' && name && !segment)
    return { category: 'write', action: 'secrets.set', ...fields };
  if (method === 'POST' && kind === 'keys' && name && segment?.toLowerCase() === 'create')
    return { category: 'write', action: 'keys.create', ...fields };
  if (method === 'PATCH' && name && segment)
    return { category: 'write', action: `${kind}.update`, ...fields };
  if (method === 'DELETE' && name && !segment)
    return { category: 'write', action: `${kind}.delete`, ...fields };
  return;
}

export class AuditService {
  private readonly pending = new Set<Promise<void>>();
  constructor(private readonly destinations: AuditDestinations,
    private readonly store: { appendAudit(event: AuditEvent): Promise<void> }) {}

  attach(req: AuditRequest, res: Response) {
    const operation = auditOperation(req.method, req.path);
    if (!operation) return;
    const requestId = randomUUID(), start = performance.now();
    res.setHeader('X-Vault-Request-Id', requestId);
    let recorded = false;
    const complete = (aborted: boolean) => {
      if (recorded) return;
      recorded = true;
      const status = aborted ? 499 : res.statusCode;
      const event: AuditEvent = { schemaVersion: 1, event: 'vault.audit', ...operation,
        requestId, time: new Date().toISOString(), durationMs: Math.max(0, Math.round(performance.now() - start)),
        ...(req.vaultScope ?? {}), grantIds: [...(req.vaultGrantIds ?? [])], status,
        outcome: aborted ? 'aborted' : status < 400 ? 'success' : [401, 403].includes(status) ? 'denied' : 'failure' };
      this.record(event);
    };
    res.once('finish', () => complete(false));
    res.once('close', () => complete(!res.writableFinished));
  }
  record(event: AuditEvent) {
    const destination = this.destinations[event.category];
    const reportFailure = (sink: string) => {
      try { console.error(JSON.stringify({ event: 'vault.audit.delivery-failed', requestId: event.requestId, category: event.category, destination: sink })); }
      catch { /* No safe fallback remains when stderr itself is unavailable. */ }
    };
    if (destination === 'console' || destination === 'both') {
      try { console.info(JSON.stringify(event)); } catch { reportFailure('console'); }
    }
    if (destination === 'collection' || destination === 'both') {
      const work = Promise.resolve().then(() => this.store.appendAudit(event)).catch(() => reportFailure('collection'));
      this.pending.add(work);
      void work.finally(() => this.pending.delete(work));
    }
  }
  async close() { while (this.pending.size) await Promise.all([...this.pending]); }
}
