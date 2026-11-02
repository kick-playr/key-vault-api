import type { MongoStore } from './store.js';
import type { Namespace, Scope, ResourceAssociation } from './types.js';
import { fail, requireCondition as check } from './errors.js';
import { envName, identifier, object } from './validation.js';
import { active, changed, find, type Kind } from './vault.js';

const SUPPORTED = new Set(['club-api', 'app', 'explorer-api', 'explorer']);
export function applicationName(value: unknown): string {
  check(typeof value === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(value));
  check(!['constructor', 'prototype', '__proto__'].includes(value));
  return value;
}
function revision(ns: Namespace, input: unknown, fields: string[]) {
  const body = object(input, ['expectedRevision', ...fields]);
  check(Number.isSafeInteger(body.expectedRevision) && (body.expectedRevision as number) >= 0);
  if (body.expectedRevision !== (ns.applicationRevision ?? 0)) fail(409, 'ApplicationRevisionConflict');
  return body;
}
function text(value: unknown, max: number): string {
  check(typeof value === 'string' && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value));
  return value;
}
function kindName(value: string): Kind { check(value === 'keys' || value === 'secrets'); return value as Kind; }
const has = <T>(map: Record<string, T> | undefined, key: string): T | undefined => map && Object.hasOwn(map, key) ? map[key] : undefined;
export interface ApplicationResource {
  kind: Kind; name: string; envName: string; policy: string; version?: string;
  enabled: boolean; missing: boolean; tags: Record<string, string>; applications: string[];
}
export interface ApplicationView { name: string; displayName: string; description: string; supported: boolean; resources: ApplicationResource[]; runtimeStatus: 'not-connected' }
export interface ApplicationsView { revision: number; generation: number; environment: string; tenant: string; applications: ApplicationView[] }

/** Metadata only. No value, private key or grant material is returned. */
export class ApplicationsService {
  constructor(private readonly store: Pick<MongoStore, 'read' | 'transaction'>) {}
  private catalog(scope: Scope) { return this.store.read({ environment: scope.environment, tenant: '_shared' }, ns => ns?.applications ?? {}); }
  private project(scope: Scope, ns: Namespace | undefined, catalog: NonNullable<Namespace['applications']>): ApplicationsView {
    const associations = ns?.resourceAssociations ?? {};
    const names = scope.tenant === '_shared' ? Object.keys(catalog) : [...new Set(Object.values(associations).flatMap(r => Object.keys(r.memberships)))];
    const applications = names.sort().flatMap(name => {
      const app = has(catalog, name); if (!app) return [];
      const resources = Object.entries(associations).flatMap(([id, association]) => {
        const policy = has(association.memberships, name); if (!policy) return [];
        const [kind, resourceName] = id.split('/') as [Kind, string];
        const versions = has(ns?.[kind], resourceName);
        const item = policy === 'latest' ? versions?.at(-1) : versions?.find(v => v.version === policy);
        return [{ kind, name: resourceName, envName: association.envName, policy,
          ...(item ? { version: item.version } : {}), enabled: item?.attributes.enabled ?? false,
          missing: !item, tags: { ...item?.tags }, applications: Object.keys(association.memberships).sort() }];
      });
      return [{ name, ...app, supported: SUPPORTED.has(name), resources, runtimeStatus: 'not-connected' as const }];
    });
    return { revision: ns?.applicationRevision ?? 0, generation: ns?.generation ?? 0, ...scope, applications };
  }
  async list(scope: Scope): Promise<ApplicationsView> {
    if (scope.tenant === '_shared') return this.store.read(scope, ns => this.project(scope, ns, ns?.applications ?? {}));
    const catalog = await this.catalog(scope);
    return this.store.read(scope, ns => this.project(scope, ns, catalog));
  }
  async save(scope: Scope, name: string, input: unknown): Promise<ApplicationsView> {
    applicationName(name);
    if (scope.tenant !== '_shared') fail(400, 'SharedScopeRequired');
    return this.store.transaction(scope, ns => {
      const body = revision(ns, input, ['displayName', 'description']);
      const displayName = text(body.displayName, 128).trim(); check(displayName.length > 0);
      const description = text(body.description ?? '', 512);
      const applications = ns.applications ??= {};
      if (!Object.hasOwn(applications, name) && Object.keys(applications).length >= 100) fail(409, 'ApplicationLimit');
      applications[name] = { displayName, description };
      ns.applicationRevision = (ns.applicationRevision ?? 0) + 1;
      changed(ns, 'application.save', name);
      return this.project(scope, ns, applications);
    });
  }
  async link(scope: Scope, application: string, rawKind: string, name: string, input: unknown): Promise<ApplicationsView> {
    applicationName(application); const kind = kindName(rawKind); identifier(name);
    const catalog = await this.catalog(scope);
    if (!has(catalog, application)) fail(404, 'ApplicationNotFound');
    return this.store.transaction(scope, ns => {
      const body = revision(ns, input, ['envName', 'version']);
      const mapping = envName(body.envName);
      check(body.version === 'latest' || typeof body.version === 'string' && /^[a-f0-9]{32}$/.test(body.version));
      const policy = body.version as string;
      const selected = find(ns, kind, name, policy === 'latest' ? undefined : policy); active(selected);
      const associations = ns.resourceAssociations ??= {};
      const id = `${kind}/${name}`, previous = has(associations, id);
      if (previous && previous.envName !== mapping) fail(409, 'CanonicalMappingConflict');
      // Existing declared mappings are authoritative even before first linking.
      const declared = new Set(ns[kind][name]!.map(v => v.tags?.envName).filter((v): v is string => v !== undefined));
      if (declared.size > 1 || declared.size === 1 && !declared.has(mapping)) fail(409, 'CanonicalMappingConflict');
      for (const [otherId, entry] of Object.entries(associations)) {
        if (otherId !== id && entry.envName === mapping && has(entry.memberships, application)) fail(409, 'MappingConflict');
      }
      if (!previous && Object.keys(associations).length >= 500) fail(409, 'ApplicationResourceLimit');
      const association: ResourceAssociation = previous ?? { envName: mapping, memberships: {} };
      association.memberships[application] = policy; associations[id] = association;
      ns.applicationRevision = (ns.applicationRevision ?? 0) + 1;
      changed(ns, 'application.link', application);
      return this.project(scope, ns, scope.tenant === '_shared' ? ns.applications ?? {} : catalog);
    });
  }
  async unlink(scope: Scope, application: string, rawKind: string, name: string, input: unknown): Promise<ApplicationsView> {
    applicationName(application); const kind = kindName(rawKind); identifier(name);
    const catalog = await this.catalog(scope);
    return this.store.transaction(scope, ns => {
      revision(ns, input, []);
      const association = has(ns.resourceAssociations, `${kind}/${name}`);
      if (!association || !has(association.memberships, application)) fail(404, 'ApplicationLinkNotFound');
      delete association.memberships[application];
      // Retain canonical envName even after the final unlink.
      ns.applicationRevision = (ns.applicationRevision ?? 0) + 1;
      changed(ns, 'application.unlink', application);
      return this.project(scope, ns, scope.tenant === '_shared' ? ns.applications ?? {} : catalog);
    });
  }
}
