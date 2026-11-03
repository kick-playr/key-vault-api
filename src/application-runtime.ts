import {runtimeResourceAssociations} from './runtime-effective-bindings.js';
import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import type { MongoStore } from './store.js';
import type { Attributes, Namespace, Scope } from './types.js';
import { applicationName } from './applications.js';
import { fail, requireCondition as check } from './errors.js';
import { envName, identifier, object, scopePart } from './validation.js';
import { find, changed } from './vault.js';
import { tenantKeySet } from './tenant-key-tree.js';

export type ResourceClassification =
  'secret' | 'encryption-key' | 'managed-credential';
export interface ApplicationRuntimeResource {
  kind: 'secrets';
  name: string;
  mapping: string;
  policy: string;
  version: string;
  classification: ResourceClassification;
  attributes: Attributes;
}
export interface ApplicationDescriptor {
  schemaVersion: 2;
  application: string;
  scope: Scope;
  generation: number;
  digest: string;
  resources: ApplicationRuntimeResource[];
}
export interface RuntimeInstanceRecord {
  application: string;
  caller: string;
  proofHash: string;
  expiresAt: number;
  lastSeen: number;
  generation?: number;
  digest?: string;
  status: 'updating' | 'applied' | 'warning' | 'blocked';
}
const canonical = (v: unknown): string =>
  JSON.stringify(v, (_k, value: unknown) =>
    value && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(
          Object.entries(value).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        )
      : value,
  );
const hash = (s: string) => createHash('sha256').update(s).digest('hex');
const has = <T>(
  map: Record<string, T> | undefined,
  key: string,
): T | undefined => (map && Object.hasOwn(map, key) ? map[key] : undefined);
const sharedMappings: Record<string, readonly string[]> = {
  app: [
    'CLERK_SECRET_KEY',
    'CLERK_ENCRYPTION_KEY',
    'CLERK_MACHINE_SECRET_KEY',
    'MANAGER_INVITATION_FLOW_KEY',
    'OPERATIONAL_SETUP_KEY',
    'DATABASE_URL',
  ],
  'explorer-api': [
    'EXPLORER_MONGODB_URI',
    'WORKFLOW_SHARED_WRAPPING_KEY_V1',
    'EXPLORER_CREDENTIAL_KEY',
    'MANAGER_SETUP_CONTROL_KEY',
    'CLERK_SECRET_KEY',
    'EXPLORER_INVITATION_SMTP_URL',
  ],
  explorer: [
    'CLERK_SECRET_KEY',
    'CLERK_ENCRYPTION_KEY',
    'CLERK_MACHINE_SECRET_KEY',
  ],
  'club-api': [
    'TENANT_CONTROL_MONGODB_URI',
    'WORKFLOW_SHARED_WRAPPING_KEY_V1',
    'MANAGER_SETUP_CONTROL_KEY',
    'MONGODB_CONNECTION_STRING',
    'CLERK_SECRET_KEY',
    'API_KEY',
    'API_KEY_SHA256',
    'ADMIN_API_KEY',
    'ADMIN_API_KEY_SHA256',
    'OPERATIONAL_SETUP_KEY',
    'BEXIO_ONBOARDING_KEY',
    'BEXIO_API_KEY',
    'BEXIO_CLIENT_SECRET',
    'DROPBOX_ACCESS_TOKEN',
    'DROPBOX_REFRESH_TOKEN',
    'DROPBOX_CLIENT_SECRET',
    'MAIL_PWD',
    'MAIL_BOUNCE_PASSWORD',
    'MATRIX_ADMIN_PASSWORD',
    'PINGEN_CLIENT_SECRET',
    'PINGEN_WEBHOOK_SECRET',
    'REDIS_URL',
    'WORKFLOW_PROXY_KEY',
  ],
};
function classification(
  application: string,
  scope: Scope,
  mapping: string,
  resourceName: string,
  tags?: Record<string, string>,
): ResourceClassification {
  const shared = has(sharedMappings, application);
  if (!shared) fail(409, 'UnsupportedApplicationContract');
  let tenantKey = false;
  if (scope.tenant !== '_shared' && tags?.keySet !== undefined) {
    const layout = tenantKeySet(scope, tags.keySet);
    const entry = layout.entries.find(
      (e) =>
        e.name === resourceName &&
        e.role === tags.keyRole &&
        e.logicalPath === tags.logicalPath,
    );
    const roleMatches =
      tags.keyRole === 'wrapping'
        ? /WRAPPING_KEY_V[0-9]+$/.test(mapping)
        : tags.keyRole === 'index'
          ? /INDEX_KEY$/.test(mapping)
          : tags.keyRole === 'control' && /CONTROL_KEY$/.test(mapping);
    if (!entry || !roleMatches || tags.envName !== mapping)
      fail(409, 'ApplicationKeySetMismatch');
    tenantKey = ['club-api', 'explorer-api'].includes(application);
  }
  const managedCredential =
    application === 'club-api' &&
    scope.tenant !== '_shared' &&
    /^RUNTIME_CREDENTIAL_[A-Z0-9_]{1,100}$/.test(mapping);
  const allowed =
    scope.tenant === '_shared' &&
    (shared.includes(mapping) ||
      (application === 'explorer' &&
        /^EXPLORER_CLUB_[A-Z0-9_]+_CLERK_SECRET_KEY$/.test(mapping)) ||
      (application==='explorer-api'&&/^[A-Z][A-Z0-9_]{0,100}_CLERK_SECRET_KEY$/.test(mapping)));
  const tenantCredential=application==='explorer-api'&&scope.tenant!=='_shared'&&/^RUNTIME_CREDENTIAL_[A-Z0-9_]{1,100}$/.test(mapping);
  const tenantConnection=['club-api','explorer-api'].includes(application)&&scope.tenant!=='_shared'&&['MONGODB_URI','CLERK_SECRET_KEY'].includes(mapping);
  if (!allowed && !tenantKey && !managedCredential && !tenantCredential && !tenantConnection)
    fail(409, 'UnsupportedApplicationMapping');
  if (managedCredential) return 'managed-credential';
  return tenantKey ||
    /(?:WRAPPING_KEY_V[0-9]+|INDEX_KEY|CONTROL_KEY|CREDENTIAL_KEY|ENCRYPTION_KEY|MANAGER_INVITATION_FLOW_KEY)$/.test(
      mapping,
    )
    ? 'encryption-key'
    : 'secret';
}
export function applicationDescriptor(
  scope: Scope,
  application: string,
  ns: Namespace | undefined,
): ApplicationDescriptor {
  applicationName(application);
  scopePart(scope.environment);
  scopePart(scope.tenant);
  if (!['development', 'dev', 'test'].includes(scope.environment))
    fail(403, 'Forbidden');
  if (!has(sharedMappings, application))
    fail(409, 'UnsupportedApplicationContract');
  if (!ns || (scope.tenant === '_shared' && !has(ns.applications, application)))
    fail(404, 'ApplicationNotFound');
  const mappings = new Set<string>();
  const resources: ApplicationRuntimeResource[] = [];
  const keySets = new Map<string, Set<string>>();
  for (const [reference, association] of Object.entries(
    runtimeResourceAssociations(scope,application,ns),
  )) {
    const policy = has(association.memberships, application);
    if (policy === undefined) continue;
    const [kind, name, ...rest] = reference.split('/');
    check(rest.length === 0 && typeof name === 'string');
    identifier(name);
    // No current ENV consumer implements key handles; never export a private JWK.
    if (kind !== 'secrets') fail(409, 'UnsupportedApplicationCapability');
    const mapping = envName(association.envName);
    if (mappings.has(mapping)) fail(409, 'MappingConflict');
    mappings.add(mapping);
    check(policy === 'latest' || /^[a-f0-9]{32}$/.test(policy));
    const selected = find(
      ns,
      'secrets',
      name,
      policy === 'latest' ? undefined : policy,
    );
    const a = selected.attributes,
      now = Math.floor(Date.now() / 1000);
    if (
      !a.enabled ||
      (a.nbf !== undefined && a.nbf > now) ||
      (a.exp !== undefined && a.exp <= now)
    )
      fail(409, 'ApplicationCandidateInactive');
    if (
      selected.tags?.envName !== undefined &&
      selected.tags.envName !== mapping
    )
      fail(409, 'CanonicalMappingConflict');
    const type = classification(
      application,
      scope,
      mapping,
      name,
      selected.tags,
    );
    if (
      scope.tenant !== '_shared' &&
      type === 'encryption-key' &&
      selected.tags?.keySet
    ) {
      const roles = keySets.get(selected.tags.keySet) ?? new Set<string>();
      roles.add(selected.tags.keyRole!);
      keySets.set(selected.tags.keySet, roles);
    }
    resources.push({
      kind: 'secrets',
      name,
      mapping,
      policy,
      version: selected.version,
      classification: type,
      attributes: { ...a },
    });
  }
  if (!resources.length) fail(409, 'ApplicationBindingsIncomplete');
  if ([...keySets.values()].some((roles) => roles.size !== 3))
    fail(409, 'ApplicationKeySetIncomplete');
  check(
    resources.length <= 100 &&
      Number.isSafeInteger(ns.generation) &&
      ns.generation >= 0,
  );
  resources.sort((a, b) =>
    a.mapping < b.mapping ? -1 : a.mapping > b.mapping ? 1 : 0,
  );
  const identity = {
    schemaVersion: 2 as const,
    application,
    scope: { ...scope },
    resources,
  };
  const result = {
    ...identity,
    generation: ns.generation,
    digest: hash(canonical(identity)),
  };
  if (Buffer.byteLength(JSON.stringify(result)) > 65536)
    fail(413, 'ApplicationDescriptorTooLarge');
  return result;
}
/** New v2 scoped contract; existing startup manifests and tenant-control revisions are untouched. */
export class ApplicationRuntimeService {
  constructor(
    private readonly store: Pick<MongoStore, 'read' | 'transaction'>,
  ) {}
  mode(scope: Scope, application: string) {
    applicationName(application);
    if (scope.tenant !== '_shared') fail(400, 'SharedScopeRequired');
    if (!['development', 'dev', 'test'].includes(scope.environment))
      fail(403, 'Forbidden');
    return this.store.read(scope, (ns) => ({
      schemaVersion: 2 as const,
      application,
      scope: { ...scope },
      mode: has(ns?.applications, application)?.liveEnabled
        ? ('live' as const)
        : ('legacy' as const),
    }));
  }
  async activate(scope: Scope, application: string, input: unknown) {
    applicationName(application);
    if (scope.tenant !== '_shared') fail(400, 'SharedScopeRequired');
    const body = object(input, ['expectedRevision']);
    check(
      Number.isSafeInteger(body.expectedRevision) &&
        (body.expectedRevision as number) >= 0,
    );
    return this.store.transaction(scope, (ns) => {
      if (body.expectedRevision !== (ns.applicationRevision ?? 0))
        fail(409, 'ApplicationRevisionConflict');
      applicationDescriptor(scope, application, ns);
      ns.applications![application]!.liveEnabled = true;
      ns.applicationRevision = (ns.applicationRevision ?? 0) + 1;
      changed(ns, 'application.activate', application);
      return { activated: true };
    });
  }
  desired(scope: Scope, application: string) {
    return this.store.read(scope, (ns) =>
      applicationDescriptor(scope, application, ns),
    );
  }
  snapshot(scope: Scope, application: string, input: unknown) {
    const body = object(input, ['generation', 'digest']);
    check(
      Number.isSafeInteger(body.generation) &&
        (body.generation as number) >= 0 &&
        typeof body.digest === 'string' &&
        /^[a-f0-9]{64}$/.test(body.digest),
    );
    return this.store.read(scope, (ns) => {
      const descriptor = applicationDescriptor(scope, application, ns);
      if (
        descriptor.generation !== body.generation ||
        descriptor.digest !== body.digest
      )
        fail(409, 'ApplicationSnapshotChanged');
      const resources = descriptor.resources.map((r) => {
        const item = find(ns, 'secrets', r.name, r.version);
        if (
          typeof item.value !== 'string' ||
          Buffer.byteLength(item.value) > 25600 ||
          item.value.includes('\0')
        )
          fail(409, 'ApplicationValueInvalid');
        return { ...r, value: item.value };
      });
      const result = { ...descriptor, resources };
      if (Buffer.byteLength(JSON.stringify(result)) > 4 * 1024 * 1024)
        fail(413, 'ApplicationSnapshotTooLarge');
      return result;
    });
  }
  inUse(scope: Scope, application: string, input: unknown) {
    applicationName(application);
    const body = object(input, ['resources']);
    check(
      Array.isArray(body.resources) &&
        body.resources.length > 0 &&
        body.resources.length <= 100,
    );
    const refs = body.resources.map((raw) => {
      const r = object(raw, ['name', 'version']);
      identifier(r.name);
      check(typeof r.version === 'string' && /^[a-f0-9]{32}$/.test(r.version));
      return { name: r.name as string, version: r.version as string };
    });
    return this.store.read(scope, (ns) => {
      for (const r of refs) {
        const association = has(runtimeResourceAssociations(scope,application,ns), `secrets/${r.name}`);
        if (!association || !has(association.memberships, application))
          fail(403, 'ApplicationInUseUnavailable');
        let item;
        try {
          item = find(ns, 'secrets', r.name, r.version);
        } catch {
          fail(403, 'ApplicationInUseUnavailable');
        }
        const now = Math.floor(Date.now() / 1000),
          a = item.attributes;
        if (
          !a.enabled ||
          (a.exp !== undefined && a.exp <= now) ||
          (a.nbf !== undefined && a.nbf > now)
        )
          fail(403, 'ApplicationInUseUnavailable');
      }
      return { valid: true };
    });
  }
  async register(scope: Scope, application: string, caller: string) {
    check(
      typeof caller === 'string' && caller.length > 0 && caller.length <= 256,
    );
    const instanceId = randomUUID(),
      proof = randomBytes(32).toString('base64url');
    return this.store.transaction(scope, (ns) => {
      applicationName(application);
      if (!has(sharedMappings, application))
        fail(409, 'UnsupportedApplicationContract');
      if (
        scope.tenant === '_shared'
          ? !has(ns.applications, application)
          : !Object.values(runtimeResourceAssociations(scope,application,ns)).some((r) =>
              has(r.memberships, application),
            )
      )
        fail(404, 'ApplicationNotFound');
      const now = Date.now(),
        records = (ns.runtimeInstances ??= {});
      for (const [id, r] of Object.entries(records))
        if (r.expiresAt <= now) delete records[id];
      if (Object.keys(records).length >= 128)
        fail(429, 'ApplicationInstanceLimit');
      records[instanceId] = {
        application,
        caller,
        proofHash: hash(proof),
        expiresAt: now + 30000,
        lastSeen: now,
        status: 'updating',
      };
      return { instanceId, proof, expiresAt: now + 30000 };
    });
  }
  acknowledge(
    scope: Scope,
    application: string,
    caller: string,
    input: unknown,
  ) {
    const body = object(input, [
      'instanceId',
      'proof',
      'generation',
      'digest',
      'status',
    ]);
    check(
      typeof body.instanceId === 'string' &&
        /^[a-f0-9-]{36}$/.test(body.instanceId) &&
        typeof body.proof === 'string' &&
        /^[A-Za-z0-9_-]{43}$/.test(body.proof),
    );
    check(
      Number.isSafeInteger(body.generation) &&
        (body.generation as number) >= 0 &&
        typeof body.digest === 'string' &&
        /^[a-f0-9]{64}$/.test(body.digest),
    );
    check(
      ['applied', 'warning', 'blocked', 'updating'].includes(
        body.status as string,
      ),
    );
    return this.store.transaction(scope, (ns) => {
      const record = has(ns.runtimeInstances, body.instanceId as string),
        now = Date.now();
      if (
        !record ||
        record.application !== application ||
        record.caller !== caller ||
        record.expiresAt <= now ||
        !timingSafeEqual(
          Buffer.from(record.proofHash, 'hex'),
          Buffer.from(hash(body.proof as string), 'hex'),
        )
      )
        fail(403, 'Forbidden');
      if ((body.generation as number) > ns.generation)
        fail(409, 'ApplicationSnapshotChanged');
      if (body.status === 'applied') {
        const desired = applicationDescriptor(scope, application, ns);
        if (body.digest !== desired.digest)
          fail(409, 'ApplicationSnapshotChanged');
      }
      // Warnings may refer to the last working generation after a rejected update.
      // They never count as adoption of the desired generation.
      record.generation = body.generation as number;
      record.digest = body.digest as string;
      record.status = body.status as
        'applied' | 'warning' | 'blocked' | 'updating';
      record.lastSeen = now;
      record.expiresAt = now + 30000;
      return { accepted: true, expiresAt: record.expiresAt };
    });
  }
  status(scope: Scope, application: string) {
    applicationName(application);
    return this.store.read(scope, (ns) => {
      const instances = Object.entries(ns?.runtimeInstances ?? {})
        .filter(([, r]) => r.application === application)
        .map(([instanceId, r]) => ({
          instanceId,
          lastSeen: r.lastSeen,
          expiresAt: r.expiresAt,
          generation: r.generation,
          digest: r.digest,
          status: r.status,
        }));
      let current: ApplicationDescriptor | undefined;
      try {
        current = applicationDescriptor(scope, application, ns);
      } catch {
        /* Invalid desired state is shown as blocked without leaking contents. */
      }
      const live = instances.filter((r) => r.expiresAt > Date.now());
      const state = !instances.length
        ? 'not-connected'
        : !live.length
          ? 'offline'
          : live.some((r) => r.status === 'blocked')
            ? 'blocked'
            : live.some((r) => r.status === 'warning')
              ? 'warning'
              : !current
                ? 'blocked'
                : live.every(
                      (r) =>
                        r.status === 'applied' && r.digest === current.digest,
                    )
                  ? 'applied'
                  : 'updating';
      return { state, instances };
    });
  }
}
