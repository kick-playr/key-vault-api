import { bindingDigest, parseSnapshotRequest } from '@kick-playr/local-key-vault/runtime-client';
import type { RuntimeSnapshotRequest, KeySetDescriptor } from '@kick-playr/local-key-vault/runtime-client';
import { fail } from './errors.js';
import { vaultName } from './manifest.js';
import type { MongoStore } from './store.js';
import { tenantKeySet } from './tenant-key-tree.js';
import type { Namespace, Scope, Version } from './types.js';
import { envName, identifier, object, scopePart } from './validation.js';
import { active } from './vault.js';

interface SecretPlan { mapping: string; purpose: string; version?: string }
interface KeyPlan {
  reference: string; currentWrappingVersion: string;
  wrappingVersions: { keyVersion: string; vaultVersion?: string }[];
  mappings?: KeySetDescriptor['mappings']; indexVersion?: string; controlVersion?: string;
}
interface EntryPlan { bindingRevision: number; secrets: SecretPlan[]; keySets: KeyPlan[] }
interface TenantPlan extends EntryPlan { tenant: string }
interface Plan { environment: string; applications: Record<string, EntryPlan>; tenants: TenantPlan[] }
interface Binding { scope: Scope; request: RuntimeSnapshotRequest }
export interface Bindings { schemaVersion: 1; applications: Record<string, Binding>; tenants: Binding[] }
const check = (value: unknown) => { if (!value) fail(400, 'InvalidBindingsPlan', 'Check the metadata-only plan schema and explicit positive revisions; see examples/explorer-api-bindings-plan.json.'); };
function pin(value: unknown): string | undefined {
  if (value === undefined) return;
  check(typeof value === 'string' && /^[a-f0-9]{32}$/.test(value as string));
  return value as string;
}
function keyVersion(value: unknown): string {
  check(typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value as string) && value !== 'latest');
  return value as string;
}
function list(value: unknown): unknown[] { check(Array.isArray(value) && value.length <= 100); return value as unknown[]; }
function entry(input: unknown, scope: Scope): EntryPlan {
  const fields = scope.tenant === '_shared' ? ['bindingRevision', 'secrets'] : ['tenant', 'bindingRevision', 'keySets', 'secrets'];
  const body = object(input, fields);
  check(Number.isSafeInteger(body.bindingRevision) && (body.bindingRevision as number) > 0);
  const secrets = list(body.secrets ?? []).map(raw => {
    const s = object(raw, ['mapping', 'purpose', 'version']);
    return { mapping: envName(s.mapping), purpose: identifier(s.purpose), version: pin(s.version) };
  });
  check(new Set(secrets.map(s => s.mapping)).size === secrets.length && new Set(secrets.map(s => s.purpose)).size === secrets.length);
  const keySets = list(body.keySets ?? []).map(raw => {
    const k = object(raw, ['reference', 'currentWrappingVersion', 'wrappingVersions', 'mappings', 'indexVersion', 'controlVersion']);
    const reference = tenantKeySet(scope, k.reference as string).reference;
    const currentWrappingVersion = keyVersion(k.currentWrappingVersion);
    const wrappingVersions = k.wrappingVersions === undefined ? [{ keyVersion: currentWrappingVersion }] : list(k.wrappingVersions).map(rawVersion => {
      const v = object(rawVersion, ['keyVersion', 'vaultVersion']);
      return { keyVersion: keyVersion(v.keyVersion), vaultVersion: pin(v.vaultVersion) };
    });
    check(wrappingVersions.length > 0 && wrappingVersions.some(v => v.keyVersion === currentWrappingVersion));
    check(new Set(wrappingVersions.map(v => v.keyVersion)).size === wrappingVersions.length);
    let mappings: KeySetDescriptor['mappings'] | undefined;
    if (k.mappings !== undefined) {
      const m = object(k.mappings, ['wrapping', 'index', 'control']);
      mappings = { wrapping: envName(m.wrapping), index: envName(m.index), control: envName(m.control) };
    }
    return { reference, currentWrappingVersion, wrappingVersions, mappings, indexVersion: pin(k.indexVersion), controlVersion: pin(k.controlVersion) };
  });
  check(secrets.length + keySets.length > 0 && new Set(keySets.map(k => k.reference)).size === keySets.length);
  return { bindingRevision: body.bindingRevision as number, secrets, keySets };
}
export function parsePlan(input: unknown): Plan {
  const body = object(input, ['schemaVersion', 'environment', 'applications', 'tenants']);
  check(body.schemaVersion === 1 && ['development', 'dev', 'test'].includes(body.environment as string));
  const environment = body.environment as string;
  check(body.applications && typeof body.applications === 'object' && !Array.isArray(body.applications));
  const apps = Object.entries(body.applications as Record<string, unknown>);
  check(apps.length <= 16);
  const applications = Object.fromEntries(apps.map(([name, value]) => {
    check(/^[a-z][a-z0-9-]{0,63}$/.test(name));
    return [name, entry(value, { environment, tenant: '_shared' })];
  }));
  const tenants = list(body.tenants).map(raw => {
    const tenant = scopePart((raw as { tenant?: unknown })?.tenant);
    check(tenant !== '_shared');
    return { tenant, ...entry(raw, { environment, tenant }) };
  });
  check(tenants.length <= 32 && new Set(tenants.map(t => t.tenant)).size === tenants.length && apps.length + tenants.length > 0);
  return { environment, applications, tenants };
}
function select(versions: Version[] | undefined, version: string | undefined, label: string): Version {
  if (!versions?.length) fail(404, 'MissingBindingsResource', `Missing ${label}; provision the required vault entry separately.`);
  if (!version && versions.length !== 1) fail(409, 'AmbiguousVersion', `${label} has multiple versions; supply explicit immutable version pins and historical wrapping labels in the plan.`);
  const selected = version ? versions.find(v => v.version === version) : versions[0];
  if (!selected) fail(404, 'MissingBindingsVersion', `The explicit version for ${label} is absent.`);
  active(selected);
  return selected;
}
function resolveRequest(scope: Scope, plan: EntryPlan, namespace: Namespace | undefined): RuntimeSnapshotRequest {
  const secrets = plan.secrets.map(s => {
    const item = select(namespace?.secrets[vaultName(scope, 'secret', s.purpose)], s.version, s.mapping);
    if (item.tags?.purpose !== undefined && item.tags.purpose !== s.purpose || item.tags?.envName !== undefined && item.tags.envName !== s.mapping) fail(409, 'BindingMismatch');
    return { mapping: s.mapping, purpose: s.purpose, version: item.version };
  });
  const keySets = plan.keySets.map(k => {
    const layout = tenantKeySet(scope, k.reference);
    const role = (kind: 'wrapping' | 'index' | 'control', version?: string) => {
      const part = layout.entries.find(e => e.role === kind)!;
      const item = select(namespace?.secrets[part.name], version, `${k.reference}/${kind}`);
      const tags = item.tags;
      if (tags?.keySet !== k.reference || tags?.keyRole !== kind || tags?.logicalPath !== part.logicalPath) fail(409, 'BindingMismatch');
      const mapping = envName(tags.envName);
      if (k.mappings && mapping !== k.mappings[kind]) fail(409, 'BindingMismatch');
      return { version: item.version, mapping };
    };
    const wrapping = k.wrappingVersions.map(v => ({ keyVersion: v.keyVersion, ...role('wrapping', v.vaultVersion) }));
    if (new Set(wrapping.map(v => v.mapping)).size !== 1) fail(409, 'BindingMismatch');
    const index = role('index', k.indexVersion), control = role('control', k.controlVersion);
    return { reference: k.reference, currentWrappingVersion: k.currentWrappingVersion,
      mappings: { wrapping: wrapping[0]!.mapping, index: index.mapping, control: control.mapping },
      wrappingVersions: wrapping.map(v => ({ keyVersion: v.keyVersion, vaultVersion: v.version })),
      indexVersion: index.version, controlVersion: control.version };
  });
  const request = { schemaVersion: 1 as const, bindingRevision: plan.bindingRevision, keySets, secrets };
  return parseSnapshotRequest({ ...request, bindingDigest: bindingDigest(request) });
}
/** Read each namespace once; callback returns only metadata, never secret material. */
export async function createBindings(input: unknown, store: Pick<MongoStore, 'read'>): Promise<Bindings> {
  const plan = parsePlan(input);
  const applications: Record<string, Binding> = {};
  if (Object.keys(plan.applications).length) {
    const scope = { environment: plan.environment, tenant: '_shared' };
    const resolved = await store.read(scope, ns => Object.fromEntries(Object.entries(plan.applications).map(([name, entry]) => [name, { scope, request: resolveRequest(scope, entry, ns) }])));
    Object.assign(applications, resolved);
  }
  const tenants: Binding[] = [];
  for (const entry of plan.tenants) {
    const scope = { environment: plan.environment, tenant: entry.tenant };
    tenants.push(await store.read(scope, ns => ({ scope, request: resolveRequest(scope, entry, ns) })));
  }
  const result: Bindings = { schemaVersion: 1, applications, tenants };
  if (Buffer.byteLength(JSON.stringify(result)) > 1024 * 1024) fail(413, 'BindingsTooLarge', 'Generated bindings exceed the runtime client limit of 1 MiB; reduce the selected mappings and namespaces.');
  return result;
}
