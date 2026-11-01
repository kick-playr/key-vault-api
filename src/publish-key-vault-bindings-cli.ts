import { lstatSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type { RuntimeManifest } from '@kick-playr/local-key-vault/runtime-client';
import { createBindings, parsePlan } from './runtime-manifest-plan.js';
import { loadBootstrapConfig } from './config.js';
import { fail, formatStartupError } from './errors.js';
import { MongoStore } from './store.js';
import { emptyNamespace } from './types.js';
import { publishManifests, validatedManifest } from './runtime-manifests.js';

/** Resolve and validate all metadata before the first write. Publish tenant history first. */
export async function publishBindings(plan: unknown, store: Pick<MongoStore, 'read' | 'transaction'>) {
  const bindings = await createBindings(plan, store);
  const apps = Object.entries(bindings.applications);
  if (!apps.length) fail(400, 'InvalidBindingsPlan');
  const tenantGroups = bindings.tenants.map(binding => ({ scope: binding.scope, manifests: apps.map(([application]) => validatedManifest({ schemaVersion: 1, application, ...binding, tenants: [] })) }));
  const manifests: RuntimeManifest[] = apps.map(([application, binding]) => validatedManifest({ schemaVersion: 1, application, ...binding,
    tenants: bindings.tenants.map(tenant => ({ tenant: tenant.scope.tenant, bindingRevision: tenant.request.bindingRevision, bindingDigest: tenant.request.bindingDigest })) }));
  // Preflight immutable-history conflicts across every namespace, without mutating storage.
  const groups = [...tenantGroups, { scope: apps[0]![1].scope, manifests }];
  for (const group of groups) await store.read(group.scope, ns => {
    publishManifests({ ...emptyNamespace(), runtimeManifests: ns?.runtimeManifests }, group.scope, group.manifests);
    return null;
  });
  for (const group of groups) await store.transaction(group.scope, ns => { publishManifests(ns, group.scope, group.manifests); });
  return { applications: manifests.length, tenants: tenantGroups.length };
}
async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--plan' || !args[1]) fail(400, 'InvalidCommand', 'Usage: ./publish-key-vault-bindings.sh --plan <metadata-plan.json>');
  let plan: unknown;
  try {
    const stat = lstatSync(args[1]);
    if (!stat.isFile() || stat.size > 1024 * 1024) throw Error();
    plan = JSON.parse(readFileSync(args[1], 'utf8'));
  } catch { fail(400, 'InvalidBindingsPlan', 'Supply a regular metadata-only JSON plan file, at most 1 MiB.'); }
  parsePlan(plan); // Reject malformed plans before database access.
  const store = await MongoStore.open(loadBootstrapConfig(resolve(dirname(fileURLToPath(import.meta.url)), '../.env')), { createVerifier: false });
  try {
    const result = await publishBindings(plan, store);
    console.log(`Published runtime manifests for ${result.applications} applications and ${result.tenants} tenants.`);
  } finally { await store.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch(error => { process.stderr.write(`[key-vault-publish] ${formatStartupError(error)}\n`); process.exitCode = 1; });
}
