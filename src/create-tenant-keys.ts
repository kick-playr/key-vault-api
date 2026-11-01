import { readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { randomBytes } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadBootstrapEnvironment, loadConfig } from './config.js';
import { fail, formatStartupError } from './errors.js';
import { GrantService } from './grants.js';
import { confirmTenantKeys, importTenantKeySet, KeyEnvironmentNames, promptKeySetName, readHiddenInput, readVisibleInput, validateKeyEnvironmentNames, validatedKeys, keyValuePrompt, grantTokenPrompt } from './import-fcrww-keys.js';
import { MongoStore } from './store.js';
import { tenantKeySet } from './tenant-key-tree.js';
import type { Scope } from './types.js';
import { scopePart } from './validation.js';

export interface TenantKeyArguments {
  environment?: string; tenant?: string; name?: string; token?: string;
  envFile?: string; generate?: boolean; yes?: boolean;
}
export function parseTenantKeyArgs(args: string[]): TenantKeyArguments {
  const result: TenantKeyArguments = {};
  const flags = { '--environment': 'environment', '--tenant': 'tenant', '--name': 'name', '--token': 'token',
    '--env-file': 'envFile' } as const;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--generate' || arg === '--yes') {
      const key = arg === '--generate' ? 'generate' : 'yes';
      if (result[key]) fail(400, 'InvalidCommand', 'Duplicate option; use --help for usage.');
      result[key] = true;
    } else {
      const split = arg.indexOf('='), flag = split < 0 ? arg : arg.slice(0, split);
      if (!Object.hasOwn(flags, flag)) fail(400, 'InvalidCommand', 'Unknown option; use --help for usage.');
      const key = flags[flag as keyof typeof flags], value = split < 0 ? args[++i] : arg.slice(split + 1);
      if (value === undefined || result[key] !== undefined) fail(400, 'InvalidCommand', 'Missing value or duplicate option; use --help for usage.');
      result[key] = value;
    }
  }
  if (result.generate && result.envFile !== undefined)
    fail(400, 'InvalidCommand', 'Use either --generate or --env-file, not both.');
  return result;
}
export async function collectTenantKeyValues(names: KeyEnvironmentNames, options: TenantKeyArguments, ask: (label: string) => Promise<string> = readHiddenInput) {
  let source: NodeJS.ProcessEnv = {};
  if (options.envFile !== undefined) {
    try { source = parseEnv(readFileSync(options.envFile, 'utf8')); }
    catch { fail(400, 'ImportFileUnavailable', 'Cannot read the selected key .env file; check its path and permissions.'); }
  }
  const values: NodeJS.ProcessEnv = {};
  for (const name of names) values[name] = source[name] === undefined || source[name] === ''
    ? await ask((options.envFile ? `Missing or blank in the selected .env file.\n` : '') + keyValuePrompt(name, names.indexOf(name)))
    : source[name];
  return values;
}
export async function promptTenantKeySetup(ask: (label: string) => Promise<string> = readVisibleInput, options: TenantKeyArguments = {}) {
  const environment = scopePart((options.environment ?? await ask('Environment ID: enter the environment from your grant, e.g. development (press Enter for development)')).trim() || 'development');
  const tenant = scopePart((options.tenant ?? await ask('Tenant ID (required): enter the exact tenant from your grant, e.g. fcrww; not a display name')).trim());
  const scope = { environment, tenant };
  const reference = options.name !== undefined ? tenantKeySet(scope, options.name.trim()).reference : await promptKeySetName(scope, ask);
  const prefix = `WORKFLOW_REAL_${tenant.toUpperCase().replaceAll('-', '_')}`;
  const defaults = [`${prefix}_WRAPPING_KEY_V1`, `${prefix}_INDEX_KEY`, `${prefix}_CONTROL_KEY`];
  return { scope, reference, envNames: validateKeyEnvironmentNames(defaults) };
}
export async function createTenantKeys(
  store: MongoStore, scope: Scope, token: string, reference: string, envNames: KeyEnvironmentNames,
  confirm: (values: NodeJS.ProcessEnv) => Promise<void> = values => confirmTenantKeys(values, scope, readHiddenInput, undefined, reference, envNames),
  supplied?: NodeJS.ProcessEnv,
) {
  const layout = tenantKeySet(scope, reference), variables = validateKeyEnvironmentNames(envNames);
  await new GrantService(store).authorize(`Bearer ${token}`, scope, ['read', 'write']);
  const exists = await store.read(scope, ns => layout.entries.some(e =>
    !!ns?.secrets[e.name]?.length || ns?.tombstones.includes(`secrets/${e.name}`)));
  if (exists) fail(409, 'KeySetAlreadyExists', 'This key set already exists or was deleted; choose a new reference. Existing keys will not be rotated.');
  const values: NodeJS.ProcessEnv = supplied ? { ...supplied } : {}, seen = new Set<string>();
  for (const name of supplied ? [] : variables) {
    let value: string;
    do { value = randomBytes(32).toString('base64'); } while (seen.has(value));
    seen.add(value); values[name] = value;
  }
  validatedKeys(values, variables);
  await confirm(values);
  const { imported, skipped: _skipped, ...result } = await importTenantKeySet(store, scope, token, values, reference, { envNames: variables, createOnly: true });
  return { ...result, created: imported };
}
async function main() {
  const options = parseTenantKeyArgs(process.argv.slice(2));
  const setup = await promptTenantKeySetup(readVisibleInput, options);
  const token = options.token ?? process.env.VAULT_TOKEN ?? await readHiddenInput(grantTokenPrompt);
  const store = await MongoStore.open(loadConfig(loadBootstrapEnvironment(fileURLToPath(new URL('../.env', import.meta.url)))));
  try {
    await new GrantService(store).authorize(`Bearer ${token}`, setup.scope, ['read', 'write']);
    const supplied = options.generate ? undefined : await collectTenantKeyValues(setup.envNames, options);
    const confirm = (values: NodeJS.ProcessEnv) => confirmTenantKeys(values, setup.scope,
      options.yes ? async () => 'yes' : readHiddenInput, undefined, setup.reference, setup.envNames);
    process.stdout.write(JSON.stringify(await createTenantKeys(store, setup.scope, token, setup.reference, setup.envNames, confirm, supplied), null, 2) + '\n');
  } finally { await store.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch(error => { process.stderr.write(`[create-keys] ${formatStartupError(error)}\n`); process.exitCode = 1; });
}
