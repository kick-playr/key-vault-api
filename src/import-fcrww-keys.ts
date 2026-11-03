import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { loadBootstrapEnvironment, loadConfig } from './config.js';
import { fail, formatStartupError } from './errors.js';
import { GrantService } from './grants.js';
import { MongoStore } from './store.js';
import type { Scope } from './types.js';
import { envName, scopePart } from './validation.js';
import { tenantKeySet } from './tenant-key-tree.js';
import { active, changed, newSecret } from './vault.js';

const mappings = [
  ['WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1', 'wrapping/v1'],
  ['WORKFLOW_REAL_FCRWW_INDEX_KEY', 'index'],
  ['WORKFLOW_REAL_FCRWW_CONTROL_KEY', 'control'],
] as const;
export type KeyEnvironmentNames = readonly [string, string, string];
export function validateKeyEnvironmentNames(names: readonly string[]): KeyEnvironmentNames {
  try {
    if (!Array.isArray(names) || names.length !== 3 || new Set(names).size !== 3) throw new Error();
    return names.map(name => envName(name)) as [string, string, string];
  } catch { fail(400, 'InvalidKeyMappings', 'Supply three distinct server-only environment-variable names, one for each key role.'); }
}
export function validatedKeys(source: NodeJS.ProcessEnv, variables: KeyEnvironmentNames = validateKeyEnvironmentNames(mappings.map(m => m[0]))) {
  const keys = mappings.map(([_defaultVariable, name], index) => {
    const variable = variables[index]!;
    const value = source[variable];
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value) || Buffer.from(value, 'base64').length !== 32 ||
        Buffer.from(value, 'base64').toString('base64') !== value) fail(400, 'InvalidImportKeys', `Missing or invalid ${variable}; expected a canonical Base64-encoded 32-byte key.`);
    return { variable, name, value };
  });
  if (new Set(keys.map(k => k.value)).size !== 3) fail(400, 'InvalidImportKeys', 'Wrapping, index and control keys must be distinct.');
  return keys;
}
export async function importTenantKeySet(store: MongoStore, scope: Scope, token: string, source: NodeJS.ProcessEnv, keySetName = `workflow-local:${scope.tenant}:key`, options: { envNames?: KeyEnvironmentNames; createOnly?: boolean } = {}) {
  scopePart(scope.environment); scopePart(scope.tenant);
  const layout = tenantKeySet(scope, keySetName);
  const variables = validateKeyEnvironmentNames(options.envNames ?? mappings.map(m => m[0]));
  const keys = validatedKeys(source, variables).map((key, index) => ({ ...key, ...layout.entries[index]!,
    tags: { purpose: layout.entries[index]!.role, source: key.variable, envName: key.variable, keySet: layout.reference,
      keyProfile: layout.profile, keyRole: layout.entries[index]!.role, logicalPath: layout.entries[index]!.logicalPath },
  }));
  const grants = new GrantService(store);
  return store.transaction(scope, async ns => {
    // Re-check current grant permissions on every CAS retry. No authorization cache.
    await grants.authorize(`Bearer ${token}`, scope, ['read', 'write']);
    let imported = 0, skipped = 0;
    for (const key of keys) {
      const versions = Object.hasOwn(ns.secrets, key.name) ? ns.secrets[key.name]! : [];
      const latest = versions.at(-1);
      if (ns.tombstones.includes(`secrets/${key.name}`)) fail(409, options.createOnly ? 'KeySetAlreadyExists' : 'ImportConflict', 'A target secret was deleted; resolve it explicitly before importing.');
      if (latest && options.createOnly) fail(409, 'KeySetAlreadyExists', 'This named key set already has stored keys; use import for existing material or a new reference.');
      if (latest) {
        if (latest.value !== key.value || Object.entries(key.tags).some(([k, v]) => latest.tags?.[k] !== v)) fail(409, 'ImportConflict', 'An existing target secret has a different value or key-set mapping; no import was committed.');
        try { active(latest); } catch { fail(409, 'ImportConflict', 'An existing target secret is inactive; no import was committed.'); }
        skipped++;
      } else {
        ns.secrets[key.name] = [newSecret({ value: key.value, valueFormat: 'base64', tags: key.tags })];
        changed(ns, options.createOnly ? 'create:tenant-key' : 'import:secrets', key.name); imported++;
      }
    }
    return { ...scope, keySet: layout.reference, imported, skipped, secrets: keys.map(k => ({ name: k.name, path: k.logicalPath, envName: k.variable })) };
  });
}
export const importFcrwwKeys = importTenantKeySet;
async function readTerminalInput(label: string, hidden: boolean): Promise<string> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) fail(400, 'InteractiveInputRequired', 'Run in an interactive terminal to enter keys with hidden input.');
  const muted = new Writable({ write(_chunk, _encoding, done) { done(); } });
  const terminal = createInterface({ input: process.stdin, output: hidden ? muted : process.stderr, terminal: true, historySize: 0 });
  try {
    return await new Promise<string>((resolve, reject) => {
      let answered = false;
      const cancel = () => reject(new Error('InputCancelled'));
      terminal.once('SIGINT', () => { terminal.close(); cancel(); });
      terminal.once('close', () => { if (!answered) cancel(); });
      process.stderr.write(label + ': ');
      terminal.question('', answer => { answered = true; resolve(answer); });
    });
  } catch { fail(400, 'InputCancelled', 'Import cancelled before any keys were written.'); }
  finally { terminal.close(); muted.destroy(); process.stderr.write('\n'); }
}
export const grantTokenPrompt = 'Grant token VALUE (required): paste the token from create-grants.sh, without "Bearer "; not VAULT_MASTER_KEY. Input is hidden; press Enter after pasting';
export function keyValuePrompt(variable: string, index: number) {
  const role = ['wrapping/v1', 'index', 'control'][index];
  return `[${index + 1}/3] ${role} key VALUE for ${variable}: paste only its 44-character Base64 value (32 bytes), without quotes or a VARIABLE= prefix. Input is hidden; press Enter after pasting`;
}
export const readVisibleInput = (label: string) => readTerminalInput(label, false);
export const readHiddenInput = (label: string) => readTerminalInput(label, true);
export async function promptKeySetName(scope: Scope, ask: (label: string) => Promise<string> = label => readTerminalInput(label, false)) {
  const name = await ask(`Key-set name (required): enter <profile>:${scope.tenant}:key, e.g. workflow-local:${scope.tenant}:key; this is the group name, not an environment-variable name`);
  return tenantKeySet(scope, name.trim()).reference;
}
export async function promptFcrwwKeys(ask: (label: string) => Promise<string> = readHiddenInput): Promise<NodeJS.ProcessEnv> {
  const entered: NodeJS.ProcessEnv = {};
  for (const [index, [variable]] of mappings.entries()) entered[variable] = await ask(keyValuePrompt(variable, index));
  return entered;
}
export async function confirmFcrwwKeys(
  entered: NodeJS.ProcessEnv,
  scope: Scope,
  ask: (label: string) => Promise<string> = readHiddenInput,
  output: (line: string) => void = line => { process.stderr.write(line + '\n'); },
  keySetName = `workflow-local:${scope.tenant}:key`,
  variables?: KeyEnvironmentNames,
): Promise<void> {
  scopePart(scope.environment); scopePart(scope.tenant);
  const keys = validatedKeys(entered, variables ? validateKeyEnvironmentNames(variables) : undefined);
  const layout = tenantKeySet(scope, keySetName);
  for (const [index, key] of keys.entries()) output(`${layout.entries[index]!.logicalPath} -> ${key.variable}: ...${key.value.slice(-3)}`);
  const answer = await ask(`Save ${layout.reference} into ${scope.environment}/${scope.tenant}? Type yes and press Enter to save all 3 keys; anything else cancels (input hidden)`);
  if (answer.trim().toLowerCase() !== 'yes') fail(400, 'InputCancelled', 'Import cancelled; no keys were written.');
}
export const confirmTenantKeys = confirmFcrwwKeys;
async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 0 && args.length !== 2) fail(400, 'InvalidCommand', 'Usage: ./import-fcrww-keys.sh [environment tenant]');
  const config = loadConfig(loadBootstrapEnvironment());
  const scope = { environment: scopePart(args[0] ?? 'development'), tenant: scopePart(args[1] ?? 'fcrww') };
  const token = process.env.VAULT_TOKEN ?? await readHiddenInput(grantTokenPrompt);
  const store = await MongoStore.open(config);
  try {
    await new GrantService(store).authorize(`Bearer ${token}`, scope, ['read', 'write']);
    const keySetName = await promptKeySetName(scope);
    const entered = await promptFcrwwKeys();
    await confirmFcrwwKeys(entered, scope, readHiddenInput, undefined, keySetName);
    const result = await importFcrwwKeys(store, scope, token, entered, keySetName);
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } finally { await store.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch(error => { process.stderr.write(`[import] ${formatStartupError(error)}\n`); process.exitCode = 1; });
}
