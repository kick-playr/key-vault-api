import { pathToFileURL } from 'node:url';
import { loadBootstrapConfig } from './config.js';
import { fail, formatStartupError } from './errors.js';
import { GrantService } from './grants.js';
import { MongoStore } from './store.js';
import { scopePart } from './validation.js';

const usage = 'Usage: ./create-key-vault-grants.sh [--clubs "fcrww,fcuster"] [--shared] [--environment development|dev|test]';
export function parseGrantArguments(args: string[]): { environment: string; tenants: string[] } {
  let clubs: string[] = [], shared = false, environment = 'development';
  const seen = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i]!;
    if (!['--clubs', '--shared', '--environment'].includes(flag) || seen.has(flag)) fail(400, 'InvalidCommand', usage);
    seen.add(flag);
    if (flag === '--shared') { shared = true; continue; }
    const value = args[++i];
    if (typeof value !== 'string' || !value.trim() || value.startsWith('--')) fail(400, 'InvalidCommand', usage);
    if (flag === '--environment') {
      if (!['development', 'dev', 'test'].includes(value)) fail(400, 'InvalidCommand', usage);
      environment = value;
    } else {
      clubs = [...new Set(value.split(',').map(club => scopePart(club.trim())))];
      if (clubs.includes('_shared') || clubs.length > 32) fail(400, 'InvalidCommand', usage);
    }
  }
  const tenants = [...(shared ? ['_shared'] : []), ...clubs];
  if (!tenants.length) fail(400, 'InvalidCommand', usage);
  return { environment, tenants };
}
export async function runCreateKeyVaultGrants(args: string[], grants: GrantService, output: (line: string) => void = console.log) {
  const { environment, tenants } = parseGrantArguments(args);
  const result = await grants.createReadGrants(tenants.map(tenant => ({ environment, tenant })));
  // Values are generated base64url tokens and validated namespace identifiers.
  // Quote defensively so the single output line is safe to source in a shell.
  const quoted = JSON.stringify(result).replaceAll("'", "'\\''");
  output(`export LOCAL_KEYVAULT_AUTH_JSON='${quoted}'`);
}
async function main() {
  const args = process.argv.slice(2);
  parseGrantArguments(args); // Reject bad input before connecting to MongoDB.
  const store = await MongoStore.open(loadBootstrapConfig());
  try { await runCreateKeyVaultGrants(args, new GrantService(store)); }
  finally { await store.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch(error => { process.stderr.write(`[key-vault-grants] ${formatStartupError(error)}\n`); process.exitCode = 1; });
}
