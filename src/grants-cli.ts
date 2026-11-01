import { pathToFileURL } from 'node:url';
import { loadBootstrapConfig, loadBootstrapEnvironment } from './config.js';
import { fail, formatStartupError } from './errors.js';
import { GrantService } from './grants.js';
import { MongoStore } from './store.js';

const usage = 'Usage: ./grants.sh create [environment tenant [read,write,crypto,list]] | list | permissions <id> <comma-separated-permissions> | revoke <id> | rotate <id> | import';
export async function runGrantCommand(args: string[], grants: GrantService, env: NodeJS.ProcessEnv = {}, output: (value: string) => void = console.log) {
  const [command, first, second, third] = args;
  let result: unknown;
  if (command === 'create' && [1, 3, 4].includes(args.length)) {
    result = await grants.create({ environment: first ?? 'dev', tenant: second ?? 'tenant-123' }, (third ?? 'read,write,crypto,list').split(','));
  } else if (command === 'list' && args.length === 1) {
    result = await grants.list();
  } else if (command === 'revoke' && args.length === 2) {
    result = await grants.revoke(first!);
  } else if (command === 'rotate' && args.length === 2) {
    result = await grants.rotate(first!);
  } else if (command === 'permissions' && args.length === 3) {
    result = await grants.setPermissions(first!, second!.split(','));
  } else if (command === 'import' && args.length === 1) {
    let input: unknown;
    try { input = JSON.parse(env.VAULT_GRANTS ?? ''); } catch { fail(400, 'InvalidGrants', 'Import requires a valid legacy VAULT_GRANTS JSON array in .env or the environment.'); }
    result = await grants.import(input);
  } else { fail(400, 'InvalidCommand', usage); }
  output(JSON.stringify(result, null, 2));
}
async function main() {
  const env = loadBootstrapEnvironment();
  const store = await MongoStore.open(loadBootstrapConfig());
  try { await runGrantCommand(process.argv.slice(2), new GrantService(store), env); }
  finally { await store.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch(error => { process.stderr.write(`[grants] ${formatStartupError(error)}\n`); process.exitCode = 1; });
}
