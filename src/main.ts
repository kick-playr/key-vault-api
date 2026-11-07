import { createApp } from './app.js';
import {createActivatedV2App} from './v2/activated-app.js';
import { loadBootstrapConfig, loadBootstrapEnvironment } from './config.js';
import { describeSystemError, formatStartupError, VaultError } from './errors.js';
async function main() {
  const config = loadBootstrapConfig();
  const authority=loadBootstrapEnvironment().VAULT_STORAGE_AUTHORITY;
  if(authority&&authority!=='v2'&&authority!=='legacy')throw Error('Invalid Vault storage authority');
  const app = await (authority==='v2'?createActivatedV2App(config):createApp(config)).catch(error => {
    if (error instanceof VaultError) throw error;
    throw new VaultError(500, 'StartupFailed', `Application initialization: ${describeSystemError(error)}`);
  });
  const stop = async () => { await app.close(); process.exit(0); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try { await app.listen(Number(new URL(config.baseUrl).port || 80), '127.0.0.1'); }
  catch (error) {
    await app.close().catch(() => undefined);
    throw new VaultError(500, 'StartupFailed', `Cannot listen at ${config.baseUrl}: ${describeSystemError(error)}`);
  }
  process.stdout.write(`Local vault ready at ${config.baseUrl}\n`);
  process.stdout.write(`Swagger UI: ${config.baseUrl.replace(/\/$/, '')}/docs\n`);
}
void main().catch(error => { process.stderr.write(`[startup] ${formatStartupError(error)}\n`); process.exitCode = 1; });
