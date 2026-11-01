import { createApp } from './app';
import { loadConfig } from './config';
async function main() {
  const config = loadConfig();
  const app = await createApp(config);
  const stop = async () => { await app.close(); process.exit(0); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try { await app.listen(Number(new URL(config.baseUrl).port || 80), '127.0.0.1'); }
  catch { await app.close(); throw new Error('StartupFailed'); }
  process.stdout.write('Local vault ready on loopback\n');
}
void main().catch(() => { process.stderr.write('Vault startup failed; check bootstrap, MongoDB availability and credentials.\n'); process.exitCode = 1; });
