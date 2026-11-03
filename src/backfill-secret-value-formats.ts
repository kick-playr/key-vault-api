import { loadBootstrapConfig } from './config.js';
import { MongoStore } from './store.js';
const args=process.argv.slice(2);
if(args.some(a=>!['--apply','--dry-run'].includes(a)) || args.includes('--apply')&&args.includes('--dry-run')) {
  console.error('Usage: node dist/backfill-secret-value-formats.js [--dry-run|--apply]');process.exitCode=1;
} else {
  let store: MongoStore | undefined;
  let config: ReturnType<typeof loadBootstrapConfig> | undefined;
  try {
    config=loadBootstrapConfig();store=await MongoStore.open(config,{createVerifier:false});
    console.log(JSON.stringify(await store.backfillSecretValueFormats(!args.includes('--apply'))));
  } catch { console.error('Secret format migration failed; sensitive details suppressed. Safe to retry after checking connectivity.');process.exitCode=1; }
  finally { await store?.close();config?.masterKey.fill(0); }
}
