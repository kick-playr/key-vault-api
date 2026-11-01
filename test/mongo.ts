import { spawn, ChildProcess } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { MongoClient } from 'mongodb';

// Each suite owns a disposable local mongod. Never uses VAULT_MONGODB_URI.
export let mongoUri: string;
let child: ChildProcess | undefined;
let dir: string;
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vault-mongo-test-'));
  const listener = createServer();
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = (listener.address() as { port: number }).port;
  await new Promise<void>(resolve => listener.close(() => resolve()));
  mongoUri = `mongodb://127.0.0.1:${port}`;
  let failure = false;
  child = spawn(process.env.MONGOD_BINARY ?? 'mongod', ['--bind_ip', '127.0.0.1', '--port', String(port), '--dbpath', dir, '--quiet', '--noauth', '--wiredTigerCacheSizeGB', '0.25', '--setParameter', 'enableTestCommands=1'], { stdio: 'ignore' });
  child.on('error', () => { failure = true; });
  child.on('exit', () => { failure = true; });
  const deadline = Date.now() + 15000;
  let lastError = '';
  while (!failure && Date.now() < deadline) {
    const client = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 200 });
    try { await client.connect(); await client.close(); return; }
    catch (error) { lastError = (error as Error).message; await client.close(); await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  throw new Error('Temporary MongoDB failed to start; install mongod or set MONGOD_BINARY. ' + lastError);
}, 20000);
afterAll(async () => {
  if (child && child.exitCode === null && child.pid) {
    const done = new Promise<void>(resolve => child!.once('exit', () => resolve()));
    child.kill('SIGTERM'); await done;
  }
  if (dir) await rm(dir, { recursive: true, force: true });
});
