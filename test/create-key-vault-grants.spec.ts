import { existsSync, readFileSync } from 'node:fs';
import { GrantService } from '../src/grants.js';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';

function fixture() {
  let registry: any[] = [];
  const store = { readGrants: async () => structuredClone(registry), transactionGrants: async (fn: (rows: any[]) => unknown) => {
    const copy = structuredClone(registry); const result = fn(copy); registry = copy; return result;
  } };
  return { grants: new GrantService(store as any), store, rows: () => registry };
}

it('creates the requested read-only grant set in one registry transaction', async () => {
  const f = fixture();
  expect(typeof (f.grants as any).createReadGrants).toBe('function');
  const result = await (f.grants as any).createReadGrants([{ environment: 'development', tenant: '_shared' }, { environment: 'development', tenant: 'fcrww' }]);
  expect(result).toMatchObject({ schemaVersion: 1, grants: [{ environment: 'development', tenant: '_shared' }, { environment: 'development', tenant: 'fcrww' }] });
  expect(f.rows().map(row => row.permissions)).toEqual([['read'], ['read']]);
  expect(new Set(result.grants.map((row: any) => row.token)).size).toBe(2);
  for (const grant of result.grants) {
    expect(grant.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(f.rows())).not.toContain(grant.token);
    await expect(f.grants.authorize(`Bearer ${grant.token}`, grant, ['read'])).resolves.toBeUndefined();
    for (const permission of ['write', 'crypto', 'list'] as const) await expect(f.grants.authorize(`Bearer ${grant.token}`, grant, [permission])).rejects.toThrow('Forbidden');
  }
});

it('validates the whole batch before persisting and rejects duplicates or oversized batches', async () => {
  const f = fixture();
  expect(typeof (f.grants as any).createReadGrants).toBe('function');
  const good = { environment: 'development', tenant: 'fcrww' };
  for (const batch of [[], [good, { ...good, tenant: 'bad tenant' }], [good, good], Array.from({ length: 34 }, (_, i) => ({ ...good, tenant: 'club' + i }))]) {
    await expect((f.grants as any).createReadGrants(batch)).rejects.toThrow();
    expect(f.rows()).toEqual([]);
  }
});

it('parses clubs/shared flags, rejects ambiguous input and prints a shell-ready JSON export', async () => {
  expect(existsSync(new URL('../src/create-key-vault-grants-cli.ts', import.meta.url))).toBe(true);
  const cli = await import('../src/create-key-vault-grants-cli.js');
  expect(cli.parseGrantArguments(['--clubs', ' fcrww, fcuster, fcrww ', '--shared'])).toEqual({ environment: 'development', tenants: ['_shared', 'fcrww', 'fcuster'] });
  expect(cli.parseGrantArguments(['--shared', '--environment', 'dev'])).toEqual({ environment: 'dev', tenants: ['_shared'] });
  for (const args of [[], ['--clubs'], ['--clubs', ''], ['--clubs', 'a,,b'], ['--clubs', '_shared'], ['--clubs', 'bad name'], ['--shared', '--shared'], ['--shared', '--unknown'], ['--shared', '--environment', 'production'], ['--clubs', Array.from({length:33}, (_,i)=>'club'+i).join(',')]]) expect(() => cli.parseGrantArguments(args)).toThrow();
  const f = fixture(), output: string[] = [];
  await cli.runCreateKeyVaultGrants(['--clubs', 'fcrww,fcuster', '--shared'], f.grants, line => output.push(line));
  expect(output).toHaveLength(1);
  const match = /^export LOCAL_KEYVAULT_AUTH_JSON='([^']+)'$/.exec(output[0]!);
  expect(match).not.toBeNull();
  const auth = JSON.parse(match![1]!);
  expect(JSON.parse(parseEnv(output[0]!).LOCAL_KEYVAULT_AUTH_JSON!)).toEqual(auth);
  expect(Object.keys(auth)).toEqual(['schemaVersion', 'grants']);
  expect(auth.grants.map((row: any) => row.tenant)).toEqual(['_shared', 'fcrww', 'fcuster']);
  expect(f.rows()).toHaveLength(3);
  await cli.runCreateKeyVaultGrants(['--clubs', 'fcrww,fcuster', '--shared'], f.grants, () => {});
  expect(f.rows()).toHaveLength(6);
  for (const grant of auth.grants) await expect(f.grants.authorize(`Bearer ${grant.token}`, grant, ['read'])).resolves.toBeUndefined();
});

it('prints no credentials if persistence fails and shell help needs no compilation or database', async () => {
  expect(existsSync(new URL('../src/create-key-vault-grants-cli.ts', import.meta.url))).toBe(true);
  const cli = await import('../src/create-key-vault-grants-cli.js');
  const f = fixture(), output: string[] = [];
  f.store.transactionGrants = async () => { throw Error('test persistence failure'); };
  await expect(cli.runCreateKeyVaultGrants(['--shared'], f.grants, line => output.push(line))).rejects.toThrow();
  expect(output).toEqual([]);
  const script = readFileSync(new URL('../create-key-vault-grants.sh', import.meta.url), 'utf8');
  expect(script.indexOf('--help|-h')).toBeLessThan(script.indexOf('npm run build'));
  const help = execFileSync('/bin/sh', [fileURLToPath(new URL('../create-key-vault-grants.sh', import.meta.url)), '--help'], { env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
  expect(help).toContain('LOCAL_KEYVAULT_AUTH_JSON');
});
