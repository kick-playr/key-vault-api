import { bindingDigest, createSecretsRuntime, selectSecretsStrategy, snapshotMappings } from '@kick-playr/local-key-vault/runtime-client';
import type { RuntimeSnapshotRequest } from '@kick-playr/local-key-vault/runtime-client';
const pin = 'a'.repeat(32), token = 'test-only-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
function fixture() {
  const scope = { environment: 'development', tenant: '_shared' };
  const request: RuntimeSnapshotRequest = { schemaVersion: 1, bindingRevision: 1, bindingDigest: '', keySets: [], secrets: [{ mapping: 'SHARED_KEY', purpose: 'shared-key', version: pin }] };
  request.bindingDigest = bindingDigest(request);
  const attributes = { enabled: true, created: 1, updated: 1, recoveryLevel: 'Purgeable' };
  const response = { schemaVersion: 1, ...scope, bindingRevision: 1, bindingDigest: request.bindingDigest, generation: 3, loadedAt: Date.now(), keySets: [], secrets: [{ ...request.secrets[0], value: 'vault-only-secret', attributes }] };
  const environment = { NODE_ENV: 'test', SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT', SHARED_KEY: 'old-environment-value', LOCAL_KEYVAULT_BINDINGS_JSON: JSON.stringify({ schemaVersion: 1, applications: { app: { scope, request } }, tenants: [] }), LOCAL_KEYVAULT_AUTH_JSON: JSON.stringify({ schemaVersion: 1, grants: [{ ...scope, token }] }) };
  return { scope, request, response, environment };
}
describe('server secrets runtime', () => {
  it('preserves environment default and rejects empty/unknown selectors', async () => {
    expect(selectSecretsStrategy({})).toBe('ENV_VARIABLES');
    for (const selected of ['', 'AZURE_KEYVAULT', 'local_keyvault']) expect(() => selectSecretsStrategy({ SECRETS_KEYS_STRATEGY: selected })).toThrow('Secrets configuration unavailable');
    const runtime = createSecretsRuntime({ environment: { SHARED_KEY: 'legacy' }, fetch: (() => { throw Error('must not call'); }) as any });
    expect(await runtime.loadProcess('app', { allowedMappings: ['SHARED_KEY'] })).toEqual({ strategy: 'ENV_VARIABLES', mappings: { SHARED_KEY: 'legacy' } });
  });
  it('only calls the read snapshot route and retains loaded values through outage without modifying env', async () => {
    const f = fixture(); let calls = 0;
    const runtime = createSecretsRuntime({ environment: f.environment, fetch: (async (url, init) => {
      calls++; expect(url).toBe('http://127.0.0.1:4000/local/runtime-snapshot'); expect(init?.method).toBe('POST'); expect(init?.redirect).toBe('error');
      expect(init?.headers).toMatchObject({ Authorization: `Bearer ${token}`, 'x-vault-tenant': '_shared' });
      return Response.json(f.response);
    }) as typeof fetch });
    const result = await runtime.loadProcess('app', { allowedMappings: ['SHARED_KEY'], requiredMappings: ['SHARED_KEY'] });
    expect(result.mappings.SHARED_KEY).toBe('vault-only-secret'); expect(f.environment.SHARED_KEY).toBe('old-environment-value');
    f.response.loadedAt = 1;
    expect((await runtime.loadProcess('app', { allowedMappings: ['SHARED_KEY'] })).mappings.SHARED_KEY).toBe('vault-only-secret');
    expect(calls).toBe(1); expect(Object.isFrozen(result.snapshot)).toBe(true);
    runtime.close(); await expect(runtime.loadProcess('app', { allowedMappings: ['SHARED_KEY'] })).rejects.toThrow('Secrets configuration unavailable');
  });
  it('fails missing/denied/wrong-tenant/version/extra-map reads without fallback or secret-bearing error output', async () => {
    for (const mutate of [ (r: any) => { r.tenant = 'other'; }, (r: any) => { r.secrets[0].version = 'b'.repeat(32); }, (r: any) => { r.secrets.push({ ...r.secrets[0], mapping: 'OTHER_SECRET' }); }, (r: any) => { r.secrets[0].attributes.enabled = false; } ]) {
      const f = fixture(); mutate(f.response);
      const runtime = createSecretsRuntime({ environment: f.environment, fetch: (async () => Response.json(f.response)) as typeof fetch });
      await expect(runtime.loadProcess('app', { allowedMappings: ['SHARED_KEY'] })).rejects.toThrow('Secrets configuration unavailable');
    }
    const f = fixture(); let calls = 0;
    const runtime = createSecretsRuntime({ environment: f.environment, fetch: (async () => { calls++; return Response.json({ error: token }, { status: 403 }); }) as typeof fetch });
    await expect(runtime.loadProcess('app', { allowedMappings: ['SHARED_KEY'] })).rejects.toThrow('Secrets configuration unavailable'); expect(calls).toBe(1);
  });
  it('rejects undeclared mappings, missing required mappings and production before a request', async () => {
    const f = fixture(), fetcher = (() => { throw Error('must not call'); }) as typeof fetch;
    const runtime = createSecretsRuntime({ environment: f.environment, fetch: fetcher });
    await expect(runtime.loadProcess('app', { allowedMappings: ['OTHER_SECRET'] })).rejects.toThrow('Secrets configuration unavailable');
    await expect(runtime.loadProcess('app', { allowedMappings: ['SHARED_KEY', 'REQUIRED_KEY'], requiredMappings: ['REQUIRED_KEY'] })).rejects.toThrow('Secrets configuration unavailable');
    expect(() => createSecretsRuntime({ environment: { ...f.environment, NODE_ENV: 'production' }, fetch: fetcher })).toThrow('Secrets configuration unavailable');
    expect(() => snapshotMappings({ keySets: [], secrets: [{ mapping: 'NEXT_PUBLIC_SECRET', value: 'value' }] } as any)).toThrow('Secrets configuration unavailable');
  });
  it('bounds responses and retries only transient failures, while isolating concurrent namespace loads', async () => {
    const f = fixture(); let calls = 0;
    const runtime = createSecretsRuntime({ environment: f.environment, fetch: (async () => { calls++; return calls === 1 ? Response.json({}, { status: 503 }) : Response.json(f.response); }) as typeof fetch });
    const [a, b] = await Promise.all([runtime.load(f.scope, f.request), runtime.load(f.scope, f.request)]);
    expect(calls).toBe(2); expect(a).toBe(b);
    const oversized = createSecretsRuntime({ environment: f.environment, fetch: (async () => new Response('x'.repeat(4 * 1024 * 1024 + 1), { headers: { 'content-type': 'application/json' } })) as typeof fetch });
    await expect(oversized.load(f.scope, f.request)).rejects.toThrow('Secrets configuration unavailable');
    const next = fixture(); next.environment.LOCAL_KEYVAULT_AUTH_JSON = JSON.stringify({ schemaVersion: 1, grants: [{ environment: 'development', tenant: 'other', token }] });
    const missing = createSecretsRuntime({ environment: next.environment, fetch: (async () => { throw Error('must not call'); }) as typeof fetch });
    await expect(missing.load(next.scope, next.request)).rejects.toThrow('Secrets configuration unavailable');
  });
  it('uses an injected scoped credential supplier without a local token fallback', async () => {
    const f = fixture(); delete (f.environment as any).LOCAL_KEYVAULT_AUTH_JSON;
    const runtime = createSecretsRuntime({ environment: f.environment, credentialSupplier: selected => { expect(selected).toEqual(f.scope); return token; }, fetch: (async (_url, init) => { expect(init?.headers).toMatchObject({ Authorization: `Bearer ${token}` }); return Response.json(f.response); }) as typeof fetch });
    expect((await runtime.loadProcess('app', { allowedMappings: ['SHARED_KEY'] })).mappings.SHARED_KEY).toBe('vault-only-secret');
  });
  it('never mixes concurrently loaded tenants and rejects a different tenant revision', async () => {
    const f = fixture();
    const bindings = { schemaVersion: 1, applications: {}, tenants: ['a', 'b'].map(tenant => ({ scope: { ...f.scope, tenant }, request: f.request })) };
    f.environment.LOCAL_KEYVAULT_BINDINGS_JSON = JSON.stringify(bindings);
    f.environment.LOCAL_KEYVAULT_AUTH_JSON = JSON.stringify({ schemaVersion: 1, grants: ['a', 'b'].map(tenant => ({ ...f.scope, tenant, token })) });
    const runtime = createSecretsRuntime({ environment: f.environment, fetch: (async (_url, init) => { const tenant = (init?.headers as Record<string, string>)['x-vault-tenant']; return Response.json({ ...f.response, tenant, secrets: [{ ...f.response.secrets[0], value: 'secret-for-' + tenant }] }); }) as typeof fetch });
    const [a, b] = await Promise.all([runtime.loadTenant('a', 1), runtime.loadTenant('b', 1)]);
    expect(snapshotMappings(a).SHARED_KEY).toBe('secret-for-a'); expect(snapshotMappings(b).SHARED_KEY).toBe('secret-for-b');
    await expect(runtime.loadTenant('a', 2)).rejects.toThrow('Secrets configuration unavailable');
  });
  it('sanitizes malformed authentication JSON without exposing credential text', () => {
    const f = fixture(); f.environment.LOCAL_KEYVAULT_AUTH_JSON = '{"secret-token-xxxxxxxxxxxxxxxxxxxxxxxx":';
    expect(() => createSecretsRuntime({ environment: f.environment })).toThrow(/^Secrets configuration unavailable$/);
  });
});
