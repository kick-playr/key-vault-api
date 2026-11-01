import { bindingDigest, createSecretsRuntime, type RuntimeSnapshotRequest } from '@kick-playr/local-key-vault/runtime-client';

const shared = { environment: 'development', tenant: '_shared' }, tenant = { environment: 'development', tenant: 'fcrww' };
function request(mapping: string, revision: number): RuntimeSnapshotRequest {
  const body = { schemaVersion: 1 as const, bindingRevision: revision, keySets: [], secrets: [{ mapping, purpose: 'test-purpose', version: 'a'.repeat(32) }] };
  return { ...body, bindingDigest: bindingDigest(body) };
}
function fixture(tenantGrant = true) {
  const processRequest = request('PROCESS_SECRET', 1), tenantRequest = request('TENANT_SECRET', 2);
  const parent = { schemaVersion: 1, application: 'club-api', scope: shared, request: processRequest, tenants: [{ tenant: 'fcrww', bindingRevision: 2, bindingDigest: tenantRequest.bindingDigest }] };
  const child = { schemaVersion: 1, application: 'club-api', scope: tenant, request: tenantRequest, tenants: [] };
  const environment = { NODE_ENV: 'development', SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT', PROCESS_SECRET: 'stale-env-canary', LOCAL_KEYVAULT_AUTH_JSON: JSON.stringify({ schemaVersion: 1, grants: [{ ...shared, token: 's'.repeat(32) }, ...(tenantGrant ? [{ ...tenant, token: 't'.repeat(32) }] : [])] }) };
  const calls: { url: string; options: RequestInit }[] = [];
  const fetch = async (url: any, options: RequestInit = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith('/local/runtime-manifests/club-api')) return Response.json(parent);
    if (String(url).endsWith('/local/runtime-manifests/club-api/2')) return Response.json(child);
    const body = JSON.parse(options.body as string), scope = (options.headers as Record<string,string>)['x-vault-tenant'] === '_shared' ? shared : tenant;
    return Response.json({ schemaVersion: 1, ...scope, bindingRevision: body.bindingRevision, bindingDigest: body.bindingDigest, generation: 1, loadedAt: Date.now(), keySets: [], secrets: body.secrets.map((s: unknown) => ({ ...(s as object), value: 'vault-only-canary', attributes: { enabled: true, created: 1, updated: 1, recoveryLevel: 'Purgeable' } })) });
  };
  return { processRequest, tenantRequest, parent, child, environment, fetch, calls };
}
const policy = { allowedMappings: ['PROCESS_SECRET'], requiredMappings: ['PROCESS_SECRET'] };

it('discovers the process manifest with shared-only auth and defers tenant reads', async () => {
  const f = fixture(false), runtime = createSecretsRuntime({ environment: f.environment, fetch: f.fetch });
  try {
    const application = await runtime.loadApplication('club-api');
    expect(application.request.bindingDigest).toBe(f.processRequest.bindingDigest);
    expect(Object.isFrozen(application)).toBe(true);
    expect(f.calls).toHaveLength(1);
    expect((await runtime.loadProcess('club-api', policy)).mappings.PROCESS_SECRET).toBe('vault-only-canary');
    expect(f.calls.map(c => c.options.method)).toEqual(['GET', 'POST']);
    expect(f.calls[0]!.options.body).toBeUndefined();
    await runtime.loadProcess('club-api', policy);
    expect(f.calls).toHaveLength(2);
    await expect(runtime.loadTenant('fcrww', 2)).rejects.toThrow();
    expect(f.calls).toHaveLength(2);
  } finally { runtime.close(); }
});
it('loads immutable revision-pinned tenant manifests and exposes sealed metadata for API startup', async () => {
  const f = fixture(), runtime = createSecretsRuntime({ environment: f.environment, fetch: f.fetch });
  try {
    const bindings = await runtime.loadBindings('club-api');
    expect(bindings.tenants[0]!.request.bindingRevision).toBe(2);
    expect(Object.isFrozen(bindings.tenants)).toBe(true);
    expect(f.calls.map(c => c.url.split('/local/')[1])).toEqual(['runtime-manifests/club-api', 'runtime-manifests/club-api/2']);
    const loaded = await runtime.loadTenant('fcrww', 2);
    expect(loaded.secrets[0]!.value).toBe('vault-only-canary');
    expect((f.calls[1]!.options.headers as any).Authorization).toBe('Bearer ' + 't'.repeat(32));
    await expect(runtime.loadTenant('fcrww', 3)).rejects.toThrow();
    await expect(runtime.loadTenant('unconfigured', 1)).rejects.toThrow();
    const count = f.calls.length;
    f.parent.tenants[0]!.bindingRevision = 3;
    await runtime.loadBindings('club-api'); await runtime.loadTenant('fcrww', 2);
    expect(f.calls).toHaveLength(count);
    await expect(runtime.loadProcess('another-app', policy)).rejects.toThrow();
  } finally { runtime.close(); }
});
it.each(['application', 'scope', 'digest', 'secret-field'])('rejects substituted process manifest %s without fetching secrets or falling back', async mode => {
  const f = fixture();
  if (mode === 'application') f.parent.application = 'other';
  if (mode === 'scope') f.parent.scope = tenant;
  if (mode === 'digest') f.parent.request.bindingDigest = '0'.repeat(64);
  if (mode === 'secret-field') (f.parent as any).value = 'must-not-be-metadata';
  const runtime = createSecretsRuntime({ environment: f.environment, fetch: f.fetch });
  try { await expect(runtime.loadProcess('club-api', policy)).rejects.toThrow(); expect(f.calls).toHaveLength(1); }
  finally { runtime.close(); }
});
it('rejects a tenant manifest that does not match the parent digest before snapshot access', async () => {
  const f = fixture(); f.parent.tenants[0]!.bindingDigest = '0'.repeat(64);
  const runtime = createSecretsRuntime({ environment: f.environment, fetch: f.fetch });
  try {
    await runtime.loadProcess('club-api', policy);
    await expect(runtime.loadTenant('fcrww', 2)).rejects.toThrow();
    expect(f.calls.map(c => c.options.method)).toEqual(['GET', 'POST', 'GET']);
  } finally { runtime.close(); }
});
it('keeps failed manifest discovery sticky until a fresh runtime and never falls back to ENV', async () => {
  const f = fixture(); let calls = 0;
  const runtime = createSecretsRuntime({ environment: f.environment, fetch: async () => { calls++; return Response.json({ error: 'not-found' }, { status: 404 }); } });
  try {
    await expect(runtime.loadProcess('club-api', policy)).rejects.toThrow();
    await expect(runtime.loadProcess('club-api', policy)).rejects.toThrow();
    expect(calls).toBe(1);
  } finally { runtime.close(); }
});
