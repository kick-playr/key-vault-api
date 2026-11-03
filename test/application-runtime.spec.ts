import { ApplicationRuntimeService } from '../src/application-runtime.js';
import { emptyNamespace, type Scope, type Namespace } from '../src/types.js';
import { newSecret } from '../src/vault.js';
const scope = { environment: 'development', tenant: '_shared' };
function fixture() {
  let ns = emptyNamespace();
  ns.applications = { app: { displayName: 'App', description: '' } };
  ns.secrets['arbitrary-database-name'] = [
    newSecret({ value: 'FIRST_CANARY' }),
  ];
  ns.resourceAssociations = {
    'secrets/arbitrary-database-name': {
      envName: 'DATABASE_URL',
      memberships: { app: 'latest' },
    },
  };
  ns.generation = 1;
  const store = {
    read: async (_s: Scope, fn: any) =>
      structuredClone(fn(structuredClone(ns))),
    transaction: async (_s: Scope, fn: any) => {
      const copy = structuredClone(ns);
      const result = await fn(copy);
      ns = copy;
      return structuredClone(result);
    },
  };
  return {
    service: new ApplicationRuntimeService(store as any),
    ns: () => ns,
  };
}
it('derives immutable explicit-resource descriptors from links and reads a coherent exact snapshot without plans', async () => {
  const f = fixture();
  const desired = await f.service.desired(scope, 'app');
  expect(desired.resources[0]).toMatchObject({
    name: 'arbitrary-database-name',
    mapping: 'DATABASE_URL',
    kind: 'secrets',
    policy: 'latest',
    classification: 'secret',
  });
  expect(JSON.stringify(desired)).not.toContain('FIRST_CANARY');
  const result = await f.service.snapshot(scope, 'app', {
    generation: desired.generation,
    digest: desired.digest,
  });
  expect(result.resources[0]!.value).toBe('FIRST_CANARY');
  const first = f.ns().secrets['arbitrary-database-name']![0]!;
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'SECOND_CANARY' }),
  );
  f.ns().generation++;
  await expect(
    f.service.snapshot(scope, 'app', {
      generation: desired.generation,
      digest: desired.digest,
    }),
  ).rejects.toThrow('ApplicationSnapshotChanged');
  expect(
    (await f.service.desired(scope, 'app')).resources[0]!.version,
  ).not.toBe(first.version);
  f.ns().resourceAssociations![
    'secrets/arbitrary-database-name'
  ]!.memberships.app = first.version;
  f.ns().generation++;
  expect((await f.service.desired(scope, 'app')).resources[0]!.version).toBe(
    first.version,
  );
});
it('rejects unsupported consumer mappings and missing or disabled candidates without partial values', async () => {
  const f = fixture();
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'UNREVIEWED_ENV';
  await expect(f.service.desired(scope, 'app')).rejects.toThrow(
    'UnsupportedApplicationMapping',
  );
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'DATABASE_URL';
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'BAD_CANARY', attributes: { enabled: false } }),
  );
  await expect(f.service.desired(scope, 'app')).rejects.toThrow(
    'ApplicationCandidateInactive',
  );
  delete f.ns().secrets['arbitrary-database-name'];
  await expect(f.service.desired(scope, 'app')).rejects.toThrow(
    'SecretNotFound',
  );
});
it('binds acknowledgements to issued instance proof, caller, application and exact desired digest without changing data generation', async () => {
  const f = fixture();
  const desired = await f.service.desired(scope, 'app');
  const instance = await f.service.register(scope, 'app', 'caller-a');
  const before = f.ns().generation;
  const body = {
    instanceId: instance.instanceId,
    proof: instance.proof,
    generation: desired.generation,
    digest: desired.digest,
    status: 'applied',
  };
  await expect(
    f.service.acknowledge(scope, 'app', 'caller-b', body),
  ).rejects.toThrow('Forbidden');
  await expect(
    f.service.acknowledge(scope, 'app', 'caller-a', {
      ...body,
      proof: 'x'.repeat(43),
    }),
  ).rejects.toThrow('Forbidden');
  await f.service.acknowledge(scope, 'app', 'caller-a', body);
  expect(f.ns().generation).toBe(before);
  const status = await f.service.status(scope, 'app');
  expect(status.state).toBe('applied');
  expect(JSON.stringify(status)).not.toContain(instance.proof);
  expect(JSON.stringify(status)).not.toContain('FIRST_CANARY');
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'SECOND_CANARY' }),
  );
  f.ns().generation++;
  expect((await f.service.status(scope, 'app')).state).toBe('updating');
  await expect(
    f.service.acknowledge(scope, 'app', 'caller-a', body),
  ).rejects.toThrow('ApplicationSnapshotChanged');
});
it('keeps encryption material explicit and never exports private RSA material', async () => {
  const f = fixture();
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'CLERK_ENCRYPTION_KEY';
  expect(
    (await f.service.desired(scope, 'app')).resources[0]!.classification,
  ).toBe('encryption-key');
  // No consumer currently declares a non-exportable-key ENV adapter.
  f.ns().keys['private-key'] = [
    {
      ...newSecret({ value: 'DO_NOT_EXPORT' }),
      privateKey: { kty: 'RSA', d: 'PRIVATE_CANARY' },
    },
  ];
  f.ns().resourceAssociations!['keys/private-key'] = {
    envName: 'CLERK_SECRET_KEY',
    memberships: { app: 'latest' },
  };
  await expect(f.service.desired(scope, 'app')).rejects.toThrow(
    'UnsupportedApplicationCapability',
  );
});
it('enforces runtime HTTP read grants while allowing bounded reports without configuration write permission', async () => {
  const { jest } = await import('@jest/globals');
  const { default: request } = await import('supertest');
  const { createHash, randomBytes } = await import('node:crypto');
  const { MongoStore } = await import('../src/store.js');
  const { createApp } = await import('../src/app.js');
  const f = fixture(),
    token = 'read-only-runtime-token-aaaaaaaaaaaaaa';
  const grant = {
    id: 'b'.repeat(64),
    tokenHash: createHash('sha256').update(token).digest('hex'),
    ...scope,
    permissions: ['read'],
    enabled: true,
  };
  const store = {
    readGrants: async () => [grant],
    read: async (_s: Scope, fn: any) =>
      structuredClone(fn(structuredClone(f.ns()))),
    transaction: async (_s: Scope, fn: any) => fn(f.ns()),
    appendAudit: async () => {},
    close: async () => {},
  };
  const spy = jest.spyOn(MongoStore, 'open').mockResolvedValue(store as any);
  const app = await createApp({
    mongoUri: 'mongodb://127.0.0.1:1/fixture',
    masterKey: randomBytes(32),
    baseUrl: 'http://127.0.0.1:4000',
    audit: { list: 'off', read: 'off', write: 'off', crypto: 'off' },
  });
  spy.mockRestore();
  await app.init();
  const call = (method: 'get' | 'post', path: string) =>
    request(app.getHttpServer())
      [method](path)
      .set('Authorization', `Bearer ${token}`)
      .set('x-vault-environment', 'development')
      .set('x-vault-tenant', '_shared');
  try {
    const desired = await call(
      'get',
      '/local/application-runtime/app/desired',
    ).expect(200);
    expect(JSON.stringify(desired.body)).not.toContain('FIRST_CANARY');
    const snapshot = await call(
      'post',
      '/local/application-runtime/app/snapshot',
    )
      .send({
        generation: desired.body.generation,
        digest: desired.body.digest,
      })
      .expect(200);
    expect(snapshot.body.resources[0].value).toBe('FIRST_CANARY');
    const registration = await call(
      'post',
      '/local/application-runtime/app/register',
    )
      .send({})
      .expect(200);
    await call('post', '/local/application-runtime/app/acknowledge')
      .send({
        ...registration.body,
        expiresAt: undefined,
        generation: desired.body.generation,
        digest: desired.body.digest,
        status: 'applied',
      })
      .expect(200);
    await call('get', '/local/applications').expect(403);
    await call('post', '/local/application-runtime/app/snapshot')
      .set('x-vault-tenant', 'other')
      .send({ generation: 1, digest: desired.body.digest })
      .expect(403);
    const { createApplicationRuntime } =
      await import('@kick-playr/local-key-vault/runtime-client');
    const runtime = createApplicationRuntime({
      application: 'app',
      scope,
      environment: {
        NODE_ENV: 'test',
        SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
        LOCAL_KEYVAULT_AUTH_JSON: JSON.stringify({
          schemaVersion: 1,
          grants: [{ ...scope, token }],
        }),
      },
      allowedMappings: ['DATABASE_URL'],
      requiredMappings: ['DATABASE_URL'],
      prepare: async (s) => ({ value: s.resources[0]!.value }),
      fetch: async (url, options) => {
        const method = options?.method === 'POST' ? 'post' : 'get';
        let q = request(app.getHttpServer())
          [method](new URL(String(url)).pathname)
          .set(options?.headers as Record<string, string>);
        if (options?.body) q = q.send(JSON.parse(String(options.body)));
        const result = await q;
        return Response.json(result.body, { status: result.status });
      },
    });
    try {
      await runtime.start();
      expect(await runtime.withValue((v) => v)).toBe('FIRST_CANARY');
      f.ns().secrets['arbitrary-database-name']!.push(
        newSecret({ value: 'HTTP_REFRESH_CANARY' }),
      );
      f.ns().generation++;
      await runtime.refresh();
      expect(await runtime.withValue((v) => v)).toBe('HTTP_REFRESH_CANARY');
      grant.enabled = false;
      await runtime.refresh();
      expect(runtime.status().state).toBe('blocked');
    } finally {
      runtime.close();
    }
    grant.enabled = false;
    await call('get', '/local/application-runtime/app/desired').expect(401);
  } finally {
    await app.close();
  }
});

async function clientFixture(options: Record<string, unknown> = {}) {
  const { createApplicationRuntime } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const f = fixture();
  const config = { ...options };
  if (typeof config.initial === 'function')
    config.initial = await config.initial(f);
  if (typeof config.baseline === 'function')
    config.baseline = await config.baseline(f);
  let httpStatus = 200;
  const calls: string[] = [];
  const disposed: string[] = [];
  const fetcher: typeof fetch = async (url, init) => {
    const action = new URL(String(url)).pathname.split('/').at(-1)!;
    calls.push(action);
    if (httpStatus !== 200)
      return Response.json(
        { error: { code: 'PRIVATE_CANARY' } },
        { status: httpStatus },
      );
    try {
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      const result =
        action === 'mode'
          ? await f.service.mode(scope, 'app')
          : action === 'in-use'
            ? await f.service.inUse(scope, 'app', body)
            : action === 'desired'
              ? await f.service.desired(scope, 'app')
              : action === 'snapshot'
                ? await f.service.snapshot(scope, 'app', body)
                : action === 'register'
                  ? await f.service.register(scope, 'app', 'caller')
                  : await f.service.acknowledge(scope, 'app', 'caller', body);
      return Response.json(result);
    } catch (e: any) {
      return Response.json(
        { error: { code: e.code ?? 'InternalError' } },
        { status: e.status ?? 500 },
      );
    }
  };
  const runtime = createApplicationRuntime({
    application: 'app',
    scope,
    environment: {
      NODE_ENV: 'test',
      SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
      LOCAL_KEYVAULT_AUTH_JSON: JSON.stringify({
        schemaVersion: 1,
        grants: [{ ...scope, token: 'client-test-token-aaaaaaaaaaaaaaaaaaa' }],
      }),
    },
    allowedMappings: ['DATABASE_URL', 'CLERK_ENCRYPTION_KEY'],
    requiredMappings: ['DATABASE_URL'],
    fetch: fetcher,
    prepare: async (snapshot: any) => {
      const value = snapshot.resources[0].value;
      return {
        value,
        dispose: async () => {
          disposed.push(value);
        },
      };
    },
    ...config,
  });
  return {
    ...f,
    runtime,
    calls,
    disposed,
    setStatus: (n: number) => {
      httpStatus = n;
    },
  };
}
it('refreshes prepared values atomically and drains a leased prior generation before disposal', async () => {
  const f = await clientFixture();
  await f.runtime.start();
  expect(await f.runtime.withValue((v) => v)).toBe('FIRST_CANARY');
  let release!: () => void;
  const held = f.runtime.withValue(async (v) => {
    await new Promise<void>((r) => {
      release = r;
    });
    return v;
  });
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'SECOND_CANARY' }),
  );
  f.ns().generation++;
  await f.runtime.refresh();
  expect(await f.runtime.withValue((v) => v)).toBe('SECOND_CANARY');
  expect(f.disposed).toEqual([]);
  release();
  expect(await held).toBe('FIRST_CANARY');
  expect(f.disposed).toEqual(['FIRST_CANARY']);
  expect(f.runtime.status().state).toBe('applied');
  f.runtime.close();
});
it('retains working values with a safe warning on outage but blocks admission after observed denial', async () => {
  const f = await clientFixture();
  await f.runtime.start();
  f.setStatus(503);
  await f.runtime.refresh();
  expect(await f.runtime.withValue((v) => v)).toBe('FIRST_CANARY');
  expect(f.runtime.status().state).toBe('warning');
  expect(JSON.stringify(f.runtime.status())).not.toContain('PRIVATE_CANARY');
  f.setStatus(401);
  await f.runtime.refresh();
  await expect(f.runtime.withValue((v) => v)).rejects.toThrow(
    'Application runtime unavailable',
  );
  expect(f.runtime.status().state).toBe('blocked');
  f.runtime.close();
});
it('known expiry blocks local admission during an outage and aborts retained operations', async () => {
  const { jest } = await import('@jest/globals');
  jest.useFakeTimers();
  try {
    const f = await clientFixture();
    const expiry = Math.floor(Date.now() / 1000) + 2;
    f.ns().secrets['arbitrary-database-name']![0]!.attributes.exp = expiry;
    await f.runtime.start();
    let retainedSignal: AbortSignal | undefined;
    const hold = f.runtime.withValue(async (_v, ctx) => {
      retainedSignal = ctx.signal;
      await new Promise<void>((r) =>
        ctx.signal.addEventListener('abort', () => r(), { once: true }),
      );
    });
    f.setStatus(503);
    await jest.advanceTimersByTimeAsync(2500);
    await hold;
    expect(retainedSignal?.aborted).toBe(true);
    await expect(f.runtime.withValue((v) => v)).rejects.toThrow(
      'Application runtime unavailable',
    );
    f.runtime.close();
  } finally {
    jest.useRealTimers();
  }
});
it('does not automatically switch changed encryption material without a migration adapter', async () => {
  const f = await clientFixture({ requiredMappings: ['CLERK_ENCRYPTION_KEY'] });
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'CLERK_ENCRYPTION_KEY';
  await f.runtime.start();
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'NEW_KEY_CANARY' }),
  );
  f.ns().generation++;
  await f.runtime.refresh();
  expect(f.runtime.status()).toMatchObject({
    state: 'warning',
    reason: 'MigrationRequired',
  });
  expect(await f.runtime.withValue((v) => v)).toBe('FIRST_CANARY');
  f.runtime.close();
});
it('polling automatically adopts an ordinary update within five seconds and serializes refreshes', async () => {
  const { jest } = await import('@jest/globals');
  jest.useFakeTimers();
  try {
    const f = await clientFixture();
    await f.runtime.start();
    f.ns().secrets['arbitrary-database-name']!.push(
      newSecret({ value: 'AUTO_CANARY' }),
    );
    f.ns().generation++;
    await jest.advanceTimersByTimeAsync(1000);
    expect(await f.runtime.withValue((v) => v)).toBe('AUTO_CANARY');
    f.runtime.close();
    const before = f.calls.length;
    await jest.advanceTimersByTimeAsync(10000);
    expect(f.calls).toHaveLength(before);
  } finally {
    jest.useRealTimers();
  }
});
it('reports a failed refresh as warning while retaining its last applied generation', async () => {
  const f = await clientFixture({
    prepare: async (snapshot: any) => {
      if (snapshot.resources[0].value === 'BROKEN_CANARY')
        throw Error('PRIVATE_ADAPTER_MESSAGE');
      return { value: snapshot.resources[0].value };
    },
  });
  await f.runtime.start();
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'BROKEN_CANARY' }),
  );
  f.ns().generation++;
  await f.runtime.refresh();
  expect((await f.service.status(scope, 'app')).state).toBe('warning');
  expect(await f.runtime.withValue((v) => v)).toBe('FIRST_CANARY');
  f.runtime.close();
});
it('a disabled in-use version stops new work even when a different newest candidate is active', async () => {
  const f = await clientFixture();
  await f.runtime.start();
  f.ns().secrets['arbitrary-database-name']![0]!.attributes.enabled = false;
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'NEW_CANARY' }),
  );
  f.ns().generation++;
  await f.runtime.refresh();
  expect(f.runtime.status().state).toBe('blocked');
  await expect(f.runtime.withValue((v) => v)).rejects.toThrow(
    'Application runtime unavailable',
  );
  f.runtime.close();
});
it('uses the explicit migration adapter for changed encryption keys rather than normal preparation', async () => {
  const migrations: string[] = [];
  const f = await clientFixture({
    requiredMappings: ['CLERK_ENCRYPTION_KEY'],
    prepareMigration: async (snapshot: any) => {
      migrations.push(snapshot.resources[0].version);
      return { value: 'MIGRATED' };
    },
  });
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'CLERK_ENCRYPTION_KEY';
  await f.runtime.start();
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'NEW_KEY_CANARY' }),
  );
  f.ns().generation++;
  await f.runtime.refresh();
  expect(migrations).toHaveLength(1);
  expect(await f.runtime.withValue((v) => v)).toBe('MIGRATED');
  f.runtime.close();
});
it('expired registrations cannot accept reports and new registration stays bounded', async () => {
  const { jest } = await import('@jest/globals');
  jest.useFakeTimers();
  try {
    const f = fixture();
    const old = await f.service.register(scope, 'app', 'caller');
    await jest.advanceTimersByTimeAsync(30001);
    const desired = await f.service.desired(scope, 'app');
    await expect(
      f.service.acknowledge(scope, 'app', 'caller', {
        instanceId: old.instanceId,
        proof: old.proof,
        generation: desired.generation,
        digest: desired.digest,
        status: 'applied',
      }),
    ).rejects.toThrow('Forbidden');
    expect((await f.service.status(scope, 'app')).state).toBe('offline');
    await f.service.register(scope, 'app', 'caller');
    expect(Object.keys(f.ns().runtimeInstances!)).toHaveLength(1);
  } finally {
    jest.useRealTimers();
  }
});
it('retains the key migration baseline across denial and credential recovery', async () => {
  const prepared: string[] = [];
  let managed = 0;
  const f = await clientFixture({
    requiredMappings: ['CLERK_ENCRYPTION_KEY'],
    prepareManagedCredential: async () => {
      managed++;
      return { value: 'BYPASS' };
    },
    prepare: async (snapshot: any) => {
      prepared.push(snapshot.resources[0].version);
      return { value: snapshot.resources[0].value };
    },
  });
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'CLERK_ENCRYPTION_KEY';
  await f.runtime.start();
  f.setStatus(403);
  await f.runtime.refresh();
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'CHANGED_WHILE_DENIED' }),
  );
  f.ns().generation++;
  f.setStatus(200);
  await f.runtime.refresh();
  expect(prepared).toHaveLength(1);
  expect(managed).toBe(0);
  expect(f.runtime.status()).toMatchObject({
    state: 'blocked',
    reason: 'MigrationRequired',
  });
  await expect(f.runtime.withValue((v) => v)).rejects.toThrow(
    'Application runtime unavailable',
  );
  f.runtime.close();
});
it('a late preparation cannot publish after close and its prepared client is disposed', async () => {
  let finish!: (value: any) => void;
  let disposed = 0;
  const f = await clientFixture({
    prepare: () =>
      new Promise((r) => {
        finish = r;
      }),
  });
  const start = f.runtime.start();
  for (let i = 0; i < 30 && !finish; i++)
    await new Promise((r) => setImmediate(r));
  expect(typeof finish).toBe('function');
  f.runtime.close();
  finish({
    value: 'LATE',
    dispose: () => {
      disposed++;
    },
  });
  await expect(start).rejects.toThrow('Application runtime unavailable');
  expect(disposed).toBe(1);
  expect(f.runtime.status().state).toBe('closed');
});
it('bounds retained client generations when operations do not release their leases', async () => {
  const f = await clientFixture();
  await f.runtime.start();
  const releases: (() => void)[] = [];
  const operations: Promise<unknown>[] = [];
  try {
    for (let i = 0; i < 33; i++) {
      operations.push(
        f.runtime.withValue(() => new Promise<void>((r) => releases.push(r))),
      );
      f.ns().secrets['arbitrary-database-name']!.push(
        newSecret({ value: 'GENERATION_' + i }),
      );
      f.ns().generation++;
      await f.runtime.refresh();
    }
    expect(f.runtime.status()).toMatchObject({
      state: 'warning',
      reason: 'DrainPending',
    });
  } finally {
    for (const release of releases) release();
    await Promise.all(operations);
    f.runtime.close();
  }
});
it('requires a complete, correctly named tenant key set rather than trusting role tags on arbitrary secrets', async () => {
  const { tenantKeySet } = await import('../src/tenant-key-tree.js');
  const tenantScope = { ...scope, tenant: 'club' };
  const f = fixture();
  f.ns().resourceAssociations = {};
  f.ns().secrets = {};
  const layout = tenantKeySet(tenantScope, 'workflow-local:club:key');
  const mappings = {
    wrapping: 'CLUB_WRAPPING_KEY_V1',
    index: 'CLUB_INDEX_KEY',
    control: 'CLUB_CONTROL_KEY',
  };
  for (const entry of layout.entries) {
    f.ns().secrets[entry.name] = [
      newSecret({
        value: 'KEY_BYTES',
        tags: {
          keySet: layout.reference,
          keyRole: entry.role,
          logicalPath: entry.logicalPath,
          envName: mappings[entry.role],
        },
      }),
    ];
    f.ns().resourceAssociations!['secrets/' + entry.name] = {
      envName: mappings[entry.role],
      memberships: { 'club-api': 'latest' },
    };
  }
  expect(
    (await f.service.desired(tenantScope, 'club-api')).resources,
  ).toHaveLength(3);
  const control = layout.entries.find((e) => e.role === 'control')!;
  delete f.ns().resourceAssociations!['secrets/' + control.name];
  await expect(f.service.desired(tenantScope, 'club-api')).rejects.toThrow(
    'ApplicationKeySetIncomplete',
  );
});
it('does not publish a candidate superseded while its dependency was being prepared', async () => {
  let finish!: (value: any) => void;
  let entered!: (value?: unknown) => void;
  const ready = new Promise((r) => {
    entered = r;
  });
  let disposed = 0;
  const f = await clientFixture({
    prepare: async (snapshot: any) => {
      const value = snapshot.resources[0].value;
      if (value === 'SECOND') {
        entered();
        return new Promise((r) => {
          finish = r;
        });
      }
      return { value };
    },
  });
  await f.runtime.start();
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'SECOND' }),
  );
  f.ns().generation++;
  const refresh = f.runtime.refresh();
  await ready;
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'THIRD' }),
  );
  f.ns().generation++;
  finish({
    value: 'SECOND',
    dispose: () => {
      disposed++;
    },
  });
  await refresh;
  expect(await f.runtime.withValue((v) => v)).toBe('FIRST_CANARY');
  expect(disposed).toBe(1);
  await f.runtime.refresh();
  expect(await f.runtime.withValue((v) => v)).toBe('THIRD');
  f.runtime.close();
});
it('fences traffic during migration and keeps it fenced after partial migration failure', async () => {
  let entered!: () => void, fail!: (e: Error) => void;
  const ready = new Promise<void>((r) => {
    entered = r;
  });
  const f = await clientFixture({
    requiredMappings: ['CLERK_ENCRYPTION_KEY'],
    prepareMigration: async () => {
      entered();
      return new Promise((_r, reject) => {
        fail = reject;
      });
    },
  });
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'CLERK_ENCRYPTION_KEY';
  await f.runtime.start();
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'NEW_KEY' }),
  );
  f.ns().generation++;
  const refresh = f.runtime.refresh();
  await ready;
  await expect(f.runtime.withValue((v) => v)).rejects.toThrow(
    'Application runtime unavailable',
  );
  fail(Error('partial data migration'));
  await refresh;
  expect(f.runtime.status()).toMatchObject({
    state: 'blocked',
    reason: 'MigrationFailed',
  });
  await expect(f.runtime.withValue((v) => v)).rejects.toThrow(
    'Application runtime unavailable',
  );
  f.runtime.close();
});
it('cannot clear a failed migration fence by pointing metadata back at the old key', async () => {
  let attempts = 0,
    managed = 0;
  const f = await clientFixture({
    requiredMappings: ['CLERK_ENCRYPTION_KEY'],
    prepareManagedCredential: async () => {
      managed++;
      return { value: 'BYPASS' };
    },
    prepareMigration: async () => {
      attempts++;
      throw Error('migration requires recovery');
    },
  });
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'CLERK_ENCRYPTION_KEY';
  const oldVersion = f.ns().secrets['arbitrary-database-name']![0]!.version;
  f.ns().resourceAssociations![
    'secrets/arbitrary-database-name'
  ]!.memberships.app = oldVersion;
  await f.runtime.start();
  f.ns().secrets['arbitrary-database-name']!.push(
    newSecret({ value: 'NEW_KEY' }),
  );
  f.ns().resourceAssociations![
    'secrets/arbitrary-database-name'
  ]!.memberships.app = 'latest';
  f.ns().generation++;
  await f.runtime.refresh();
  f.ns().resourceAssociations![
    'secrets/arbitrary-database-name'
  ]!.memberships.app = oldVersion;
  f.ns().generation++;
  await f.runtime.refresh();
  expect(attempts).toBe(2);
  expect(managed).toBe(0);
  expect(f.runtime.status()).toMatchObject({
    state: 'blocked',
    reason: 'MigrationFailed',
  });
  f.runtime.close();
});
it('all concurrent startup callers fail readiness when no initial snapshot can load', async () => {
  const f = await clientFixture();
  f.setStatus(503);
  const results = await Promise.allSettled([
    f.runtime.start(),
    f.runtime.start(),
  ]);
  expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected']);
  f.runtime.close();
});
it('bounds startup even when a transport ignores its abort signal', async () => {
  const { jest } = await import('@jest/globals');
  jest.useFakeTimers();
  try {
    const f = await clientFixture({
      fetch: async () => new Promise<Response>(() => {}),
    });
    let outcome = 'pending';
    const start = f.runtime.start().then(
      () => {
        outcome = 'resolved';
      },
      () => {
        outcome = 'rejected';
      },
    );
    await jest.advanceTimersByTimeAsync(5001);
    expect(outcome).toBe('rejected');
    await start;
    f.runtime.close();
  } finally {
    jest.useRealTimers();
  }
});
it('exposes the new runtime through native Node ESM named imports as well as require', async () => {
  const { execFileSync } = await import('node:child_process');
  const script =
    "import { createApplicationRuntime, parseApplicationDescriptor } from '@kick-playr/local-key-vault/runtime-client'; console.log(typeof createApplicationRuntime, typeof parseApplicationDescriptor)";
  expect(
    execFileSync(process.execPath, ['--input-type=module', '-e', script], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim(),
  ).toBe('function function');
});
it('switches an application to live mode only through explicit shared-scope activation and never downgrades on label edits', async () => {
  const { ApplicationsService } = await import('../src/applications.js');
  const f = fixture();
  expect(await f.service.mode(scope, 'app')).toMatchObject({ mode: 'legacy' });
  await expect(
    f.service.activate({ ...scope, tenant: 'club' }, 'app', {
      expectedRevision: 0,
    }),
  ).rejects.toThrow('SharedScopeRequired');
  await f.service.activate(scope, 'app', { expectedRevision: 0 });
  expect(await f.service.mode(scope, 'app')).toMatchObject({ mode: 'live' });
  const store = {
    read: async (_s: Scope, fn: any) => fn(f.ns()),
    transaction: async (_s: Scope, fn: any) => fn(f.ns()),
  };
  await new ApplicationsService(store as any).save(scope, 'app', {
    expectedRevision: 1,
    displayName: 'Renamed',
    description: '',
  });
  expect(await f.service.mode(scope, 'app')).toMatchObject({ mode: 'live' });
});
it('retains a seeded startup generation when the newest candidate is invalid', async () => {
  const f = await clientFixture({
    initial: async (base: any) => {
      const d = await base.service.desired(scope, 'app');
      const snapshot = await base.service.snapshot(scope, 'app', {
        generation: d.generation,
        digest: d.digest,
      });
      base
        .ns()
        .secrets['arbitrary-database-name'].push(
          newSecret({ value: 'BAD', attributes: { enabled: false } }),
        );
      base.ns().generation++;
      return {
        snapshot: JSON.parse(JSON.stringify(snapshot)),
        prepared: { value: 'STARTUP_VALUE' },
      };
    },
  });
  await f.runtime.start();
  expect(await f.runtime.withValue((v) => v)).toBe('STARTUP_VALUE');
  expect(f.runtime.status().state).toBe('warning');
  f.runtime.close();
});
it('reads explicit migration mode without loading secret values', async () => {
  const f = await clientFixture();
  expect(await f.runtime.mode()).toBe('legacy');
  await f.service.activate(scope, 'app', { expectedRevision: 0 });
  expect(await f.runtime.mode()).toBe('live');
  expect(f.calls).not.toContain('snapshot');
  f.runtime.close();
});
it('supports a code-owned finite mapping predicate for registered realm credential names', async () => {
  const f = await clientFixture({
    allowedMappings: (name: string) => name === 'DATABASE_URL',
  });
  await f.runtime.start();
  expect(await f.runtime.withValue((v) => v)).toBe('FIRST_CANARY');
  f.runtime.close();
});
it('converts legacy process pins into an immutable migration baseline and blocks a changed initial encryption key', async () => {
  const { applicationSnapshotFromLegacy, bindingDigest } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const { vaultName } = await import('../src/manifest.js');
  const f = await clientFixture({
    requiredMappings: ['CLERK_ENCRYPTION_KEY'],
    initial: async (base: any) => {
      const name = vaultName(scope, 'secret', 'request-encryption');
      const item = newSecret({ value: 'LEGACY_KEY' });
      base.ns().secrets = { [name]: [item] };
      base.ns().resourceAssociations = {
        ['secrets/' + name]: {
          envName: 'CLERK_ENCRYPTION_KEY',
          memberships: { app: 'latest' },
        },
      };
      const body = {
        schemaVersion: 1 as const,
        bindingRevision: 1,
        keySets: [],
        secrets: [
          {
            mapping: 'CLERK_ENCRYPTION_KEY',
            purpose: 'request-encryption',
            version: item.version,
          },
        ],
      };
      const legacy = {
        ...body,
        bindingDigest: bindingDigest(body),
        ...scope,
        generation: 1,
        loadedAt: Date.now(),
        secrets: [
          {
            ...body.secrets[0]!,
            value: 'LEGACY_KEY',
            attributes: item.attributes,
          },
        ],
      };
      const snapshot = applicationSnapshotFromLegacy('app', legacy);
      expect(snapshot.resources[0]!.name).toBe(name);
      expect(snapshot.resources[0]!.classification).toBe('encryption-key');
      expect(Object.isFrozen(snapshot.resources[0]!)).toBe(true);
      base.ns().secrets[name].push(newSecret({ value: 'CHANGED_KEY' }));
      base.ns().generation++;
      return { snapshot, prepared: { value: 'LEGACY_KEY' } };
    },
  });
  await f.runtime.start();
  expect(await f.runtime.withValue((v) => v)).toBe('LEGACY_KEY');
  expect(f.runtime.status().reason).toBe('MigrationRequired');
  f.runtime.close();
});
it('can recover from an expired retained startup version without discarding the encryption baseline or restarting', async () => {
  const { applicationSnapshotFromLegacy, bindingDigest } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const { vaultName } = await import('../src/manifest.js');
  const f = await clientFixture({
    initial: async (base: any) => {
      const purpose = 'database',
        name = vaultName(scope, 'secret', purpose),
        old = newSecret({
          value: 'EXPIRED',
          attributes: { exp: Math.floor(Date.now() / 1000) - 1 },
        });
      const fresh = newSecret({ value: 'FRESH' });
      base.ns().secrets = { [name]: [old, fresh] };
      base.ns().resourceAssociations = {
        ['secrets/' + name]: {
          envName: 'DATABASE_URL',
          memberships: { app: 'latest' },
        },
      };
      base.ns().generation++;
      const request = {
        schemaVersion: 1 as const,
        bindingRevision: 1,
        keySets: [],
        secrets: [{ mapping: 'DATABASE_URL', purpose, version: old.version }],
      };
      const snapshot = applicationSnapshotFromLegacy('app', {
        ...request,
        bindingDigest: bindingDigest(request),
        ...scope,
        generation: 1,
        loadedAt: Date.now() - 5000,
        secrets: [
          {
            ...request.secrets[0]!,
            value: 'EXPIRED',
            attributes: old.attributes,
          },
        ],
      });
      return { snapshot, prepared: { value: 'EXPIRED' } };
    },
  });
  await expect(f.runtime.start()).rejects.toThrow(
    'Application runtime unavailable',
  );
  await f.runtime.start();
  expect(await f.runtime.withValue((v) => v)).toBe('FRESH');
  f.runtime.close();
});
it('checks a metadata-only legacy baseline on cold startup without fetching obsolete secret values', async () => {
  const { applicationDescriptorFromLegacy, bindingDigest } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const { vaultName } = await import('../src/manifest.js');
  const f = await clientFixture({
    requiredMappings: ['CLERK_ENCRYPTION_KEY'],
    baseline: async (base: any) => {
      const purpose = 'clerk-encryption',
        name = vaultName(scope, 'secret', purpose),
        old = newSecret({ value: 'PRIVATE-OLD' }),
        fresh = newSecret({ value: 'PRIVATE-NEW' });
      base.ns().secrets = { [name]: [old, fresh] };
      base.ns().resourceAssociations = {
        ['secrets/' + name]: {
          envName: 'CLERK_ENCRYPTION_KEY',
          memberships: { app: 'latest' },
        },
      };
      base.ns().generation++;
      const request = {
        schemaVersion: 1 as const,
        bindingRevision: 1,
        keySets: [],
        secrets: [
          { mapping: 'CLERK_ENCRYPTION_KEY', purpose, version: old.version },
        ],
      };
      const baseline = applicationDescriptorFromLegacy('app', scope, {
        ...request,
        bindingDigest: bindingDigest(request),
      });
      expect(JSON.stringify(baseline)).not.toContain('PRIVATE-OLD');
      return baseline;
    },
  });
  await expect(f.runtime.start()).rejects.toThrow(
    'Application runtime unavailable',
  );
  expect(f.runtime.status()).toMatchObject({
    state: 'blocked',
    reason: 'MigrationRequired',
  });
  await expect(f.runtime.withValue((v) => v)).rejects.toThrow();
  f.runtime.close();
});
it('treats manager invitation cookie keys as encryption material in live and legacy baselines', async () => {
  const f = fixture();
  f.ns().resourceAssociations!['secrets/arbitrary-database-name']!.envName =
    'MANAGER_INVITATION_FLOW_KEY';
  expect(
    (await f.service.desired(scope, 'app')).resources[0]!.classification,
  ).toBe('encryption-key');
  const { applicationDescriptorFromLegacy, bindingDigest } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const input = {
    schemaVersion: 1 as const,
    bindingRevision: 1,
    keySets: [],
    secrets: [
      {
        mapping: 'MANAGER_INVITATION_FLOW_KEY',
        purpose: 'invitation-flow',
        version: 'a'.repeat(32),
      },
    ],
  };
  expect(
    applicationDescriptorFromLegacy('app', scope, {
      ...input,
      bindingDigest: bindingDigest(input),
    }).resources[0]!.classification,
  ).toBe('encryption-key');
});
it('converts tenant legacy key pins into canonical v2 names without reading private values', async () => {
  const { applicationDescriptorFromTenantLegacy, bindingDigest } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const selected = { environment: 'development', tenant: 'club' };
  const request = {
    schemaVersion: 1 as const,
    bindingRevision: 3,
    keySets: [
      {
        reference: 'workflow-local:club:key',
        mappings: {
          wrapping: 'CLUB_WRAPPING_KEY_V1',
          index: 'CLUB_INDEX_KEY',
          control: 'CLUB_CONTROL_KEY',
        },
        currentWrappingVersion: 'v1',
        wrappingVersions: [{ keyVersion: 'v1', vaultVersion: 'a'.repeat(32) }],
        indexVersion: 'b'.repeat(32),
        controlVersion: 'c'.repeat(32),
      },
    ],
    secrets: [],
  };
  const descriptor = applicationDescriptorFromTenantLegacy(
    'explorer-api',
    selected,
    { ...request, bindingDigest: bindingDigest(request) },
  );
  expect(descriptor.resources).toHaveLength(3);
  expect(
    descriptor.resources.every((r) => r.classification === 'encryption-key'),
  ).toBe(true);
  expect(
    descriptor.resources.find((r) => r.mapping === 'CLUB_WRAPPING_KEY_V1')!
      .name,
  ).toMatch(/^tk-wrapping-[a-f0-9]{64}$/);
});
it('admits only reviewed ordinary tenant Mongo and Clerk slots alongside private runtime credentials', async () => {
  const f = fixture();
  f.ns().applications = {
    'club-api': { displayName: 'Club', description: '' },
    'explorer-api': { displayName: 'Explorer', description: '' },
  };
  for (const application of ['club-api', 'explorer-api'])
    for (const mapping of [
      'MONGODB_URI',
      'CLERK_SECRET_KEY',
      'RUNTIME_CREDENTIAL_ABCDEF1234567890ABCDEF12',
    ]) {
      f.ns().resourceAssociations = {
        'secrets/arbitrary-database-name': {
          envName: mapping,
          memberships: { [application]: 'latest' },
        },
      };
      const d = await f.service.desired(
        { ...scope, tenant: 'club' },
        application,
      );
      expect(d.resources[0]!.classification).toBe(
        application === 'club-api' && mapping.startsWith('RUNTIME_CREDENTIAL_')
          ? 'managed-credential'
          : 'secret',
      );
    }
});
it('retains distinct wrapping aliases for one immutable key when only index/control rotates', async () => {
  const { bindingDigest, parseSnapshotRequest } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const k = {
    reference: 'workflow-local:club:key',
    mappings: {
      wrapping: 'CLUB_WRAPPING_KEY_V1',
      index: 'CLUB_INDEX_KEY',
      control: 'CLUB_CONTROL_KEY',
    },
    currentWrappingVersion: 'a'.repeat(32),
    wrappingVersions: [
      { keyVersion: 'v1', vaultVersion: 'a'.repeat(32) },
      { keyVersion: 'a'.repeat(32), vaultVersion: 'a'.repeat(32) },
    ],
    indexVersion: 'b'.repeat(32),
    controlVersion: 'c'.repeat(32),
  };
  const body = {
    schemaVersion: 1 as const,
    bindingRevision: 4,
    keySets: [k],
    secrets: [],
  };
  const parsed = parseSnapshotRequest({
    ...body,
    bindingDigest: bindingDigest(body),
  });
  expect(parsed.keySets[0]!.wrappingVersions).toHaveLength(2);
  const duplicate = {
    ...body,
    keySets: [
      {
        ...k,
        wrappingVersions: [k.wrappingVersions[0]!, k.wrappingVersions[0]!],
      },
    ],
  };
  expect(() => bindingDigest(duplicate)).toThrow();
});
it('verified managed-only refresh retains valid prior credentials during a transient broker outage', async () => {
  const { createApplicationRuntime } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const { createHash } = await import('node:crypto');
  let generation = 1,
    version = 'a'.repeat(32),
    fail = false,
    managedCalls = 0;
  const selected = { environment: 'development', tenant: 'club' },
    canonical = (x: any) =>
      JSON.stringify(x, (_k, v) =>
        v && typeof v === 'object' && !Array.isArray(v)
          ? Object.fromEntries(
              Object.entries(v).sort(([a], [b]) =>
                a < b ? -1 : a > b ? 1 : 0,
              ),
            )
          : v,
      );
  const descriptor = () => {
    const identity = {
      schemaVersion: 2,
      application: 'club-api',
      scope: selected,
      resources: [
        {
          kind: 'secrets',
          name: 'credential',
          mapping: 'RUNTIME_CREDENTIAL_ABCDEF1234567890ABCDEF12',
          policy: 'latest',
          version,
          classification: 'managed-credential',
          attributes: {
            enabled: true,
            created: 1,
            updated: 1,
            recoveryLevel: 'Purgeable',
          },
        },
      ],
    };
    return {
      ...identity,
      generation,
      digest: createHash('sha256').update(canonical(identity)).digest('hex'),
    };
  };
  const runtime = createApplicationRuntime({
    application: 'club-api',
    scope: selected,
    environment: {
      NODE_ENV: 'test',
      SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
      LOCAL_KEYVAULT_AUTH_JSON: JSON.stringify({
        schemaVersion: 1,
        grants: [
          { ...selected, token: 'test-token-aaaaaaaaaaaaaaaaaaaaaaaaaaa' },
        ],
      }),
    },
    allowedMappings: ['RUNTIME_CREDENTIAL_ABCDEF1234567890ABCDEF12'],
    prepare: async () => ({ value: 'OLD' }),
    prepareManagedCredential: async () => {
      managedCalls++;
      if (fail) throw Error('PRIVATE_BROKER_VALUE');
      return { value: 'NEW' };
    },
    fetch: async (input: string | URL | Request) => {
      const action = new URL(String(input)).pathname.split('/').at(-1);
      const d = descriptor();
      if (action === 'snapshot')
        return Response.json({
          ...d,
          resources: d.resources.map((r) => ({ ...r, value: 'PRIVATE_TOKEN' })),
        });
      if (action === 'register')
        return Response.json({
          instanceId: 'a'.repeat(36),
          proof: 'a'.repeat(43),
          expiresAt: Date.now() + 30000,
        });
      if (action === 'acknowledge')
        return Response.json({ accepted: true, expiresAt: Date.now() + 30000 });
      if (action === 'in-use') return Response.json({ valid: true });
      return Response.json(d);
    },
  } as any);
  try {
    await runtime.start();
    version = 'b'.repeat(32);
    generation++;
    fail = true;
    await runtime.refresh();
    expect(managedCalls).toBe(1);
    expect(await runtime.withValue((v: any) => v)).toBe('OLD');
    expect(runtime.status().state).toBe('warning');
    fail = false;
    await runtime.refresh();
    expect(await runtime.withValue((v: any) => v)).toBe('NEW');
    expect(runtime.status().state).toBe('applied');
  } finally {
    runtime.close();
  }
});
