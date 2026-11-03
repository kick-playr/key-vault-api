import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const plan = {
  scope: { environment: 'development', tenant: 'club' },
  expectedRevision: 3,
  fromDigest: 'a'.repeat(64),
  toDigest: 'b'.repeat(64),
  from: {
    wrapping: { name: 'wrap', version: 'a'.repeat(32) },
    index: { name: 'index', version: 'b'.repeat(32) },
    control: { name: 'control', version: 'c'.repeat(32) },
  },
  to: {
    wrapping: { name: 'wrap', version: 'd'.repeat(32) },
    index: { name: 'index', version: 'e'.repeat(32) },
    control: { name: 'control', version: 'f'.repeat(32) },
  },
};
const keyDigest = (scope: any, keys: any) =>
  require('node:crypto')
    .createHash('sha256')
    .update(
      JSON.stringify([
        scope,
        ['wrapping', 'index', 'control'].map((role) => [
          role,
          keys[role].name,
          keys[role].version,
        ]),
      ]),
    )
    .digest('hex');
plan.fromDigest = keyDigest(plan.scope, plan.from);
plan.toDigest = keyDigest(plan.scope, plan.to);
function fixture() {
  let job: any;
  let state = 'active',
    fail = false;
  const migrated = new Set<string>(),
    steps: string[] = [];
  const store = {
    begin: async (p: any) => {
      job ??= {
        id: 'operation',
        plan: p,
        stage: 'pending',
        unit: 0,
        completed: 0,
        checkpoint: null,
      };
      state = 'in-rotation';
      return structuredClone(job);
    },
    acquire: async (_id: any, owner: any) => {
      job.owner = owner;
      job.epoch = (job.epoch ?? 0) + 1;
      return structuredClone(job);
    },
    assertLease: async (l: any) => {
      if (job.owner !== l.owner || job.epoch !== l.epoch) throw Error('stale');
    },
    renew: async () => {},
    checkpoint: async (l: any, patch: any) => {
      await store.assertLease(l);
      Object.assign(job, patch);
      return structuredClone(job);
    },
    complete: async (l: any, activate: any) => {
      await store.assertLease(l);
      const r = await activate({});
      job.stage = 'completed';
      job.activatedRevision = r;
      state = 'active';
      return structuredClone(job);
    },
    fail: async (l: any) => {
      await store.assertLease(l);
      job.stage = 'failed';
    },
  };
  const worker = {
    inventory: async () => ({
      units: ['records', 'indexes', 'control'],
      roles: ['wrapping', 'index', 'control'],
    }),
    migrateBatch: async (_p: any, c: any) => {
      await c.assertLease();
      steps.push(c.unit);
      if (fail && c.unit === 'indexes') throw Error('PRIVATE_VALUE');
      migrated.add(c.unit);
      return { checkpoint: null, completed: 1, done: true };
    },
    verify: async () => {
      if (migrated.size !== 3) throw Error('incomplete');
    },
    activate: async () => 4,
    verifyActivation: async () => {},
  };
  return {
    store,
    worker,
    state: () => state,
    job: () => job,
    setFail: (v: boolean) => {
      fail = v;
    },
    steps,
  };
}
it('durably fences the tenant, checkpoints all three roles and activates only after verification', async () => {
  const {
    createTenantRotationCoordinator,
  } = require('../runtime-client/tenant-rotation.cjs');
  const f = fixture();
  const coordinator = createTenantRotationCoordinator({
    store: f.store,
    worker: f.worker,
  });
  const result = await coordinator.run(plan);
  expect(result.stage).toBe('completed');
  expect(result.activatedRevision).toBe(4);
  expect(f.state()).toBe('active');
  expect(f.steps).toEqual(['records', 'indexes', 'control']);
});
it('keeps partial failure unavailable and resumes checkpoints after coordinator restart', async () => {
  const {
    createTenantRotationCoordinator,
  } = require('../runtime-client/tenant-rotation.cjs');
  const f = fixture();
  f.setFail(true);
  await expect(
    createTenantRotationCoordinator({ store: f.store, worker: f.worker }).run(
      plan,
    ),
  ).rejects.toThrow('Tenant key rotation unavailable');
  expect(f.state()).toBe('in-rotation');
  expect(f.job().unit).toBe(1);
  f.setFail(false);
  await createTenantRotationCoordinator({
    store: f.store,
    worker: f.worker,
  }).run(plan);
  expect(f.steps.filter((x) => x === 'records')).toHaveLength(1);
  expect(f.state()).toBe('active');
});
it('refuses incomplete role inventory and never exposes worker exception payloads', async () => {
  const {
    createTenantRotationCoordinator,
  } = require('../runtime-client/tenant-rotation.cjs');
  const f = fixture();
  f.worker.inventory = async () =>
    ({ units: ['records'], roles: ['wrapping'] }) as any;
  await expect(
    createTenantRotationCoordinator({ store: f.store, worker: f.worker }).run(
      plan,
    ),
  ).rejects.toThrow('Tenant key rotation unavailable');
  expect(f.state()).toBe('in-rotation');
  expect(f.steps).toHaveLength(0);
});
it('activation must verify the committed control references before reopening availability', async () => {
  const {
    createTenantRotationCoordinator,
  } = require('../runtime-client/tenant-rotation.cjs');
  const f = fixture();
  (f.worker as any).verifyActivation = async () => {
    throw Error('wrong references');
  };
  await expect(
    createTenantRotationCoordinator({ store: f.store, worker: f.worker }).run(
      plan,
    ),
  ).rejects.toThrow('Tenant key rotation unavailable');
  expect(f.state()).toBe('in-rotation');
});
it('waits for authenticated ephemeral expiry without inventing progress or reopening early', async () => {
  const {
    createTenantRotationCoordinator,
  } = require('../runtime-client/tenant-rotation.cjs');
  const f = fixture();
  let waited = false;
  const next = f.worker.migrateBatch;
  f.worker.migrateBatch = async (p: any, c: any) => {
    if (!waited) {
      waited = true;
      return {
        checkpoint: null,
        completed: 0,
        done: false,
        waitUntil: Date.now() + 15,
      };
    }
    return next(p, c);
  };
  const progress: any[] = [];
  await createTenantRotationCoordinator({
    store: f.store,
    worker: f.worker,
  }).run(plan, { onProgress: (s: any) => progress.push(s) });
  expect(
    progress.some((p) => p.stage === 'waiting-expiry' && p.completed === 0),
  ).toBe(true);
  expect(progress[0].to.wrapping.version).toBe(plan.to.wrapping.version);
  expect(Object.isFrozen(progress[0].scope)).toBe(true);
});
function mongoFixture() {
  let now = 10000;
  let tables: Record<string, any[]> = {
    tenantDefinitions: [
      {
        id: 'club',
        environment: 'development',
        configRevision: 3,
        status: 'suspended',
      },
    ],
    tenantHostBindings: [
      { tenantId: 'club', environment: 'development', configRevision: 3 },
    ],
    tenantRuntimeAuthorities: [
      { tenantId: 'club', environment: 'development', configRevision: 3 },
    ],
  };
  const clone = (v: any) => JSON.parse(JSON.stringify(v));
  const match = (row: any, query: any) =>
    Object.entries(query).every(([key, wanted]: any) =>
      wanted && typeof wanted === 'object'
        ? wanted.$gt !== undefined
          ? row[key] > wanted.$gt
          : wanted.$nin
            ? !wanted.$nin.includes(row[key])
            : false
        : row[key] === wanted,
    );
  const collection = (name: string) => {
    const rows = () => (tables[name] ??= []);
    const patch = (row: any, update: any) => {
      Object.assign(row, update.$set ?? {});
      for (const [key, n] of Object.entries(update.$inc ?? {}))
        row[key] = (row[key] ?? 0) + (n as number);
      for (const key of Object.keys(update.$unset ?? {})) delete row[key];
    };
    return {
      findOne: async (q: any) => clone(rows().find((r) => match(r, q)) ?? null),
      find: (q: any) => ({
        toArray: async () => clone(rows().filter((r) => match(r, q))),
      }),
      insertOne: async (row: any) => {
        if (rows().some((r) => r._id === row._id)) throw Error('duplicate');
        rows().push(clone(row));
      },
      updateOne: async (q: any, u: any, o: any = {}) => {
        const row = rows().find((r) => match(r, q));
        if (row) {
          patch(row, u);
          return { matchedCount: 1, modifiedCount: 1 };
        }
        if (o.upsert) {
          rows().push(clone({ ...q, ...u.$setOnInsert }));
          return { matchedCount: 0, modifiedCount: 0 };
        }
        return { matchedCount: 0, modifiedCount: 0 };
      },
      replaceOne: async (q: any, u: any) => {
        const i = rows().findIndex((r) => match(r, q));
        if (i < 0) return { modifiedCount: 0 };
        rows()[i] = clone(u);
        return { modifiedCount: 1 };
      },
      findOneAndUpdate: async (q: any, u: any) => {
        const row = rows().find((r) => match(r, q));
        if (!row) return null;
        patch(row, u);
        return clone(row);
      },
    };
  };
  const client = {
    db: () => ({ collection }),
    startSession: () => ({
      endSession: async () => {},
      withTransaction: async (work: any) => {
        const before = clone(tables);
        try {
          return await work();
        } catch (e) {
          tables = before;
          throw e;
        }
      },
    }),
  };
  return {
    client,
    now: () => now,
    advance: () => {
      now += 4000;
    },
    rows: (name: string) => (tables[name] ??= []),
    collection,
  };
}
it('native store atomically restores the original suspended state and exposes only verified safe metadata', async () => {
  const {
    createTenantRotationCoordinator,
    createMongoTenantRotationStore,
  } = require('../runtime-client/tenant-rotation.cjs');
  const m = mongoFixture(),
    f = fixture();
  f.worker.activate = async () => {
    for (const name of [
      'tenantDefinitions',
      'tenantHostBindings',
      'tenantRuntimeAuthorities',
    ])
      await m
        .collection(name)
        .updateOne(
          { environment: 'development' },
          { $set: { configRevision: 4 } },
        );
    return 4;
  };
  const store = createMongoTenantRotationStore({
    client: m.client,
    database: 'control',
    clock: m.now,
  });
  await createTenantRotationCoordinator({ store, worker: f.worker }).run(plan);
  expect(m.rows('tenantDefinitions')[0]).toMatchObject({
    status: 'suspended',
    configRevision: 4,
  });
  const status = await store.status(plan.scope);
  expect(status).toMatchObject({
    stage: 'completed',
    activatedRevision: 4,
    to: plan.to,
  });
  expect(status.owner).toBeUndefined();
  expect(status.checkpoint).toBeUndefined();
});
it('native activation rolls back all control writes when host/authority revisions do not match', async () => {
  const {
    createTenantRotationCoordinator,
    createMongoTenantRotationStore,
  } = require('../runtime-client/tenant-rotation.cjs');
  const m = mongoFixture(),
    f = fixture();
  f.worker.activate = async () => {
    await m
      .collection('tenantDefinitions')
      .updateOne(
        { environment: 'development' },
        { $set: { configRevision: 4 } },
      );
    return 4;
  };
  const store = createMongoTenantRotationStore({
    client: m.client,
    database: 'control',
    clock: m.now,
  });
  await expect(
    createTenantRotationCoordinator({ store, worker: f.worker }).run(plan),
  ).rejects.toThrow('Tenant key rotation unavailable');
  expect(m.rows('tenantDefinitions')[0]).toMatchObject({
    status: 'in-rotation',
    configRevision: 3,
  });
  expect((await store.status(plan.scope)).stage).toBe('failed');
});
it('native leases reject stale workers after takeover and preserve independent tenant scopes', async () => {
  const {
    createMongoTenantRotationStore,
  } = require('../runtime-client/tenant-rotation.cjs');
  const m = mongoFixture();
  const store = createMongoTenantRotationStore({
    client: m.client,
    database: 'control',
    clock: m.now,
  });
  const job = await store.begin(plan),
    first = await store.acquire(job.id, 'first', 3000);
  m.advance();
  const second = await store.acquire(job.id, 'second', 3000);
  await expect(
    store.checkpoint(
      { id: job.id, owner: 'first', epoch: first.epoch },
      { stage: 'migrating', unit: 1 },
    ),
  ).rejects.toThrow();
  await store.assertLease({ id: job.id, owner: 'second', epoch: second.epoch });
  expect(
    await store.status({ environment: 'development', tenant: 'other' }),
  ).toBeNull();
});
it('native expiry waits persist and continue without releasing the tenant gate', async () => {
  const {
    createTenantRotationCoordinator,
    createMongoTenantRotationStore,
  } = require('../runtime-client/tenant-rotation.cjs');
  const m = mongoFixture(),
    f = fixture();
  let waiting = false;
  const migrate = f.worker.migrateBatch;
  f.worker.migrateBatch = async (p: any, c: any) => {
    if (!waiting) {
      waiting = true;
      return {
        checkpoint: null,
        completed: 0,
        done: false,
        waitUntil: Date.now() + 10,
      };
    }
    return migrate(p, c);
  };
  f.worker.activate = async () => {
    for (const name of [
      'tenantDefinitions',
      'tenantHostBindings',
      'tenantRuntimeAuthorities',
    ])
      await m
        .collection(name)
        .updateOne(
          { environment: 'development' },
          { $set: { configRevision: 4 } },
        );
    return 4;
  };
  const store = createMongoTenantRotationStore({
    client: m.client,
    database: 'control',
    clock: m.now,
  });
  await createTenantRotationCoordinator({ store, worker: f.worker }).run(plan);
  expect((await store.status(plan.scope)).stage).toBe('completed');
});
it('native write fences roll back batch data if the lease expires before commit', async () => {
  const {
    createMongoTenantRotationStore,
  } = require('../runtime-client/tenant-rotation.cjs');
  const m = mongoFixture(),
    store = createMongoTenantRotationStore({
      client: m.client,
      database: 'control',
      clock: m.now,
    });
  const job = await store.begin(plan),
    owner = await store.acquire(job.id, 'owner', 3000);
  await expect(
    store.withLease(
      { id: job.id, owner: 'owner', epoch: owner.epoch },
      async () => {
        await m
          .collection('tenantDefinitions')
          .updateOne(
            { id: 'club' },
            { $set: { sentinel: 'SHOULD_ROLL_BACK' } },
          );
        m.advance();
      },
    ),
  ).rejects.toThrow();
  expect(m.rows('tenantDefinitions')[0].sentinel).toBeUndefined();
});
it('binds rotation proof digests to the exact three key versions and namespace', () => {
  const {
    rotationKeyDigest,
  } = require('../runtime-client/tenant-rotation.cjs');
  expect(rotationKeyDigest(plan.scope, plan.to)).not.toBe(
    rotationKeyDigest({ ...plan.scope, tenant: 'another' }, plan.to),
  );
  expect(rotationKeyDigest(plan.scope, plan.to)).not.toBe(
    rotationKeyDigest(plan.scope, plan.from),
  );
});
it('accepts an established database identity in the durable plan but rejects malformed dataset metadata',()=>{const{validateRotationPlan}=require('../runtime-client/tenant-rotation.cjs');const dataset={database:'club_data',cluster:'c'.repeat(64)};expect(validateRotationPlan({...plan,dataset}).dataset).toEqual(dataset);expect(()=>validateRotationPlan({...plan,dataset:{database:'admin',cluster:'c'.repeat(64)}})).toThrow();});
it('timestamps expiry barriers after the primary gate wins any pre-existing writer transaction',async()=>{const{createMongoTenantRotationStore}=require('../runtime-client/tenant-rotation.cjs');const m=mongoFixture();const client={...m.client,db:()=>({collection:(name:string)=>{const original=m.collection(name);return name==='tenantDefinitions'?{...original,updateOne:async(...args:Parameters<typeof original.updateOne>)=>{m.advance();return original.updateOne(...args);}}:original;}})};const store=createMongoTenantRotationStore({client,database:'control',clock:m.now});const job=await store.begin(plan);expect(job.createdAt).toBe(m.now());expect(m.rows('tenantDefinitions')[0].status).toBe('in-rotation');});
