const { test } = require("node:test"),
  assert = require("node:assert/strict");
const {
  createIntegrationRuntime,
} = require("../../runtime-client/integration-runtime.cjs");
const clone = (v) => (v === undefined ? undefined : structuredClone(v));
function fixture() {
  const rows = new Map();
  const match = (r, q) => r && Object.entries(q).every(([k, v]) => r[k] === v);
  const db = {
    databaseName: "fcrww-kick-playr",
    client: {
      startSession: () => ({
        withTransaction: async (fn) => {
          const backup = clone(rows);
          try {
            return await fn();
          } catch (e) {
            rows.clear();
            for (const [k, v] of backup) rows.set(k, v);
            throw e;
          }
        },
        endSession: async () => {},
      }),
    },
    collection: (name) => ({
      findOne: async (q, o) => {
        const r = clone(rows.get(name + q._id));
        if (!match(r, q)) return null;
        if (o?.projection?.value === 0) delete r.value;
        return r;
      },
      insertOne: async (r) => {
        const k = name + r._id;
        if (rows.has(k)) throw Error("duplicate");
        rows.set(k, clone(r));
      },
      replaceOne: async (q, r) => {
        const k = name + q._id;
        if (!match(rows.get(k), q)) return { matchedCount: 0 };
        rows.set(k, clone(r));
        return { matchedCount: 1 };
      },
      updateOne: async (q, u) => {
        const k = name + q._id,
          r = rows.get(k);
        if (!match(r, q)) return { matchedCount: 0 };
        Object.assign(r, clone(u.$set ?? {}));
        for (const [key, n] of Object.entries(u.$inc ?? {}))
          r[key] = (r[key] ?? 0) + n;
        return { matchedCount: 1 };
      },
    }),
  };
  let allowed = true;
  const runtime = createIntegrationRuntime({
    db,
    tenantId: "fcrww",
    environment: "development",
    integrationId: "bexio",
    staticVersion: "s1",
    accountReference: "account",
    keys: new Map([["k1", Buffer.alloc(32, 7)]]),
    activeKeyVersion: "k1",
    beforeWrite: async () => {
      if (!allowed) throw Error("stale");
    },
  });
  return { runtime, rows, invalidate: () => (allowed = false) };
}
const metadata = {
  schema: 1,
  connectionId: "bexio",
  provider: "bexio",
  purpose: "oauth",
  securityEpoch: 1,
  capabilities: ["oauth:refresh"],
};
const token = {
  accessToken: "PRIVATE-A",
  refreshToken: "PRIVATE-R",
  expiresAt: Date.now() + 60000,
};
test("native lifecycle uses same encrypted authority and metadata-only inspection", async () => {
  const f = fixture();
  await f.runtime.reconnect(token, "account", 0, {
    expectedRevision: 0,
    metadata,
  });
  const row = await f.runtime.inspect();
  assert.equal(row.metadata.connectionId, "bexio");
  assert.equal("value" in row, false);
  assert.equal(JSON.stringify([...f.rows.values()]).includes("PRIVATE"), false);
  await f.runtime.setLifecycle(1, 1, "suspended", {
    ...metadata,
    securityEpoch: 2,
  });
  await assert.rejects(f.runtime.token());
  await f.runtime.setLifecycle(2, 2, "active", {
    ...metadata,
    securityEpoch: 3,
  });
  assert.deepEqual(await f.runtime.token(), token);
});
test("stale reconnect revision cannot overwrite refreshed authority", async () => {
  const f = fixture();
  await f.runtime.reconnect(token, "account", 0, { metadata });
  await assert.rejects(
    f.runtime.reconnect(token, "account", 1, { expectedRevision: 0, metadata }),
    /authority-conflict/,
  );
});
test("lifecycle mutation and reconnect obey transaction fence", async () => {
  const f = fixture();
  await f.runtime.reconnect(token, "account", 0, { metadata });
  f.invalidate();
  await assert.rejects(f.runtime.setLifecycle(1, 1, "suspended", metadata));
  assert.equal((await f.runtime.inspect()).revision, 1);
});
test("missing migrated metadata is not upgraded to capabilities automatically", async () => {
  const f = fixture();
  await f.runtime.reconnect(token, "account", 0);
  assert.equal((await f.runtime.inspect()).metadata, undefined);
});
test("unknown lifecycle metadata cannot persist static clients", async () => {
  const f = fixture();
  await assert.rejects(
    f.runtime.reconnect(token, "account", 0, {
      metadata: { ...metadata, clientSecret: "PRIVATE" },
    }),
  );
  assert.equal(await f.runtime.inspect(), null);
});
test("revocation honors the same transactional authority fence", async () => {
  const f = fixture();
  await f.runtime.reconnect(token, "account", 0, { metadata });
  f.invalidate();
  await assert.rejects(f.runtime.revoke(1));
  assert.equal((await f.runtime.inspect()).status, "active");
});
