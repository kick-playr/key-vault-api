import { bindingDigest } from "@kick-playr/local-key-vault/runtime-client";
import { OAuthCredentialService } from "../src/oauth-credentials.js";
import { emptyNamespace } from "../src/types.js";
import { newSecret } from "../src/vault.js";
import { vaultName } from "../src/manifest.js";
import { auditOperation } from "../src/audit.js";
const scope = { environment: "development", tenant: "club" };
const mapping = "RUNTIME_CREDENTIAL_BEXIO";
function fixture() {
  let ns = emptyNamespace();
  const value = {
    clientId: "client",
    clientSecret: "secret",
    accessToken: "old",
    refreshToken: "refresh",
    expiresAt: 1,
  };
  const item = newSecret({
    value: JSON.stringify(value),
    tags: { purpose: "bexio", envName: mapping },
  });
  ns.secrets[vaultName(scope, "secret", "bexio")] = [item];
  const req = {
    schemaVersion: 1 as const,
    bindingRevision: 4,
    keySets: [],
    secrets: [{ mapping, purpose: "bexio", version: item.version }],
  };
  const request = { ...req, bindingDigest: bindingDigest(req) };
  ns.runtimeManifests = {
    "club-api": {
      currentRevision: 4,
      versions: {
        "4": {
          schemaVersion: 1,
          application: "club-api",
          scope,
          request,
          tenants: [],
        },
      },
    },
  };
  const service = new OAuthCredentialService({
    read: async (_: unknown, fn: any) => structuredClone(fn(ns)),
    transaction: async (_: unknown, fn: any) => {
      const copy = JSON.parse(JSON.stringify(ns));
      const out = fn(copy);
      ns = copy;
      return structuredClone(out);
    },
  } as any);
  const identity = {
    application: "club-api",
    mapping,
    provider: "bexio",
    bindingRevision: 4,
    bindingDigest: request.bindingDigest,
  };
  const claim = {
    ...identity,
    operationId: "12345678-1234-4123-8123-123456789abc",
    expectedVersion: item.version,
  };
  return { service, identity, claim, value, item, ns: () => ns };
}
it("reserves once, preserves pinned history and commits idempotently", async () => {
  const f = fixture();
  await f.service.enroll(scope, {
    application: "club-api",
    mapping,
    provider: "bexio",
  });
  await f.service.begin(scope, f.claim);
  await expect(f.service.begin(scope, f.claim)).rejects.toThrow();
  const value = JSON.stringify({
    ...f.value,
    accessToken: "new",
    refreshToken: "new-refresh",
    expiresAt: Date.now() + 60000,
  });
  const result = await f.service.commit(scope, { ...f.claim, value });
  expect(result.version).not.toBe(f.item.version);
  expect(await f.service.commit(scope, { ...f.claim, value })).toEqual(result);
  expect(
    await f.service.read(scope, { ...f.identity, version: f.item.version }),
  ).toEqual({ version: f.item.version, value: f.item.value });
  await expect(
    f.service.commit(scope, {
      ...f.claim,
      value: JSON.stringify({ ...f.value, expiresAt: Date.now() + 60000 }),
    }),
  ).rejects.toThrow();
});
it("rejects unenrolled, invalid identities, immutable changes and foreign versions", async () => {
  const f = fixture();
  await expect(f.service.begin(scope, f.claim)).rejects.toThrow();
  await f.service.enroll(scope, {
    application: "club-api",
    mapping,
    provider: "bexio",
  });
  await f.service.begin(scope, f.claim);
  await expect(
    f.service.commit(scope, {
      ...f.claim,
      value: JSON.stringify({
        ...f.value,
        clientId: "changed",
        expiresAt: Date.now() + 60000,
      }),
    }),
  ).rejects.toThrow();
  await expect(
    f.service.read(scope, {
      ...f.identity,
      bindingDigest: "a".repeat(64),
      version: f.item.version,
    }),
  ).rejects.toThrow();
  await expect(
    f.service.read(scope, { ...f.identity, version: "a".repeat(32) }),
  ).rejects.toThrow();
  await expect(
    f.service.enroll(
      { ...scope, tenant: "_shared" },
      { application: "club-api", mapping, provider: "bexio" },
    ),
  ).rejects.toThrow();
});
it("classifies redacted OAuth audit routes", () => {
  expect(auditOperation("POST", "/local/oauth-credentials/read")).toEqual({
    category: "read",
    action: "local.oauth-credentials.read",
  });
  expect(
    auditOperation(
      "POST",
      "/namespaces/dev/club/local/oauth-credentials/begin",
    ),
  ).toEqual({ category: "write", action: "local.oauth-credentials.begin" });
});
it("fails closed on ordinary-secret head changes, disabled versions, invalid inputs and immutable fields", async () => {
  const f = fixture();
  await f.service.enroll(scope, {
    application: "club-api",
    mapping,
    provider: "bexio",
  });
  expect(
    await f.service.enroll(scope, {
      application: "club-api",
      mapping,
      provider: "bexio",
    }),
  ).toMatchObject({ anchorVersion: f.item.version });
  await expect(
    f.service.begin(scope, { ...f.claim, operationId: "invalid" }),
  ).rejects.toThrow();
  await expect(
    f.service.read(scope, {
      ...f.identity,
      provider: "dropbox",
      version: f.item.version,
    }),
  ).rejects.toThrow();
  await f.service.begin(scope, f.claim);
  for (const edit of [
    { added: "no" },
    { clientSecret: "different" },
    { expiresAt: 1 },
    { accessToken: "" },
    { accessToken: "x".repeat(26000) },
  ]) {
    await expect(
      f.service.commit(scope, {
        ...f.claim,
        value: JSON.stringify({
          ...f.value,
          expiresAt: Date.now() + 60000,
          ...edit,
        }),
      }),
    ).rejects.toThrow();
  }
  await expect(
    f.service.begin(scope, {
      ...f.claim,
      operationId: "22345678-1234-4123-8123-123456789abc",
    }),
  ).rejects.toThrow();
  f.ns().secrets[vaultName(scope, "secret", "bexio")]!.push(
    newSecret({ value: f.item.value }),
  );
  await expect(
    f.service.commit(scope, {
      ...f.claim,
      value: JSON.stringify({ ...f.value, expiresAt: Date.now() + 60000 }),
    }),
  ).rejects.toThrow();
  f.ns().secrets[vaultName(scope, "secret", "bexio")]![0]!.attributes.enabled =
    false;
  await expect(
    f.service.read(scope, { ...f.identity, version: f.item.version }),
  ).rejects.toThrow();
});
it("enforces narrow renew permissions and redacts HTTP audits", async () => {
  const { jest } = await import("@jest/globals");
  const { default: request } = await import("supertest");
  const { createHash, randomBytes } = await import("node:crypto");
  const { MongoStore } = await import("../src/store.js");
  const { createApp } = await import("../src/app.js");
  const f = fixture(),
    token = "oauth-fixture-token-aaaaaaaaaaaaaaaa";
  let permissions = ["read", "write", "renew"];
  const events: unknown[] = [];
  const store = {
    readGrants: async () => [
      {
        id: "a".repeat(64),
        tokenHash: createHash("sha256").update(token).digest("hex"),
        ...scope,
        permissions,
        enabled: true,
      },
    ],
    read: async (_: unknown, fn: any) =>
      structuredClone(fn(JSON.parse(JSON.stringify(f.ns())))),
    transaction: async (_: unknown, fn: any) => {
      const copy = JSON.parse(JSON.stringify(f.ns()));
      const out = fn(copy);
      Object.assign(f.ns(), copy);
      return out;
    },
    appendAudit: async (e: unknown) => {
      events.push(e);
    },
    close: async () => {},
  };
  const spy = jest.spyOn(MongoStore, "open").mockResolvedValue(store as any);
  const app = await createApp({
    mongoUri: "mongodb://127.0.0.1:1/fixture",
    masterKey: randomBytes(32),
    baseUrl: "http://127.0.0.1:4000",
    audit: { read: "console", write: "collection", list: "off", crypto: "off" },
  });
  spy.mockRestore();
  await app.init();
  const call = (path: string) =>
    request(app.getHttpServer())
      .post(path)
      .set("Authorization", `Bearer ${token}`)
      .set("x-vault-environment", scope.environment)
      .set("x-vault-tenant", scope.tenant);
  try {
    await call("/local/oauth-credentials/enroll")
      .send({ application: "club-api", mapping, provider: "bexio" })
      .expect(200);
    permissions = ["read"];
    await call("/local/oauth-credentials/begin").send(f.claim).expect(403);
    permissions = ["renew"];
    await call("/local/oauth-credentials/enroll")
      .send({ application: "club-api", mapping, provider: "bexio" })
      .expect(403);
    await call("/namespaces/development/club/local/oauth-credentials/begin")
      .send(f.claim)
      .expect(200);
    await call("/local/oauth-credentials/read")
      .send({ ...f.identity, version: f.item.version })
      .expect(403);
    await request(app.getHttpServer())
      .put("/local/runtime-manifests/club-api")
      .set("Authorization", `Bearer ${token}`)
      .set("x-vault-environment", scope.environment)
      .set("x-vault-tenant", scope.tenant)
      .send({})
      .expect(403);
    await request(app.getHttpServer())
      .put("/secrets/ordinary?api-version=2025-07-01")
      .set("Authorization", `Bearer ${token}`)
      .set("x-vault-environment", scope.environment)
      .set("x-vault-tenant", scope.tenant)
      .send({ value: "private-canary" })
      .expect(403);
  } finally {
    await app.close();
  }
  expect(JSON.stringify(events)).not.toContain("private-canary");
  expect(JSON.stringify(events)).not.toContain("clientSecret");
  expect(events).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        action: "local.oauth-credentials.begin",
        category: "write",
      }),
    ]),
  );
});
it("accepts Dropbox archiveRoot without accountId and freezes it during renewal", async () => {
  const f = fixture();
  const r = f.ns().runtimeManifests!["club-api"]!.versions["4"]!.request;
  const value = { ...f.value, archiveRoot: "/archive/development/club" };
  f.ns().secrets[vaultName(scope, "secret", "bexio")]![0]!.value =
    JSON.stringify(value);
  await f.service.enroll(scope, {
    application: "club-api",
    mapping,
    provider: "dropbox",
  });
  const claim = {
    ...f.claim,
    provider: "dropbox",
    bindingDigest: r.bindingDigest,
  };
  await f.service.begin(scope, claim);
  await expect(
    f.service.commit(scope, {
      ...claim,
      value: JSON.stringify({
        ...value,
        archiveRoot: "/changed",
        expiresAt: Date.now() + 60000,
      }),
    }),
  ).rejects.toThrow();
  await expect(
    f.service.commit(scope, {
      ...claim,
      value: JSON.stringify({
        ...value,
        accessToken: "new",
        expiresAt: Date.now() + 60000,
      }),
    }),
  ).resolves.toHaveProperty("version");
});
it("preserves operator expiry and not-before restrictions in renewed versions", async () => {
  const f = fixture();
  const old = f.ns().secrets[vaultName(scope, "secret", "bexio")]![0]!;
  const now = Math.floor(Date.now() / 1000);
  old.attributes.exp = now + 120;
  old.attributes.nbf = now - 60;
  await f.service.enroll(scope, {
    application: "club-api",
    mapping,
    provider: "bexio",
  });
  await f.service.begin(scope, f.claim);
  const result = await f.service.commit(scope, {
    ...f.claim,
    value: JSON.stringify({ ...f.value, expiresAt: Date.now() + 3600000 }),
  });
  const renewed = f
    .ns()
    .secrets[vaultName(scope, "secret", "bexio")]!.find(
      (v) => v.version === result.version,
    )!;
  expect(renewed.attributes).toMatchObject({
    enabled: true,
    exp: now + 120,
    nbf: now - 60,
  });
  const { jest } = await import("@jest/globals");
  const clock = jest.spyOn(Date, "now").mockReturnValue((now + 120) * 1000);
  try {
    await expect(
      f.service.read(scope, { ...f.identity, version: result.version }),
    ).rejects.toThrow("Forbidden");
  } finally {
    clock.mockRestore();
  }
});
