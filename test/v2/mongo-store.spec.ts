import { ResourceService } from "../../src/v2/resources.js";
import { IntegrationSchemas } from "../../src/v2/integration-schemas.js";
import { ConsentService, consentReader } from "../../src/v2/consents.js";
import { GrantService } from "../../src/v2/grants.js";
import { Authorization } from "../../src/v2/authorization.js";
import { createHash } from "node:crypto";
import { V2MongoStore } from "../../src/v2/mongo-store.js";
import { ValueCipher } from "../../src/v2/value-cipher.js";
import { replicaFixture } from "./mongo-fixture.js";
import type {
  GrantRecord,
  ResourceRecord,
  ResourceVersion,
} from "../../src/v2/records.js";
const scope = {
  environment: "development",
  ownerType: "tenant" as const,
  ownerId: "fcrww",
};
let fixture: Awaited<ReturnType<typeof replicaFixture>>, store: V2MongoStore;
beforeAll(async () => {
  fixture = await replicaFixture();
  store = await V2MongoStore.open({
    mongoUri: fixture.uri,
    masterKey: Buffer.alloc(32, 9),
  });
}, 30000);
afterAll(async () => {
  await store?.close();
  await fixture?.close();
});
const grant = (id: string): GrantRecord => ({
  _id: id,
  tokenHash: createHash("sha256").update(id).digest("hex"),
  grantClass: "application",
  applicationId: "club-api",
  environment: "development",
  capabilities: ["metadata:list", "secrets:read"],
  enabled: true,
  revision: 1,
  createdAt: Date.now(),
});
function resource(id: string): {
  resource: ResourceRecord;
  version: ResourceVersion;
} {
  const cipher = new ValueCipher(Buffer.alloc(32, 9)),
    versionId = id + "-v1";
  const resource: ResourceRecord = {
    ...scope,
    _id: id,
    name: id,
    kind: "secret",
    contentType: "text/plain",
    valueFormat: "text",
    schemaIdentity: "secret:text@1",
    enabled: true,
    revision: 1,
    currentVersionId: versionId,
    currentVersionNumber: 1,
  };
  const version: ResourceVersion = {
    ...scope,
    _id: versionId,
    resourceId: id,
    versionNumber: 1,
    kind: "secret",
    contentType: "text/plain",
    valueFormat: "text",
    schemaIdentity: resource.schemaIdentity,
    createdAt: Date.now(),
    createdBy: "operator",
    value: cipher.seal(
      scope,
      id,
      versionId,
      resource.schemaIdentity,
      Buffer.from("PRIVATE-" + id),
    ),
  };
  cipher.close();
  return { resource, version };
}
it("persists one grant per document and revokes only its expected revision", async () => {
  await store.grants.insertOne(grant("one"));
  await store.grants.insertOne(grant("two"));
  expect(await store.grants.countDocuments({})).toBe(2);
  expect(await store.revokeGrant("one", 1)).toBe(true);
  expect(await store.revokeGrant("one", 1)).toBe(false);
  expect((await store.grants.findOne({ _id: "one" }))?.enabled).toBe(false);
  expect((await store.grants.findOne({ _id: "two" }))?.revision).toBe(1);
  await expect(
    store.grants.insertOne({
      ...grant("write-attempt"),
      capabilities: ["resources:write"],
    }),
  ).rejects.toThrow();
});
it("lists names, scope, type and versions without decryption or returning value fields", async () => {
  const r = resource("bexio-client");
  await store.createResource(r.resource, r.version, "operator");
  const original = ValueCipher.prototype.open;
  ValueCipher.prototype.open = () => {
    throw Error("Metadata must not decrypt");
  };
  try {
    const list = await store.listResources(scope, { limit: 20 });
    expect(list[0]?.name).toBe("bexio-client");
    const versions = await store.listVersions(scope, r.resource._id);
    expect(versions[0]?.versionNumber).toBe(1);
    expect(versions[0]).not.toHaveProperty("value");
    expect(JSON.stringify(list)).not.toContain("PRIVATE");
  } finally {
    ValueCipher.prototype.open = original;
  }
  expect(
    (await store.readValue(scope, r.resource._id, r.version._id)).toString(),
  ).toBe("PRIVATE-bexio-client");
  await expect(
    store.readValue(
      { ...scope, ownerId: "other" },
      r.resource._id,
      r.version._id,
    ),
  ).rejects.toThrow();
  await expect(
    store.listResources({ ...scope, environment: { $ne: "other" } } as any, {
      limit: 20,
    }),
  ).rejects.toThrow();
});
it("publishes exactly one concurrent version and atomically keeps its metadata, audit and change head", async () => {
  const r = resource("concurrent");
  await store.createResource(r.resource, r.version, "operator");
  const make = (suffix: string): ResourceVersion => {
    const c = new ValueCipher(Buffer.alloc(32, 9));
    const v = {
      ...r.version,
      _id: "concurrent-" + suffix,
      versionNumber: 2,
      value: c.seal(
        scope,
        r.resource._id,
        "concurrent-" + suffix,
        r.resource.schemaIdentity,
        Buffer.from(suffix),
      ),
    };
    c.close();
    return v;
  };
  const results = await Promise.allSettled([
    store.publishVersion(scope, r.resource._id, 1, make("a"), "operator"),
    store.publishVersion(scope, r.resource._id, 1, make("b"), "operator"),
  ]);
  expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  expect(
    await store.versions.countDocuments({ resourceId: r.resource._id }),
  ).toBe(2);
  const current = await store.resources.findOne({ _id: r.resource._id });
  expect(current?.revision).toBe(2);
  expect(
    await fixture.client
      .db("key-vault-kick-playr")
      .collection("vault_audit_events")
      .countDocuments({ targetId: r.resource._id }),
  ).toBe(2);
  await expect(
    store.publishVersion(
      { ...scope, ownerId: "wrong" },
      r.resource._id,
      2,
      { ...make("c"), versionNumber: 3 },
      "operator",
    ),
  ).rejects.toThrow();
  expect(
    await store.versions.countDocuments({ resourceId: r.resource._id }),
  ).toBe(2);
});
it("rejects the wrong master key and legacy target database without exposing connection strings", async () => {
  await expect(
    V2MongoStore.open({
      mongoUri: fixture.uri,
      masterKey: Buffer.alloc(32, 1),
    }),
  ).rejects.toThrow("Vault storage unavailable");
  await expect(
    V2MongoStore.open({
      mongoUri: fixture.uri.replace("/key-vault-kick-playr", "/legacy"),
      masterKey: Buffer.alloc(32, 9),
    }),
  ).rejects.toThrow();
});

it("delivers application passwords only through approved provisioning and atomically replaces grants", async () => {
  const tokens: string[] = [],
    actor = { issuer: "https://identity.invalid", subject: "admin" };
  const authorization = new Authorization(
    {
      fence: async () => {},
      roles: async () => ({
        revision: "1",
        globalAdmin: true,
        clubAdminTenantIds: [],
      }),
    },
    { read: async () => ({ enabled: true, revision: 1 }) },
  );
  await fixture.client
    .db("key-vault-kick-playr")
    .collection("vault_application_tenants")
    .insertOne({
      applicationId: "explorer-api",
      environment: "development",
      tenantId: "fcrww",
      enabled: true,
    });
  await fixture.client
    .db("key-vault-kick-playr")
    .collection("vault_application_environments")
    .insertOne({
      applicationId: "explorer-api",
      environment: "development",
      revision: 1,
      enabled: true,
    });
  let approved = true;
  const service = new GrantService(store, authorization, {
    approve: async () => ({
      applicationId: "explorer-api",
      environment: "development",
      approvedTenantIds: approved ? ["fcrww"] : [],
      fence: async () => {},
      deliver: async (token: string) => {
        tokens.push(token);
      },
    }),
  });
  approved = false;
  await expect(
    service.issue(actor, {
      applicationId: "explorer-api",
      environment: "development",
    }),
  ).rejects.toThrow();
  expect(tokens).toHaveLength(0);
  approved = true;
  const first = await service.issue(actor, {
    applicationId: "explorer-api",
    environment: "development",
  });
  expect(tokens).toHaveLength(1);
  expect(JSON.stringify(first)).not.toContain(tokens[0]);
  expect(first).not.toHaveProperty("tokenHash");
  expect(
    (
      await service.authorize(
        "Bearer " + tokens[0],
        "explorer-api",
        "development",
      )
    )._id,
  ).toBe(first._id);
  await expect(
    service.issue(actor, {
      applicationId: "explorer-api",
      environment: "development",
      replaces: { id: "missing", revision: 1 },
    }),
  ).rejects.toThrow();
  expect(tokens).toHaveLength(1);
  const next = await service.rotate(actor, first._id, first.revision);
  await expect(
    service.authorize("Bearer " + tokens[0], "explorer-api", "development"),
  ).rejects.toThrow();
  expect(
    (
      await service.authorize(
        "Bearer " + tokens[1],
        "explorer-api",
        "development",
      )
    )._id,
  ).toBe(next._id);
  await service.revoke(actor, next._id, next.revision);
  await expect(
    service.authorize("Bearer " + tokens[1], "explorer-api", "development"),
  ).rejects.toThrow();
});

it("keeps tenant consent in one document and only permits its club admin to change it", async () => {
  const reader = consentReader(store),
    authorization = new Authorization(
      {
        fence: async () => {},
        roles: async (actor) => ({
          revision: "1",
          globalAdmin: actor.subject === "global",
          clubAdminTenantIds: actor.subject === "club" ? ["fcrww"] : [],
        }),
      },
      reader,
    );
  const consents = new ConsentService(store, authorization),
    club = { issuer: "https://identity.invalid", subject: "club" },
    global = { issuer: "https://identity.invalid", subject: "global" };
  await expect(consents.approve(global, scope, 0)).rejects.toThrow();
  await consents.approve(club, scope, 0);
  const permit = await authorization.require(global, "values:read", scope);
  await consents.revoke(club, scope, 1);
  await expect(authorization.assertCurrent(permit)).rejects.toThrow();
  expect(
    await fixture.client
      .db("key-vault-kick-playr")
      .collection("vault_tenant_admin_consents")
      .countDocuments({}),
  ).toBe(1);
  await expect(
    consents.approve(club, { ...scope, ownerId: "other" }, 0),
  ).rejects.toThrow();
});

it("saves typed static integration JSON with plaintext metadata and fences value access through consent", async () => {
  const reader = consentReader(store);
  const authorization = new Authorization(
      {
        roles: async (actor) => ({
          revision: "1",
          globalAdmin: actor.subject === "global",
          clubAdminTenantIds: actor.subject === "club" ? ["fcrww"] : [],
        }),
        fence: async () => {},
      },
      reader,
    ),
    resources = new ResourceService(
      store,
      authorization,
      new IntegrationSchemas(),
    );
  const club = { issuer: "https://identity.invalid", subject: "club" },
    global = { issuer: "https://identity.invalid", subject: "global" };
  const created = await resources.create(club, scope, {
    name: "Bexio Accounting",
    kind: "integration",
    schemaIdentity: "builtin:bexio@1",
    value: {
      clientId: "client",
      clientSecret: "PRIVATE-BEXIO",
      accountReference: "account",
    },
  });
  expect(created.name).toBe("Bexio Accounting");
  expect(created.kind).toBe("integration");
  expect(created).not.toHaveProperty("value");
  await expect(
    resources.reveal(global, scope, created._id, created.currentVersionId),
  ).rejects.toThrow();
  const revealed = await resources.reveal(
    club,
    scope,
    created._id,
    created.currentVersionId,
  );
  try {
    expect(JSON.parse(revealed.toString()).clientSecret).toBe("PRIVATE-BEXIO");
  } finally {
    revealed.fill(0);
  }
  const changed = await resources.update(club, scope, created._id, 1, {
    name: "Bexio Finance",
    kind: "integration",
    schemaIdentity: "builtin:bexio@1",
    value: {
      clientId: "client",
      clientSecret: "PRIVATE-NEXT",
      accountReference: "account",
    },
  });
  expect(changed.revision).toBe(2);
  expect(changed.name).toBe("Bexio Finance");
  await store.links.insertOne({
    _id: "in-use",
    applicationId: "club-api",
    environment: "development",
    tenantId: "fcrww",
    resourceId: created._id,
    accessName: "BEXIO",
    versionPolicy: "latest",
    revision: 1,
  });
  await expect(
    resources.remove(club, scope, created._id, 2, "Bexio Finance"),
  ).rejects.toThrow();
  await store.links.deleteOne({ _id: "in-use" });
  await resources.remove(club, scope, created._id, 2, "Bexio Finance");
  expect(
    (await resources.list(club, scope, { limit: 100 })).some(
      (r) => r._id === created._id,
    ),
  ).toBe(false);
  await expect(
    resources.create(club, scope, {
      name: "Runtime material",
      kind: "integration",
      schemaIdentity: "builtin:bexio@1",
      value: {
        clientId: "c",
        clientSecret: "p",
        accountReference: "a",
        accessToken: "NO",
      },
    }),
  ).rejects.toThrow();
  const document = await store.resources.findOne({ _id: created._id });
  expect(JSON.stringify(document)).not.toContain("PRIVATE-BEXIO");
});
