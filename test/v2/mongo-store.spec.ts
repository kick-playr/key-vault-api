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
  await store.transaction(async (tx) => {
    await tx.db.collection<any>("vault_tenants").insertMany(
      [
        { _id: "fcrww", name: "FCRWW" },
        { _id: "other", name: "Other" },
      ],
      { session: tx.session },
    );
    await tx.db.collection("vault_tenant_environments").insertMany(
      ["fcrww", "other"].map((tenantId) => ({
        tenantId,
        environment: "development",
        enabled: true,
        revision: 1,
      })),
      { session: tx.session },
    );
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

it("bootstraps only explicitly linked resources, keeps tenant failures local and denies revoked grants before 304", async () => {
  const { BootstrapService } = await import("../../src/v2/bootstrap.js");
  const password = "b".repeat(43),
    app = "bootstrap-app";
  await store.grants.insertOne({
    ...grant("bootstrap-grant"),
    applicationId: app,
    tokenHash: createHash("sha256").update(password).digest("hex"),
  });
  await store.transaction(async (tx) => {
    await tx.db.collection("vault_application_environments").insertOne(
      {
        applicationId: app,
        environment: "development",
        enabled: true,
        revision: 1,
      },
      { session: tx.session },
    );
    await tx.db.collection("vault_application_tenants").insertMany(
      ["fcrww", "other"].map((tenantId) => ({
        applicationId: app,
        environment: "development",
        tenantId,
        enabled: true,
        revision: 1,
      })),
      { session: tx.session },
    );
  });
  const one = resource("bootstrap-one"),
    hidden = resource("bootstrap-hidden");
  await store.createResource(one.resource, one.version, "test");
  await store.createResource(hidden.resource, hidden.version, "test");
  await store.links.insertMany([
    {
      _id: "bootstrap-link",
      applicationId: app,
      environment: "development",
      tenantId: "fcrww",
      resourceId: one.resource._id,
      accessName: "MONGODB_URI",
      versionPolicy: "latest",
      revision: 1,
    },
    {
      _id: "bootstrap-missing",
      applicationId: app,
      environment: "development",
      tenantId: "other",
      resourceId: "absent",
      accessName: "MONGODB_URI",
      versionPolicy: "latest",
      revision: 1,
    },
  ]);
  const service = new BootstrapService(store),
    result = await service.snapshot("Bearer " + password, app, "development");
  expect(result.status).toBe(200);
  if (result.status !== 200) throw Error("Expected payload");
  expect(result.snapshot.tenants.fcrww?.ready).toBe(true);
  expect(
    result.snapshot.tenants.fcrww?.values.map((v) => v.resourceId),
  ).toEqual([one.resource._id]);
  expect(result.snapshot.tenants.other?.ready).toBe(false);
  expect(
    await service.snapshot(
      "Bearer " + password,
      app,
      "development",
      result.etag,
    ),
  ).toEqual({ status: 304, etag: result.etag });
  await store.revokeGrant("bootstrap-grant", 1);
  await expect(
    service.snapshot("Bearer " + password, app, "development", result.etag),
  ).rejects.toThrow("Vault access denied");
});
it("derives club-admin authority from control records and never accepts JWT role claims", async () => {
  const { ControlRoleAuthority } =
    await import("../../src/v2/control-authority.js");
  await store.transaction(async (tx) => {
    await tx.db.client
      .db("control-kick-playr")
      .collection("tenantDefinitions")
      .insertOne(
        {
          id: "authority-club",
          environment: "development",
          status: "active",
          configRevision: 1,
          hostname: "club.example",
        },
        { session: tx.session },
      );
    await tx.db.client
      .db("control-kick-playr")
      .collection("tenantRuntimeAuthorities")
      .insertOne(
        {
          tenantId: "authority-club",
          environment: "development",
          schema: 1,
          status: "active",
          configRevision: 1,
          authorityRevision: 1,
          identityRealm: "https://club.example",
          hostnames: ["club.example"],
          users: [
            {
              issuer: "https://club.example",
              subject: "admin",
              status: "active",
              permissions: ["club:settings:read", "club:settings:write"],
            },
          ],
        },
        { session: tx.session },
      );
  });
  const authority = new ControlRoleAuthority(store),
    scope = {
      environment: "development",
      ownerType: "tenant" as const,
      ownerId: "authority-club",
    },
    actor = { issuer: "https://club.example", subject: "admin" };
  const roles = await authority.roles(actor, scope);
  expect(roles.clubAdminTenantIds).toEqual(["authority-club"]);
  expect(roles.globalAdmin).toBe(false);
  expect(
    (await authority.roles({ ...actor, subject: "attacker" }, scope))
      .clubAdminTenantIds,
  ).toEqual([]);
  await store.transaction(async (tx) => {
    await tx.db.client
      .db("control-kick-playr")
      .collection("tenantRuntimeAuthorities")
      .updateOne(
        { tenantId: "authority-club" },
        { $set: { status: "suspended" } },
        { session: tx.session },
      );
  });
  await expect(
    store.transaction((tx) =>
      authority.fence(actor, scope, roles.revision, tx),
    ),
  ).rejects.toThrow();
});
it("shares one tenant refresh winner and fences old refresh results after reconnect", async () => {
  const { createRequire } = await import("node:module"),
    { createIntegrationRuntime } = createRequire(import.meta.url)(
      "../../runtime-client/integration-runtime.cjs",
    );
  const runtime = await store.transaction(async (tx) =>
    createIntegrationRuntime({
      db: tx.db.client.db("fcrww-kick-playr"),
      tenantId: "fcrww",
      environment: "development",
      integrationId: "bexio-test",
      staticVersion: "client-v1",
      accountReference: "account",
      keys: new Map([["k1", Buffer.alloc(32, 8)]]),
      activeKeyVersion: "k1",
    }),
  );
  await runtime.reconnect(
    {
      accessToken: "old",
      refreshToken: "refresh",
      expiresAt: Date.now() - 100,
    },
    "account",
    0,
  );
  let providerCalls = 0,
    release!: () => void;
  const wait = new Promise<void>((resolve) => (release = resolve));
  const first = runtime.refresh(async () => {
    providerCalls++;
    await wait;
    return {
      accessToken: "stale",
      refreshToken: "stale-refresh",
      expiresAt: Date.now() + 100000,
    };
  });
  while (providerCalls === 0) await new Promise((r) => setTimeout(r, 5));
  await expect(
    runtime.refresh(async () => {
      providerCalls++;
      throw Error("must not dispatch");
    }),
  ).rejects.toThrow();
  await runtime.reconnect(
    {
      accessToken: "fresh",
      refreshToken: "fresh-refresh",
      expiresAt: Date.now() + 100000,
    },
    "account",
    1,
  );
  release();
  await expect(first).rejects.toThrow();
  expect(providerCalls).toBe(1);
  expect((await runtime.token()).accessToken).toBe("fresh");
});
async function workloadOperator(
  owner: import("../../src/v2/records.js").ResourceScope,
  capabilities: import("../../src/v2/records.js").GrantCapability[] = [
    "metadata:list",
    "secrets:read",
    "keys:export",
    "resources:write",
    "rotations:admin",
    "assignments:write",
  ],
) {
  const { randomBytes, randomUUID } = await import("node:crypto");
  const password = randomBytes(32).toString("base64url"),
    id = randomUUID();
  await store.grants.insertOne({
    _id: id,
    tokenHash: createHash("sha256").update(password).digest("hex"),
    grantClass: "operator",
    environment: owner.environment,
    capabilities,
    enabled: true,
    revision: 1,
    createdAt: Date.now(),
  });
  await store.transaction(async (tx) => {
    await tx.db
      .collection<any>("vault_grant_scopes")
      .insertOne(
        { _id: id + "-scope", grantId: id, ...owner },
        { session: tx.session },
      );
  });
  return (
    await import("../../src/v2/workload-operator.js")
  ).createWorkloadOperator(store, "Bearer " + password, owner);
}
it("blocks key activation for offline and joining instances until ACK or confirmed permanent stop", async () => {
  const { InstanceService } = await import("../../src/v2/instances.js"),
    { KeyRotationService } = await import("../../src/v2/key-rotations.js");
  const app = "rotation-app",
    password = "c".repeat(43),
    owner = {
      environment: "development",
      ownerType: "application" as const,
      ownerId: app,
    },
    actor = { issuer: "https://platform.example", subject: "global" };
  const auth = new Authorization(
    {
      roles: async () => ({
        revision: "1",
        globalAdmin: true,
        clubAdminTenantIds: [],
      }),
      fence: async () => {},
    },
    { read: async () => null },
  );
  await store.grants.insertOne({
    ...grant("rotation-grant"),
    applicationId: app,
    tokenHash: createHash("sha256").update(password).digest("hex"),
    capabilities: ["keys:export"],
  });
  await store.transaction((tx) =>
    tx.db.collection("vault_application_environments").insertOne(
      {
        applicationId: app,
        environment: "development",
        enabled: true,
        revision: 1,
      },
      { session: tx.session },
    ),
  );
  const operator = await workloadOperator(owner);
  const resources = new ResourceService(
      store,
      operator.authorization,
      new IntegrationSchemas(),
    ),
    key = await resources.create(operator.actor, owner, {
      name: "Data encryption",
      kind: "encryption-key",
      valueFormat: "base64",
      value: Buffer.alloc(32, 1).toString("base64"),
    });
  await store.links.insertOne({
    _id: "rotation-link",
    applicationId: app,
    environment: "development",
    resourceId: key._id,
    accessName: "DATA_KEY",
    versionPolicy: "latest",
    revision: 1,
  });
  const instances = new InstanceService(store),
    offline = await instances.register(
      "Bearer " + password,
      app,
      "development",
    ),
    rotations = new KeyRotationService(store, operator.authorization),
    versionId = "rotation-key-v2";
  const prepared = await rotations.prepare(operator.actor, owner, key._id, 1, {
    _id: versionId,
    ...owner,
    resourceId: key._id,
    versionNumber: 2,
    kind: "encryption-key",
    contentType: "text/plain",
    valueFormat: "base64",
    schemaIdentity: key.schemaIdentity,
    createdAt: Date.now(),
    createdBy: "test",
    value: store.sealValue(
      owner,
      key._id,
      versionId,
      key.schemaIdentity,
      Buffer.from(Buffer.alloc(32, 2).toString("base64")),
    ),
  });
  const humanRotations = new KeyRotationService(store, auth);
  await expect(
    humanRotations.activate(actor, owner, prepared.rotationId),
  ).rejects.toThrow("Vault access denied");
  expect(
    (await humanRotations.status(actor, owner, key._id)).rotations,
  ).toHaveLength(1);
  await expect(
    rotations.activate(operator.actor, owner, prepared.rotationId),
  ).rejects.toThrow("Waiting");
  const joining = await instances.register(
    "Bearer " + password,
    app,
    "development",
  );
  await instances.acknowledge("Bearer " + password, app, "development", {
    ...joining,
    rotationId: prepared.rotationId,
    versionId,
  });
  await expect(
    rotations.activate(operator.actor, owner, prepared.rotationId),
  ).rejects.toThrow("Waiting");
  await expect(
    rotations.retireInstance(
      operator.actor,
      owner,
      offline.instanceId,
      "yes",
      "offline",
    ),
  ).rejects.toThrow();
  await rotations.retireInstance(
    operator.actor,
    owner,
    offline.instanceId,
    "PERMANENTLY STOPPED " + offline.instanceId,
    "operator verified process termination",
  );
  expect(
    await rotations.activate(operator.actor, owner, prepared.rotationId),
  ).toEqual({
    state: "active",
  });
  expect(
    (await store.resources.findOne({ _id: key._id }))?.currentVersionId,
  ).toBe(versionId);
  await expect(
    instances.acknowledge("Bearer " + password, app, "development", {
      ...offline,
      rotationId: prepared.rotationId,
      versionId,
    }),
  ).rejects.toThrow();
});
it("refuses an existing v2 collection with missing schema enforcement", async () => {
  const { collectionDefinitions } = await import("../../src/v2/indexes.js");
  await store.transaction((tx) =>
    tx.db.command({
      collMod: "vault_resources",
      validator: {},
      validationLevel: "off",
    }),
  );
  try {
    const opened = await V2MongoStore.open({
      mongoUri: fixture.uri,
      masterKey: Buffer.alloc(32, 9),
    }).catch((error) => error);
    if (opened instanceof V2MongoStore) await opened.close();
    expect(opened).toBeInstanceOf(Error);
    expect(opened.message).toBe("Vault storage unavailable");
  } finally {
    await store.transaction((tx) =>
      tx.db.command({
        collMod: "vault_resources",
        validator: collectionDefinitions.vault_resources!.validator,
        validationLevel: "strict",
        validationAction: "error",
      }),
    );
  }
});
it("stages migration resumably with only static integration values in Vault and refuses changed sources", async () => {
  const { MigrationService } = await import("../../src/v2/migration.js");
  let revision = 1,
    stages = 0;
  const source = {
    inventory: async () => [
      {
        sourceId: "migration-bexio",
        revision,
        owner: scope,
        name: "Migrated accounting",
        kind: "integration" as const,
        provider: "bexio" as const,
        accountReference: "account",
        versions: [
          {
            id: "legacy-v1",
            value: {
              clientId: "client",
              clientSecret: "STATIC-CLIENT",
              accessToken: "RUNTIME-ACCESS",
              refreshToken: "RUNTIME-REFRESH",
              expiresAt: 123,
            },
          },
        ],
      },
    ],
  };
  const staged = new Map<string, unknown>(),
    runtime = {
      stage: async (jobId: string, item: any, versions: any[]) => {
        stages++;
        staged.set(jobId, versions);
      },
      verify: async () => {},
      activate: async () => {},
      rollback: async () => {},
      hasPostCutoverWrites: async () => false,
    };
  const migration = new MigrationService(
      store,
      source,
      runtime,
      Buffer.alloc(32, 3),
    ),
    { previewMigration } = await import("../../src/v2/migration.js"),
    preview = await previewMigration(source, Buffer.alloc(32, 3));
  await migration.stage(preview.digest, "migration-test");
  await migration.stage(preview.digest, "migration-test");
  expect(stages).toBe(2);
  expect(JSON.stringify(staged.get("migration-test"))).toContain(
    "RUNTIME-ACCESS",
  );
  expect(await migration.verify("migration-test")).toEqual({
    jobId: "migration-test",
    phase: "verified",
  });
  const record = await store.resources.findOne({
    name: "Migrated accounting",
    ...scope,
  });
  const bytes = await store.readValue(
    scope,
    record!._id,
    record!.currentVersionId,
  );
  try {
    expect(bytes.toString()).toContain("STATIC-CLIENT");
    expect(bytes.toString()).not.toContain("RUNTIME");
  } finally {
    bytes.fill(0);
  }
  await store.resources.updateOne(
    { _id: record!._id },
    { $set: { custody: "workload-only" } },
  );
  await expect(migration.verify("migration-test")).rejects.toThrow(
    "metadata verification",
  );
  await store.resources.updateOne(
    { _id: record!._id },
    { $set: { custody: "admin-managed" } },
  );
  revision = 2;
  await expect(
    migration.activate("migration-test", {
      assertConsumersStopped: async () => {},
      assertLegacyWritersFenced: async () => {},
      assertLegacyReadersFenced: async () => {},
      assertFreshGrantsDelivered: async () => {},
      assertTenantEnrollmentApproved: async () => {},
    }),
  ).rejects.toThrow("source changed");
});
it("migrates runtime payloads only into the encrypted tenant collections", async () => {
  const { MongoRuntimeMigrationTarget } =
    await import("../../src/v2/runtime-migration-target.js");
  const actor = { issuer: "https://platform.example", subject: "global" },
    auth = new Authorization(
      {
        roles: async () => ({
          revision: "1",
          globalAdmin: true,
          clubAdminTenantIds: [],
        }),
        fence: async () => {},
      },
      {
        read: async () => ({ enabled: true, revision: 1 }),
        fence: async () => {},
      },
    ),
    resources = new ResourceService(store, auth, new IntegrationSchemas());
  const key = await resources.create(actor, scope, {
    name: "Migration wrapping key",
    kind: "encryption-key",
    valueFormat: "base64",
    value: Buffer.alloc(32, 5).toString("base64"),
  });
  const target = new MongoRuntimeMigrationTarget(store, [
    {
      tenantId: "fcrww",
      mongoUri: fixture.uri.replace("key-vault-kick-playr", "fcrww-kick-playr"),
      wrappingKeyResourceId: key._id,
    },
  ]);
  try {
    await target.stage(
      "native-runtime-migration",
      {
        sourceId: "runtime",
        revision: 1,
        owner: scope,
        name: "Bexio",
        kind: "integration",
        provider: "bexio",
        accountReference: "account",
        pendingRefresh: true,
        runtimeMetadata: {schema:1,connectionId:"bexio",provider:"bexio",purpose:"oauth",capabilities:["contacts:read"],securityEpoch:7},
        versions: [],
      },
      [
        {
          id: "old-token-v1",
          value: {
            accessToken: "NATIVE-PRIVATE-ACCESS",
            refreshToken: "NATIVE-PRIVATE-REFRESH",
            expiresAt: 123,
          },
        },
      ],
      "native-integration",
      "static-v1",
    );
    await target.verify("native-runtime-migration");
    const row = await store.transaction((tx) =>
      tx.db.client
        .db("fcrww-kick-playr")
        .collection("integration_runtime_credentials")
        .findOne({ _id: "development/native-integration" } as any, {
          session: tx.session,
        }),
    );
    expect(JSON.stringify(row)).not.toContain("NATIVE-PRIVATE");
    expect(row?.status).toBe("staged");
    expect(row?.metadata).toEqual({schema:1,connectionId:"bexio",provider:"bexio",purpose:"oauth",capabilities:["contacts:read"],securityEpoch:7});
    await store.transaction(async tx=>{await tx.db.client.db("fcrww-kick-playr").collection("integration_runtime_credentials").updateOne({_id:"development/native-integration"} as any,{$set:{"metadata.securityEpoch":8}},{session:tx.session})});
    await expect(target.verify("native-runtime-migration")).rejects.toThrow("Runtime migration is incomplete");
    await store.transaction(async tx=>{await tx.db.client.db("fcrww-kick-playr").collection("integration_runtime_credentials").updateOne({_id:"development/native-integration"} as any,{$set:{"metadata.securityEpoch":7}},{session:tx.session})});
    await target.activate("native-runtime-migration");
    await target.activate("native-runtime-migration");
    expect(await target.hasPostCutoverWrites("native-runtime-migration")).toBe(
      false,
    );
  } finally {
    await target.close();
  }
});
it("cannot bypass key rotation by replacing a linked resource under the same access name", async () => {
  const { LinkService } = await import("../../src/v2/links.js");
  const actor = { issuer: "https://platform.example", subject: "global" },
    owner = {
      environment: "development",
      ownerType: "application" as const,
      ownerId: "bound-app",
    },
    auth = new Authorization(
      {
        roles: async () => ({
          revision: "1",
          globalAdmin: true,
          clubAdminTenantIds: [],
        }),
        fence: async () => {},
      },
      { read: async () => null },
    ),
    resources = new ResourceService(store, auth, new IntegrationSchemas()),
    links = new LinkService(store, auth);
  await store.transaction((tx) =>
    tx.db.collection("vault_application_environments").insertOne(
      {
        applicationId: "bound-app",
        environment: "development",
        enabled: true,
        revision: 1,
      },
      { session: tx.session },
    ),
  );
  const operator = await workloadOperator(owner),
    operatorResources = new ResourceService(
      store,
      operator.authorization,
      new IntegrationSchemas(),
    );
  const one = await operatorResources.create(operator.actor, owner, {
      name: "One key",
      kind: "encryption-key",
      valueFormat: "base64",
      value: Buffer.alloc(32, 1).toString("base64"),
    }),
    two = await operatorResources.create(operator.actor, owner, {
      name: "Two key",
      kind: "encryption-key",
      valueFormat: "base64",
      value: Buffer.alloc(32, 2).toString("base64"),
    });
  await links.save(actor, owner, "bound-app", 1, [
    {
      resourceId: one._id,
      accessName: "APP_ENCRYPTION_KEY",
      versionPolicy: "latest",
    },
  ]);
  await expect(
    links.save(actor, owner, "bound-app", 2, [
      {
        resourceId: two._id,
        accessName: "APP_ENCRYPTION_KEY",
        versionPolicy: "latest",
      },
    ]),
  ).rejects.toThrow("coordinated rotation");
  expect(
    (await links.list(actor, owner, "bound-app")).links[0]?.resourceId,
  ).toBe(one._id);
});
it("falls back from encrypted Redis cache failures and invalidates runtime authority on static changes", async () => {
  const { createRequire } = await import("node:module"),
    { createIntegrationRuntime } = createRequire(import.meta.url)(
      "../../runtime-client/integration-runtime.cjs",
    );
  const db = await store.transaction(async (tx) =>
      tx.db.client.db("fcrww-kick-playr"),
    ),
    base = {
      db,
      tenantId: "fcrww",
      environment: "development",
      integrationId: "cached-integration",
      staticVersion: "static-one",
      accountReference: "account",
      keys: new Map([["k1", Buffer.alloc(32, 8)]]),
      activeKeyVersion: "k1",
      cache: {
        get: async () => {
          throw Error("Redis offline");
        },
        set: async () => {
          throw Error("Redis offline");
        },
      },
    };
  const first = createIntegrationRuntime(base);
  await first.reconnect(
    {
      accessToken: "cached-runtime",
      refreshToken: "cached-refresh",
      expiresAt: Date.now() + 100000,
    },
    "account",
    0,
  );
  expect((await first.token()).accessToken).toBe("cached-runtime");
  const changed = createIntegrationRuntime({
    ...base,
    staticVersion: "static-two",
  });
  expect(await changed.synchronizeStatic(1)).toEqual({
    status: "reauthorization-required",
    authorityGeneration: 2,
  });
  await expect(first.token()).rejects.toThrow("reauthorization-required");
});
it("uses batch metadata queries instead of one Mongo read per linked secret at bootstrap", async () => {
  const { BootstrapService } = await import("../../src/v2/bootstrap.js");
  const app = "batch-app",
    password = "d".repeat(43);
  await store.grants.insertOne({
    ...grant("batch-grant"),
    applicationId: app,
    tokenHash: createHash("sha256").update(password).digest("hex"),
  });
  await store.transaction(async (tx) => {
    await tx.db
      .collection("vault_application_environments")
      .insertOne(
        {
          applicationId: app,
          environment: "development",
          enabled: true,
          revision: 1,
        },
        { session: tx.session },
      );
    await tx.db
      .collection("vault_application_tenants")
      .insertOne(
        {
          applicationId: app,
          environment: "development",
          tenantId: "fcrww",
          enabled: true,
          revision: 1,
        },
        { session: tx.session },
      );
  });
  for (let i = 0; i < 30; i++) {
    const item = resource("batch-" + i);
    await store.createResource(item.resource, item.version, "test");
    await store.links.insertOne({
      _id: "batch-link-" + i,
      applicationId: app,
      environment: "development",
      tenantId: "fcrww",
      resourceId: item.resource._id,
      accessName: "BATCH_SECRET_" + i,
      versionPolicy: "latest",
      revision: 1,
    });
  }
  await store.transaction((tx) => tx.db.command({ profile: 2 }));
  try {
    const result = await new BootstrapService(store).snapshot(
      "Bearer " + password,
      app,
      "development",
    );
    expect(result.status).toBe(200);
    const reads = await store.transaction((tx) =>
      tx.db
        .collection("system.profile")
        .countDocuments({ "command.find": "vault_resources" }),
    );
    expect(reads).toBeLessThanOrEqual(2);
  } finally {
    await store.transaction((tx) => tx.db.command({ profile: 0 }));
  }
});
it("keeps runtime tokens decryptable after proven pre-dispatch recovery", async () => {
  const { createIntegrationRuntime } = (
    await import("node:module")
  ).createRequire(import.meta.url)(
    "../../runtime-client/integration-runtime.cjs",
  );
  const db = await store.transaction(async (tx) =>
    tx.db.client.db("fcrww-kick-playr"),
  );
  const runtime = createIntegrationRuntime({
    db,
    tenantId: "fcrww",
    environment: "development",
    integrationId: "recovery-test",
    staticVersion: "v1",
    accountReference: "account",
    keys: new Map([["k1", Buffer.alloc(32, 8)]]),
    activeKeyVersion: "k1",
  });
  await runtime.reconnect(
    {
      accessToken: "old",
      refreshToken: "refresh",
      expiresAt: Date.now() + 100000,
    },
    "account",
    0,
  );
  const id = "development/recovery-test",
    row = await db
      .collection("integration_runtime_credentials")
      .findOne({ _id: id } as any);
  await db
    .collection("integration_runtime_credentials")
    .updateOne({ _id: id } as any, {
      $set: { operation: "reserved-recovery" },
    });
  await db
    .collection("integration_refresh_operations")
    .insertOne({
      _id: "reserved-recovery",
      tenantId: "fcrww",
      environment: "development",
      integrationId: "recovery-test",
      phase: "reserved",
      authorityGeneration: row!.authorityGeneration,
      revision: row!.revision,
      staticVersion: "v1",
    } as any);
  await runtime.recoverReserved("reserved-recovery");
  expect((await runtime.token()).accessToken).toBe("old");
  await db
    .collection("integration_runtime_credentials")
    .updateOne({ _id: id } as any, { $set: { expiresAt: 0 } });
  let calls = 0;
  const refreshed = await runtime.refresh(async (old: any) => {
    calls++;
    expect(old.refreshToken).toBe("refresh");
    return {
      accessToken: "new",
      refreshToken: "new-refresh",
      expiresAt: Date.now() + 100000,
    };
  });
  expect(refreshed.accessToken).toBe("new");
  expect(calls).toBe(1);
  expect(
    (await db
      .collection("integration_runtime_credentials")
      .findOne({ _id: id } as any))!.authorityGeneration,
  ).toBe(2);
});
it("keeps workload credentials opaque and immutable to admins while allowing scoped deployment access", async () => {
  const owner = {
    environment: "development",
    ownerType: "application" as const,
    ownerId: "custody-app",
  };
  await store.transaction(async (tx) => {
    await tx.db
      .collection("vault_application_environments")
      .insertOne(
        {
          applicationId: owner.ownerId,
          environment: owner.environment,
          enabled: true,
          revision: 1,
        },
        { session: tx.session },
      );
  });
  const input = resource("custody-control-uri"),
    metadata = {
      ...input.resource,
      ...owner,
      custody: "workload-only" as const,
    },
    version = { ...input.version, ...owner };
  version.value = store.sealValue(
    owner,
    metadata._id,
    version._id,
    version.schemaIdentity,
    Buffer.from("mongodb://PRIVATE/control-kick-playr"),
  );
  await store.createResource(metadata, version, "deployment");
  const admin = { issuer: "https://platform.example", subject: "global" },
    auth = new Authorization(
      {
        roles: async () => ({
          revision: "1",
          globalAdmin: true,
          clubAdminTenantIds: [],
        }),
        fence: async () => {},
      },
      { read: async () => null },
    ),
    resources = new ResourceService(store, auth, new IntegrationSchemas());
  const list = await resources.list(admin, owner, { limit: 20 });
  expect(list[0]?.custody).toBe("workload-only");
  expect(JSON.stringify(list)).not.toContain("PRIVATE");
  await expect(
    resources.reveal(admin, owner, metadata._id, version._id),
  ).rejects.toThrow("Vault access denied");
  await expect(
    resources.update(admin, owner, metadata._id, 1, {
      name: "renamed",
      kind: "secret",
      value: "chosen",
    }),
  ).rejects.toThrow("Vault access denied");
  await expect(
    resources.setEnabled(admin, owner, metadata._id, 1, false),
  ).rejects.toThrow("Vault access denied");
  await expect(
    resources.remove(admin, owner, metadata._id, 1, metadata.name),
  ).rejects.toThrow("Vault access denied");
  const operator = await workloadOperator(owner),
    deployed = new ResourceService(
      store,
      operator.authorization,
      new IntegrationSchemas(),
    );
  const created = await deployed.create(operator.actor, owner, {
    name: "Operator-provisioned URI",
    kind: "secret",
    value: "mongodb://PRIVATE/other",
  });
  expect(created.custody).toBe("workload-only");
  await expect(
    resources.reveal(admin, owner, created._id, created.currentVersionId),
  ).rejects.toThrow("Vault access denied");
  const key = await deployed.create(operator.actor, owner, {
    name: "Workload control key",
    kind: "encryption-key",
    valueFormat: "base64",
    value: Buffer.alloc(32, 3).toString("base64"),
  });
  const limited = await workloadOperator(owner, [
      "metadata:list",
      "secrets:read",
    ]),
    limitedResources = new ResourceService(
      store,
      limited.authorization,
      new IntegrationSchemas(),
    );
  await expect(
    limitedResources.reveal(
      limited.actor,
      owner,
      key._id,
      key.currentVersionId,
    ),
  ).rejects.toThrow("Vault access denied");
  const keyOnly = await workloadOperator(owner, ["keys:export"]),
    keyResources = new ResourceService(
      store,
      keyOnly.authorization,
      new IntegrationSchemas(),
    );
  const exported = await keyResources.reveal(
    keyOnly.actor,
    owner,
    key._id,
    key.currentVersionId,
  );
  expect(exported.toString()).toBe(Buffer.alloc(32, 3).toString("base64"));
  exported.fill(0);
  const { LinkService } = await import("../../src/v2/links.js");
  const links = new LinkService(store, auth);
  const ordinary = await resources.create(admin, owner, {
    name: "Ordinary text",
    kind: "secret",
    value: "known",
  });
  await expect(
    links.create(admin, owner, {
      applicationId: owner.ownerId,
      resourceId: ordinary._id,
      accessName: "TENANT_CONTROL_MONGODB_URI",
      versionPolicy: "latest",
    }),
  ).rejects.toThrow("Vault access denied");
  await links.create(admin, owner, {
    applicationId: owner.ownerId,
    resourceId: metadata._id,
    accessName: "TENANT_CONTROL_MONGODB_URI",
    versionPolicy: "latest",
  });
  const password = "w".repeat(43);
  await store.grants.insertOne({
    ...grant("custody-workload-grant"),
    applicationId: owner.ownerId,
    tokenHash: createHash("sha256").update(password).digest("hex"),
  });
  const { BootstrapService } = await import("../../src/v2/bootstrap.js");
  const snapshot = await new BootstrapService(store).snapshot(
    "Bearer " + password,
    owner.ownerId,
    owner.environment,
  );
  expect(snapshot.status).toBe(200);
  if (snapshot.status !== 200) throw Error("Expected ready snapshot");
  expect(snapshot.snapshot.application.ready).toBe(true);
  expect(snapshot.snapshot.application.values[0]?.value).toBe(
    "mongodb://PRIVATE/control-kick-playr",
  );
  // A stale/imported link cannot bypass custody validation at delivery time.
  await store.resources.updateOne({ _id: metadata._id }, { $set: { custody: "admin-managed" } });
  const invalid = await new BootstrapService(store).snapshot("Bearer " + password, owner.ownerId, owner.environment);
  expect(invalid.status).toBe(200);
  if (invalid.status !== 200) throw Error("Expected unavailable snapshot");
  expect(invalid.snapshot.application.ready).toBe(false);
  expect(invalid.snapshot.application.values).toEqual([]);
  await store.resources.updateOne({ _id: metadata._id }, { $set: { custody: "workload-only" } });
  const bytes = await deployed.reveal(
    operator.actor,
    owner,
    metadata._id,
    version._id,
  );
  expect(bytes.toString()).toContain("mongodb://PRIVATE");
  bytes.fill(0);
  await store.grants.updateOne(
    { _id: operator.actor.subject },
    { $set: { enabled: false }, $inc: { revision: 1 } },
  );
  await expect(
    deployed.reveal(operator.actor, owner, metadata._id, version._id),
  ).rejects.toThrow();
});
it('delivers fresh application grants privately and fences tenant enrollment revocation before publication',async()=>{
 const {DeploymentGrantDelivery}=await import('../../src/v2/grant-delivery.js');
 const owner={environment:'development',ownerType:'application' as const,ownerId:'delivery-app'},actor={issuer:'https://platform.example',subject:'global'};
 const auth=new Authorization({roles:async()=>({revision:'1',globalAdmin:true,clubAdminTenantIds:[]}),fence:async()=>{}},{read:async()=>null});
 await store.transaction(async tx=>{
  await tx.db.collection('vault_application_environments').insertOne({applicationId:owner.ownerId,environment:owner.environment,revision:1,enabled:true},{session:tx.session});
  await tx.db.collection<any>('vault_deployment_custody').insertOne({_id:'delivery-custody',applicationId:owner.ownerId,environment:owner.environment,revision:1,enabled:true,mode:'deployment-only',deliveryId:'private-sink'},{session:tx.session});
  await tx.db.collection('vault_application_tenants').insertOne({applicationId:owner.ownerId,environment:owner.environment,tenantId:'fcrww',revision:1,enabled:true},{session:tx.session});
  await tx.db.collection<any>('vault_machine_enrollments').insertOne({_id:'delivery-enrollment',applicationId:owner.ownerId,environment:owner.environment,tenantId:'fcrww',approved:true,approvedBy:'https://club.example|admin',approvedAt:Date.now()},{session:tx.session});
 });
 let delivered='',revoke=true;
 const delivery=new DeploymentGrantDelivery(store,{id:'private-sink',deliver:async input=>{
  delivered=input.password;
  const candidate=await store.grants.findOne({tokenHash:createHash('sha256').update(input.password).digest('hex')});expect(candidate?.enabled).toBe(false);
  if(revoke)await store.transaction(async tx=>{await tx.db.collection<any>('vault_machine_enrollments').updateOne({_id:'delivery-enrollment'},{$set:{approved:false}},{session:tx.session})});
 }});
 const grants=new GrantService(store,auth,delivery);
 await expect(grants.issue(actor,{applicationId:owner.ownerId,environment:owner.environment})).rejects.toThrow('Vault access denied');
 expect((await store.grants.findOne({tokenHash:createHash('sha256').update(delivered).digest('hex')}))?.enabled).toBe(false);
 await store.transaction(async tx=>{await tx.db.collection<any>('vault_machine_enrollments').updateOne({_id:'delivery-enrollment'},{$set:{approved:true}},{session:tx.session})});
 revoke=false;
 const metadata=await grants.issue(actor,{applicationId:owner.ownerId,environment:owner.environment});
 expect(JSON.stringify(metadata)).not.toContain(delivered);expect(metadata).not.toHaveProperty('tokenHash');
 expect((await grants.authorize('Bearer '+delivered,owner.ownerId,owner.environment)).enabled).toBe(true);
});
it('blocks deleting an application whose owned resource is consumed only by another application',async()=>{
 const {CatalogService}=await import('../../src/v2/catalog.js');
 const actor={issuer:'https://platform.example',subject:'global'},auth=new Authorization({roles:async()=>({revision:'1',globalAdmin:true,clubAdminTenantIds:[]}),fence:async()=>{}},{read:async()=>null});
 const catalog=new CatalogService(store,auth),owner={environment:'development',ownerType:'application' as const,ownerId:'resource-owner'};
 await catalog.saveApplication(actor,'development',{id:owner.ownerId,name:'Resource owner',description:'',revision:0});
 await catalog.saveApplication(actor,'development',{id:'resource-consumer',name:'Consumer',description:'',revision:0});
 const resource=await new ResourceService(store,auth,new IntegrationSchemas()).create(actor,owner,{name:'Shared resource',kind:'secret',value:'private'});
 await store.links.insertOne({_id:'shared-owner-delete-link',applicationId:'resource-consumer',environment:'development',resourceId:resource._id,accessName:'SHARED_SECRET',versionPolicy:'latest',revision:1});
 await expect(catalog.removeApplication(actor,'development',owner.ownerId,1,'Resource owner')).rejects.toThrow('Application is in use');
});
