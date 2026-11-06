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
