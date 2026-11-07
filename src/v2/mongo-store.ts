import {
  MongoClient,
  type ClientSession,
  type Collection,
  type Db,
} from "mongodb";
import { randomUUID } from "node:crypto";
import {
  tenantIdentifier,
  assertDatabaseName,
  databaseNames,
} from "./database-names.js";
import { installCollections } from "./indexes.js";
import { ValueCipher } from "./value-cipher.js";
import type {
  AuditRecord,
  GrantRecord,
  ResourceLink,
  ResourceRecord,
  ResourceScope,
  ResourceVersion,
} from "./records.js";
const unavailable = () => Error("Vault storage unavailable");
const conflict = () => Error("Vault document conflict");
export function scopeFilter(scope: ResourceScope): ResourceScope {
  if (
    !scope ||
    typeof scope.environment !== "string" ||
    !/^[a-z][a-z0-9-]{0,31}$/.test(scope.environment) ||
    !["application", "tenant"].includes(scope.ownerType) ||
    typeof scope.ownerId !== "string" ||
    !/^[a-z0-9][a-z0-9-]{0,63}$/.test(scope.ownerId)
  )
    throw unavailable();
  if (scope.ownerType === "tenant") tenantIdentifier(scope.ownerId);
  return {
    environment: scope.environment,
    ownerType: scope.ownerType,
    ownerId: scope.ownerId,
  };
}

export interface V2Transaction {
  readonly session: ClientSession;
  readonly db: Db;
}
export class V2MongoStore {
  readonly databaseName = databaseNames.vault;
  readonly resources: Collection<ResourceRecord>;
  readonly versions: Collection<ResourceVersion>;
  readonly grants: Collection<GrantRecord>;
  readonly links: Collection<ResourceLink>;
  private closed = false;
  private readonly transactions = new WeakSet<V2Transaction>();
  private constructor(
    private readonly client: MongoClient,
    private readonly db: Db,
    private readonly cipher: ValueCipher,
  ) {
    this.resources = db.collection<ResourceRecord>("vault_resources");
    this.versions = db.collection<ResourceVersion>("vault_resource_versions");
    this.grants = db.collection<GrantRecord>("vault_grants");
    this.links = db.collection<ResourceLink>("vault_resource_links");
  }
  static async open(config: {
    mongoUri: string;
    masterKey: Buffer;
  }): Promise<V2MongoStore> {
    assertDatabaseName(config.mongoUri, databaseNames.vault);
    let client: MongoClient | undefined, cipher: ValueCipher | undefined;
    try {
      cipher = new ValueCipher(config.masterKey);
      client = new MongoClient(config.mongoUri, {
        connectTimeoutMS: 3000,
        serverSelectionTimeoutMS: 3000,
        socketTimeoutMS: 5000,
        retryWrites: false,
        readPreference: "primary",
        readConcern: { level: "majority" },
        writeConcern: { w: "majority", wtimeoutMS: 5000 },
      });
      await client.connect();
      const hello = await client.db("admin").command({ hello: 1 });
      if (!hello.setName && hello.msg !== "isdbgrid") throw unavailable();
      const db = client.db(databaseNames.vault),
        scope: ResourceScope = {
          environment: "platform",
          ownerType: "application",
          ownerId: "vault-api",
        },
        id = "value-encryption-check";
      const checks = db.collection<{
        _id: string;
        value: ReturnType<ValueCipher["seal"]>;
      }>("vault_platform_settings");
      const value = cipher.seal(
        scope,
        id,
        "v2",
        "verifier",
        Buffer.from("vault-v2-master-key-check"),
      );
      await checks.updateOne(
        { _id: id },
        { $setOnInsert: { value } },
        { upsert: true },
      );
      const existing = await checks.findOne({ _id: id });
      if (!existing) throw unavailable();
      const plain = cipher.open(scope, id, "v2", "verifier", existing.value);
      try {
        if (plain.toString() !== "vault-v2-master-key-check")
          throw unavailable();
      } finally {
        plain.fill(0);
      }
      await installCollections(db);
      return new V2MongoStore(client, db, cipher);
    } catch {
      cipher?.close();
      await client?.close().catch(() => undefined);
      throw unavailable();
    }
  }
  async transaction<T>(
    work: (transaction: V2Transaction) => Promise<T>,
  ): Promise<T> {
    if (this.closed) throw unavailable();
    const session = this.client.startSession();
    try {
      return await session.withTransaction(
        async () => {
          const tx = Object.freeze({ session, db: this.db });
          this.transactions.add(tx);
          try {
            return await work(tx);
          } finally {
            this.transactions.delete(tx);
          }
        },
        {
          readConcern: { level: "snapshot" },
          writeConcern: { w: "majority" },
          readPreference: "primary",
        },
      );
    } finally {
      await session.endSession();
    }
  }
  private within<T>(
    tx: V2Transaction | undefined,
    work: (tx: V2Transaction) => Promise<T>,
  ): Promise<T> {
    if (!tx) return this.transaction(work);
    if (!this.transactions.has(tx)) throw unavailable();
    return work(tx);
  }
  sealValue(
    scope: ResourceScope,
    resourceId: string,
    versionId: string,
    schemaIdentity: string,
    value: Buffer,
  ) {
    return this.cipher.seal(
      scopeFilter(scope),
      resourceId,
      versionId,
      schemaIdentity,
      value,
    );
  }
  private assertVersion(
    resource: ResourceRecord,
    version: ResourceVersion,
  ): void {
    scopeFilter(resource);
    for (const field of [
      "environment",
      "ownerType",
      "ownerId",
      "kind",
      "contentType",
      "valueFormat",
      "schemaIdentity",
    ] as const)
      if (version[field] !== resource[field]) throw conflict();
    if (
      version.resourceId !== resource._id ||
      !Number.isSafeInteger(version.versionNumber) ||
      version.versionNumber < 1
    )
      throw conflict();
    const plain = this.cipher.open(
      resource,
      resource._id,
      version._id,
      resource.schemaIdentity,
      version.value,
    );
    plain.fill(0);
  }
  private async changed(
    tx: V2Transaction,
    scope: ResourceScope,
    targetId: string,
    actorId: string,
    action: string,
  ): Promise<void> {
    await tx.db.collection<AuditRecord>("vault_audit_events").insertOne(
      {
        _id: randomUUID(),
        ...scopeFilter(scope),
        actorId,
        action,
        targetId,
        at: Date.now(),
      },
      { session: tx.session },
    );
    await tx.db
      .collection("vault_change_heads")
      .updateOne(
        { ...scopeFilter(scope) },
        { $inc: { revision: 1 } },
        { upsert: true, session: tx.session },
      );
  }
  async createResource(
    resource: ResourceRecord,
    version: ResourceVersion,
    actorId: string,
    transaction?: V2Transaction,
  ): Promise<void> {
    const r = structuredClone(resource),
      v = structuredClone(version);
    this.assertVersion(r, v);
    if (
      r.revision !== 1 ||
      r.currentVersionId !== v._id ||
      r.currentVersionNumber !== 1 ||
      v.versionNumber !== 1
    )
      throw conflict();
    await this.within(transaction, async (tx) => {
      await this.resources.insertOne(r, { session: tx.session });
      await this.versions.insertOne(v, { session: tx.session });
      await this.changed(
        tx,
        {
          environment: r.environment,
          ownerType: r.ownerType,
          ownerId: r.ownerId,
        },
        r._id,
        actorId,
        "resource.create",
      );
    });
  }
  async publishVersion(
    scope: ResourceScope,
    resourceId: string,
    expectedRevision: number,
    version: ResourceVersion,
    actorId: string,
    transaction?: V2Transaction,
    metadata?: Pick<
      ResourceRecord,
      "name" | "contentType" | "valueFormat" | "schemaIdentity"
    >,
  ): Promise<void> {
    const v = structuredClone(version);
    await this.within(transaction, async (tx) => {
      const r = await this.resources.findOne(
        { _id: resourceId, ...scopeFilter(scope) },
        { session: tx.session },
      );
      if (!r || r.deletedAt !== undefined || r.revision !== expectedRevision)
        throw conflict();
      this.assertVersion({ ...r, ...metadata }, v);
      if (v.versionNumber !== r.currentVersionNumber + 1) throw conflict();
      const changed = await this.resources.updateOne(
        { _id: resourceId, ...scopeFilter(scope), revision: expectedRevision },
        {
          $set: {
            ...metadata,
            currentVersionId: v._id,
            currentVersionNumber: v.versionNumber,
          },
          $inc: { revision: 1 },
        },
        { session: tx.session },
      );
      if (changed.matchedCount !== 1) throw conflict();
      await this.versions.insertOne(v, { session: tx.session });
      await this.changed(tx, scope, resourceId, actorId, "resource.version");
    });
  }
  async revokeGrant(id: string, expectedRevision: number): Promise<boolean> {
    const result = await this.grants.updateOne(
      { _id: id, revision: expectedRevision, enabled: true },
      { $set: { enabled: false }, $inc: { revision: 1 } },
    );
    return result.matchedCount === 1;
  }
  async listResources(
    scope: ResourceScope,
    options: { limit: number; after?: string; kind?: ResourceRecord["kind"] },
  ): Promise<ResourceRecord[]> {
    if (
      !Number.isSafeInteger(options.limit) ||
      options.limit < 1 ||
      options.limit > 100
    )
      throw unavailable();
    return this.resources
      .find(
        {
          ...scopeFilter(scope),
          deletedAt: { $exists: false },
          ...(options.after ? { _id: { $gt: options.after } } : {}),
          ...(options.kind ? { kind: options.kind } : {}),
        },
        { projection: { value: 0 } },
      )
      .sort({ _id: 1 })
      .limit(options.limit)
      .toArray();
  }
  async listVersions(
    scope: ResourceScope,
    resourceId: string,
  ): Promise<Omit<ResourceVersion, "value">[]> {
    return this.versions
      .find({ ...scopeFilter(scope), resourceId }, { projection: { value: 0 } })
      .sort({ versionNumber: -1 })
      .toArray() as Promise<Omit<ResourceVersion, "value">[]>;
  }
  openVersion(scope:ResourceScope,resourceId:string,version:ResourceVersion):Buffer{const owner=scopeFilter(scope);if(version.resourceId!==resourceId||version.environment!==owner.environment||version.ownerType!==owner.ownerType||version.ownerId!==owner.ownerId)throw unavailable();return this.cipher.open(owner,resourceId,version._id,version.schemaIdentity,version.value)}
  async readValue(
    scope: ResourceScope,
    resourceId: string,
    versionId: string,
    transaction?: V2Transaction,
  ): Promise<Buffer> {
    if (transaction && !this.transactions.has(transaction)) throw unavailable();
    const version = await this.versions.findOne(
      {
        _id: versionId,
        resourceId,
        ...scopeFilter(scope),
      },
      transaction ? { session: transaction.session } : {},
    );
    if (!version) throw unavailable();
    return this.cipher.open(
      scope,
      resourceId,
      versionId,
      version.schemaIdentity,
      version.value,
    );
  }
  async close(): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      this.cipher.close();
      await this.client.close();
    }
  }
}
