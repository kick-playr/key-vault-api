import { createHash } from "node:crypto";
import { MongoClient } from "mongodb";
import { createRequire } from "node:module";
import { assertDatabaseName, databaseNames } from "./database-names.js";
import type { V2MongoStore } from "./mongo-store.js";
import type { LegacyItem, RuntimeMigrationTarget } from "./migration.js";
const { sealRuntime, openRuntime, validateRuntimeMetadata } = createRequire(import.meta.url)(
  "../../runtime-client/integration-runtime.cjs",
);
export interface RuntimeTargetConfiguration {
  tenantId: string;
  mongoUri: string;
  wrappingKeyResourceId: string;
}
/** Operator-only maintenance port. Static keys are read locally from the staged Vault, never persisted in tenant records. */
export class MongoRuntimeMigrationTarget implements RuntimeMigrationTarget {
  private readonly clients = new Map<string, MongoClient>();
  constructor(
    private readonly vault: V2MongoStore,
    private readonly configurations: readonly RuntimeTargetConfiguration[],
  ) {
    for (const c of configurations)
      assertDatabaseName(c.mongoUri, databaseNames.tenant(c.tenantId));
    if (
      new Set(configurations.map((c) => c.tenantId)).size !==
      configurations.length
    )
      throw Error("Duplicate migration tenant target");
  }
  private async target(tenantId: string) {
    const config = this.configurations.find((c) => c.tenantId === tenantId);
    if (!config) throw Error("Explicit tenant runtime target is required");
    let client = this.clients.get(tenantId);
    if (!client) {
      client = new MongoClient(config.mongoUri, {
        serverSelectionTimeoutMS: 3000,
        connectTimeoutMS: 3000,
        readConcern: { level: "majority" },
        writeConcern: { w: "majority" },
        retryWrites: false,
      });
      await client.connect();
      this.clients.set(tenantId, client);
    }
    return { client, db: client.db(databaseNames.tenant(tenantId)), config };
  }
  private async key(
    item: { environment: string; tenantId: string; keyResourceId: string },
    versionId?: string,
  ) {
    const scope = {
        environment: item.environment,
        ownerType: "tenant" as const,
        ownerId: item.tenantId,
      },
      record = await this.vault.resources.findOne({
        _id: item.keyResourceId,
        ...scope,
        kind: "encryption-key",
        enabled: true,
      });
    if (!record) throw Error("Staged tenant wrapping key is missing");
    const id = versionId ?? record.currentVersionId,
      bytes = await this.vault.readValue(scope, record._id, id);
    try {
      const key = Buffer.from(
        bytes.toString("utf8"),
        record.valueFormat === "hex64" ? "hex" : "base64",
      );
      if (key.length !== 32) {
        key.fill(0);
        throw Error("Invalid tenant wrapping key");
      }
      return { versionId: id, key };
    } finally {
      bytes.fill(0);
    }
  }
  async stage(
    jobId: string,
    item: LegacyItem,
    versions: { id: string; value: Record<string, unknown> }[],
    integrationId: string,
    staticVersion: string,
  ) {
    if (item.owner.ownerType !== "tenant")
      throw Error("Runtime credentials require tenant ownership");
    if(item.runtimeMetadata && validateRuntimeMetadata(item.runtimeMetadata).provider !== item.provider) throw Error("Runtime metadata provider mismatch");
    const { client, db, config } = await this.target(item.owner.ownerId),
      identity = {
        environment: item.owner.environment,
        tenantId: item.owner.ownerId,
        integrationId,
      },
      keyInfo = await this.key({
        ...identity,
        keyResourceId: config.wrappingKeyResourceId,
      }),
      session = client.startSession();
    try {
      await db
        .collection("integration_runtime_credentials")
        .createIndex(
          { tenantId: 1, environment: 1, integrationId: 1 },
          { unique: true, name: "runtime_integration_identity" },
        );
      await session.withTransaction(async () => {
        const id = identity.environment + "/" + integrationId,
          existing = await db
            .collection<any>("integration_runtime_credentials")
            .findOne({ _id: id }, { session });
        if (existing && existing.migrationJobId !== jobId)
          throw Error("Runtime target already contains a different authority");
        for (let i = 0; i < versions.length; i++) {
          const version = versions[i]!,
            context = {
              ...identity,
              authorityGeneration: 1,
              revision: i + 1,
              staticVersion,
            },
            value = sealRuntime(
              context,
              version.value,
              keyInfo.key,
              keyInfo.versionId,
            );
          await db
            .collection<any>("integration_refresh_operations")
            .updateOne(
              { _id: jobId + "/" + integrationId + "/" + version.id },
              {
                $setOnInsert: {
                  ...identity,
                  authorityGeneration: 1,
                  revision: i + 1,
                  staticVersion,
                  migrationJobId: jobId,
                  phase: "migrated-history",
                  value,
                },
              },
              { upsert: true, session },
            );
        }
        const current = versions.at(-1)!,
          revision = versions.length,
          context = {
            ...identity,
            authorityGeneration: 1,
            revision,
            staticVersion,
          },
          record = {
            _id: id,
            ...identity,
            authorityGeneration: 1,
            revision,
            staticVersion,
            accountReference: item.accountReference,
            status: "staged",
            ...(item.runtimeMetadata ? { metadata: validateRuntimeMetadata(item.runtimeMetadata) } : {}),
            stagedStatus: item.pendingRefresh || !item.runtimeMetadata
              ? "reauthorization-required"
              : "active",
            operation: null,
            expiresAt: current.value.expiresAt,
            value: sealRuntime(
              context,
              current.value,
              keyInfo.key,
              keyInfo.versionId,
            ),
            migrationJobId: jobId,
            migratedRevision: revision,
            keyResourceId: config.wrappingKeyResourceId,
          };
        if (existing) {
          if (existing.status !== "staged")
            throw Error("Runtime target is already active");
          await db
            .collection<any>("integration_runtime_credentials")
            .replaceOne(
              { _id: id, migrationJobId: jobId, status: "staged" },
              record,
              { session },
            );
        } else
          await db
            .collection<any>("integration_runtime_credentials")
            .insertOne(record, { session });
      });
      await this.vault.transaction((tx) =>
        tx.db
          .collection<any>("vault_migration_runtime_targets")
          .updateOne(
            { _id: jobId + "/" + identity.tenantId + "/" + integrationId },
            {
              $set: {
                jobId,
                ...identity,
                keyResourceId: config.wrappingKeyResourceId,
                versions: versions.length,
                metadataDigest: createHash("sha256").update(JSON.stringify(item.runtimeMetadata ?? null)).digest("hex"),
              },
            },
            { upsert: true, session: tx.session },
          ),
      );
    } finally {
      keyInfo.key.fill(0);
      await session.endSession();
    }
  }
  private rows(jobId: string) {
    return this.vault.transaction((tx) =>
      tx.db
        .collection<any>("vault_migration_runtime_targets")
        .find({ jobId }, { session: tx.session })
        .toArray(),
    );
  }
  async verify(jobId: string) {
    for (const target of await this.rows(jobId)) {
      const { db } = await this.target(target.tenantId),
        record = await db
          .collection<any>("integration_runtime_credentials")
          .findOne({
            _id: target.environment + "/" + target.integrationId,
            migrationJobId: jobId,
          });
      if (
        !record ||
        !["staged", "active", "reauthorization-required"].includes(
          record.status,
        ) ||
        record.revision !== target.versions ||
        createHash("sha256").update(JSON.stringify(record.metadata ?? null)).digest("hex") !== target.metadataDigest
      )
        throw Error("Runtime migration is incomplete");
      const history = await db
        .collection<any>("integration_refresh_operations")
        .find({
          migrationJobId: jobId,
          integrationId: target.integrationId,
          tenantId: target.tenantId,
          environment: target.environment,
        })
        .toArray();
      if (history.length !== target.versions)
        throw Error("Runtime history is incomplete");
      for (const row of [record, ...history]) {
        const key = await this.key(target, row.value.keyVersion);
        try {
          const value = openRuntime(
            row,
            row.value,
            new Map([[key.versionId, key.key]]),
          );
          if (!value.accessToken || !value.refreshToken)
            throw Error("Runtime value verification failed");
        } finally {
          key.key.fill(0);
        }
      }
    }
  }
  async activate(jobId: string) {
    for (const target of await this.rows(jobId)) {
      const { db } = await this.target(target.tenantId),
        id = target.environment + "/" + target.integrationId;
      const record = await db
        .collection<any>("integration_runtime_credentials")
        .findOne({ _id: id, migrationJobId: jobId });
      if (!record) throw Error("Runtime migration is incomplete");
      if (record.status === "staged")
        await db
          .collection<any>("integration_runtime_credentials")
          .updateOne(
            { _id: id, migrationJobId: jobId, status: "staged" },
            { $set: { status: record.stagedStatus } },
            { writeConcern: { w: "majority" } },
          );
    }
  }
  async hasPostCutoverWrites(jobId: string) {
    for (const target of await this.rows(jobId)) {
      const { db } = await this.target(target.tenantId),
        record = await db
          .collection<any>("integration_runtime_credentials")
          .findOne({
            _id: target.environment + "/" + target.integrationId,
            migrationJobId: jobId,
          });
      if (record && record.revision !== record.migratedRevision) return true;
    }
    return false;
  }
  async rollback(jobId: string) {
    if (await this.hasPostCutoverWrites(jobId))
      throw Error("Runtime authority has changed");
    for (const target of await this.rows(jobId)) {
      const { db } = await this.target(target.tenantId);
      await db
        .collection<any>("integration_runtime_credentials")
        .deleteOne({
          _id: target.environment + "/" + target.integrationId,
          migrationJobId: jobId,
          status: "staged",
        });
      await db
        .collection("integration_refresh_operations")
        .deleteMany({
          migrationJobId: jobId,
          integrationId: target.integrationId,
          environment: target.environment,
          tenantId: target.tenantId,
          phase: "migrated-history",
        });
    }
  }
  async close() {
    await Promise.all(
      [...this.clients.values()].map((client) => client.close()),
    );
    this.clients.clear();
  }
}
