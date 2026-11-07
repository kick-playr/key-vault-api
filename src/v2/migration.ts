import { createRequire } from "node:module";
import type { RuntimeLifecycleMetadata } from "../../runtime-client/integration-runtime.cjs";
import { effectiveCustody } from "./resource-custody.js";
import { createHmac, randomUUID } from "node:crypto";
import { scopeFilter, type V2MongoStore } from "./mongo-store.js";
import { databaseNames } from "./database-names.js";
import { IntegrationSchemas } from "./integration-schemas.js";
import { validateSecretValueFormat } from "../secret-value-format.js";
import type {
  ResourceScope,
  ResourceRecord,
  ResourceVersion,
} from "./records.js";
const { validateRuntimeMetadata } = createRequire(import.meta.url)("../../runtime-client/integration-runtime.cjs");
export interface IntegrationValueMapping {
  rename?: { user?: "username"; fromAddress?: "sender"; inbox?: "inboxFolder"; archive?: "archiveFolder" };
  defaults?: { protocol?: "smtp" | "imap"; tls?: "implicit" | "starttls" | "none" };
  metadataOnly?: readonly "mailboxId"[];
}
export type LegacyItem = {
  disposition?: "retain-legacy-backup";
  retentionReason?: string;
  valueMapping?: IntegrationValueMapping;
  databaseTarget?: string;
  sourceId: string;
  revision: number;
  owner: ResourceScope;
  name: string;
  kind: "secret" | "encryption-key" | "integration";
  provider?: "bexio" | "dropbox" | "email" | "pingen";
  accountReference?: string;
  valueFormat?: "text" | "base64" | "hex64";
  custody?: "admin-managed" | "workload-only";
  pendingRefresh?: boolean;
  runtimeMetadata?: RuntimeLifecycleMetadata;
  schemaIdentity?: string;
  versions: { id: string; value: unknown }[];
};
export interface MigrationSource {
  inventory(): Promise<LegacyItem[]>;
}
export interface RuntimeMigrationTarget {
  stage(
    jobId: string,
    item: LegacyItem,
    versions: { id: string; value: Record<string, unknown> }[],
    staticResourceId: string,
    staticVersionId: string,
  ): Promise<void>;
  verify(jobId: string): Promise<void>;
  activate(jobId: string): Promise<void>;
  rollback(jobId: string): Promise<void>;
  hasPostCutoverWrites(jobId: string): Promise<boolean>;
}
export interface CutoverEvidence {
  assertLegacyWritersFenced(): Promise<void>;
  assertLegacyReadersFenced(): Promise<void>;
  assertFreshGrantsDelivered(): Promise<void>;
  assertTenantEnrollmentApproved(): Promise<void>;
  assertConsumersStopped(): Promise<void>;
}
export function canonicalApplication(id: string) {
  return id === "app" ? "club-app" : id === "explorer" ? "explorer-app" : id;
}
function normalizedIntegration(input: Record<string, unknown>, mapping: IntegrationValueMapping | undefined, accountReference?: string) {
  const data = { ...input };
  if (!mapping) return data;
  const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
  if (!object(mapping) || Object.keys(mapping).some(k => !["rename", "defaults", "metadataOnly"].includes(k))) throw Error("Invalid reviewed value mapping");
  const aliases: Record<string, string> = {user:"username",fromAddress:"sender",inbox:"inboxFolder",archive:"archiveFolder"};
  if (mapping.rename !== undefined) {
    if (!object(mapping.rename)) throw Error("Invalid reviewed aliases");
    for (const [from, to] of Object.entries(mapping.rename)) {
      if (typeof to !== "string" || aliases[from] !== to) throw Error("Invalid reviewed aliases");
      if (Object.hasOwn(data, from)) {
        if (Object.hasOwn(data, to)) throw Error("Integration alias collision");
        data[to] = data[from]; delete data[from];
      }
    }
  }
  if (mapping.defaults !== undefined) {
    if (!object(mapping.defaults) || Object.entries(mapping.defaults).some(([key,value]) => key === "protocol" ? !["smtp","imap"].includes(String(value)) : key === "tls" ? !["implicit","starttls","none"].includes(String(value)) : true)) throw Error("Invalid reviewed nonsecret defaults");
    for (const [key,value] of Object.entries(mapping.defaults)) {
      if (Object.hasOwn(data,key) && data[key] !== value) throw Error("Integration default collision");
      if (!Object.hasOwn(data,key)) data[key] = value;
    }
  }
  if (mapping.metadataOnly !== undefined) {
    if (!Array.isArray(mapping.metadataOnly) || new Set(mapping.metadataOnly).size !== mapping.metadataOnly.length || mapping.metadataOnly.some(key => key !== "mailboxId")) throw Error("Invalid reviewed metadata fields");
    if (mapping.metadataOnly.includes("mailboxId") && Object.hasOwn(data,"mailboxId")) {
      if (typeof data.mailboxId !== "string" || !data.mailboxId || (accountReference !== undefined && data.mailboxId !== accountReference)) throw Error("Reviewed mailbox account mismatch");
      delete data.mailboxId;
    }
  }
  return data;
}
export function classifyIntegration(
  provider: string,
  input: unknown,
  accountReference?: string,
  selectedSchema?: string,
  valueMapping?: IntegrationValueMapping,
) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw Error("Unclassified integration payload");
  const schemaIdentity=selectedSchema ?? "builtin:"+provider+"@1";
  if(schemaIdentity !== "builtin:"+provider+"@1" && !(["email","pingen"].includes(provider) && schemaIdentity === "builtin:"+provider+"@2")) throw Error("Unsupported reviewed integration schema");
  const data = normalizedIntegration(input as Record<string, unknown>, valueMapping, accountReference),
    runtimeKeys = [
      "accessToken",
      "refreshToken",
      "expiresAt",
      "idToken",
      "tokenType",
    ],
    staticKeys =
      provider === "bexio"
        ? ["clientId", "clientSecret", "redirectUri"]
        : provider === "dropbox"
          ? ["clientId", "clientSecret", "redirectUri", "archiveRoot"]
          : provider === "pingen"
            ? ["apiToken", "organizationId", "apiOrigin", ...(schemaIdentity === "builtin:pingen@2" ? ["webhookSecret"] : [])]
            : provider === "email"
              ? [
                  "protocol",
                  "host",
                  "port",
                  "tls",
                  "username",
                  "password",
                  "sender",
                  ...(schemaIdentity === "builtin:email@2" ? ["inboxFolder","archiveFolder"] : []),
                ]
              : [];
  if (
    !staticKeys.length ||
    Object.keys(data).some((k) => ![...staticKeys, ...runtimeKeys].includes(k))
  )
    throw Error("Unclassified integration fields");
  const staticValue = Object.fromEntries(
    Object.entries(data).filter(([key]) => staticKeys.includes(key)),
  );
  if (["bexio", "dropbox"].includes(provider)) {
    if (!accountReference) throw Error("Expected provider account is required");
    staticValue.accountReference = accountReference;
  }
  new IntegrationSchemas().validate(schemaIdentity, staticValue);
  const runtimeValue = Object.fromEntries(
    Object.entries(data).filter(([key]) => runtimeKeys.includes(key)),
  );
  if (Object.keys(runtimeValue).length) {
    if (
      typeof runtimeValue.accessToken !== "string" ||
      !runtimeValue.accessToken ||
      typeof runtimeValue.refreshToken !== "string" ||
      !runtimeValue.refreshToken ||
      !Number.isSafeInteger(runtimeValue.expiresAt)
    )
      throw Error("Unclassified runtime credentials");
  }
  return {
    staticValue,
    schemaIdentity,
    runtimeValue: Object.keys(runtimeValue).length ? runtimeValue : undefined,
  };
}
function checked(items: LegacyItem[]) {
  if (!Array.isArray(items) || items.length > 10000)
    throw Error("Migration inventory exceeds limits");
  const ids = new Set();
  for (const item of items) {
    item.owner = scopeFilter(item.owner);
    if (
      !item.sourceId ||
      ids.has(item.sourceId) ||
      !Number.isSafeInteger(item.revision) ||
      item.revision < 0 ||
      !item.name ||
      !Array.isArray(item.versions) ||
      !item.versions.length ||
      item.versions.length > 1000
    )
      throw Error("Invalid migration inventory");
    if (
      item.custody !== undefined &&
      !["admin-managed", "workload-only"].includes(item.custody)
    )
      throw Error("Invalid custody classification");
    if (
      item.owner.ownerType === "application" &&
      item.kind === "encryption-key" &&
      item.custody === "admin-managed"
    )
      throw Error("Application keys require workload-only custody");
    if (item.disposition !== undefined && item.disposition !== "retain-legacy-backup") throw Error("Invalid migration disposition");
    if (item.disposition === "retain-legacy-backup") {
      if (typeof item.retentionReason !== "string" || !item.retentionReason.trim() || item.retentionReason.length > 1000 || /[\x00-\x1f\x7f]/.test(item.retentionReason)) throw Error("Explicit retention reason is required");
      if (item.valueMapping !== undefined || item.runtimeMetadata !== undefined || item.databaseTarget !== undefined) throw Error("Retained backups cannot have active value mappings");
    } else if (item.retentionReason !== undefined) throw Error("A retention reason requires a backup disposition");
    if (item.valueMapping !== undefined && item.kind !== "integration") throw Error("Value mappings require an integration");
    if (item.runtimeMetadata !== undefined) {
      const metadata = validateRuntimeMetadata(item.runtimeMetadata);
      if(item.kind !== "integration" || metadata.provider !== item.provider) throw Error("Invalid runtime lifecycle mapping");
      item.runtimeMetadata=metadata;
    }
    ids.add(item.sourceId);
    if (item.owner.ownerType === "application")
      item.owner = {
        ...item.owner,
        ownerId: canonicalApplication(item.owner.ownerId),
      };
    if (!["secret", "encryption-key", "integration"].includes(item.kind))
      throw Error("Unclassified resource");
    for (const version of item.versions) {
      if (!version.id) throw Error("Invalid source version");
      if (item.disposition === "retain-legacy-backup") continue;
      if (item.kind === "integration") {
        const split=classifyIntegration(item.provider!, version.value, item.accountReference, item.schemaIdentity, item.valueMapping);
        if(split.runtimeValue && item.owner.ownerType !== "tenant") throw Error("Runtime credentials require an explicit tenant owner");
      }
      else {
        if (typeof version.value !== "string")
          throw Error("Unclassified scalar value");
        validateSecretValueFormat(version.value, item.valueFormat ?? "text");
        if (
          item.kind === "encryption-key" &&
          !["base64", "hex64"].includes(item.valueFormat ?? "")
        )
          throw Error("Explicit key encoding is required");
      }
    }
  }
  return items;
}
const digest = (items: LegacyItem[], reviewKey: Buffer) => {
  if (reviewKey.length !== 32)
    throw Error("A private migration review key is required");
  return createHmac("sha256", reviewKey)
    .update(JSON.stringify(items))
    .digest("hex");
};
export async function previewMigration(
  source: MigrationSource,
  reviewKey: Buffer,
) {
  const items = checked(structuredClone(await source.inventory()));
  const active = items.filter(item => item.disposition !== "retain-legacy-backup");
  const retained = items.filter(item => item.disposition === "retain-legacy-backup");
  return {
    digest: digest(items, reviewKey),
    databases: {
      vault: databaseNames.vault,
      control: databaseNames.control,
      tenants: [
        ...new Set(
          items
            .filter((i) => i.owner.ownerType === "tenant")
            .map((i) => databaseNames.tenant(i.owner.ownerId)),
        ),
      ],
    },
    counts: {
      retainedBackups: retained.length,
      retainedVersions: retained.reduce((n,i) => n + i.versions.length, 0),
      resources: active.length,
      staticVersions: active.reduce((n, i) => n + i.versions.length, 0),
      runtimeVersions: active.reduce(
        (n, i) =>
          n +
          (i.kind === "integration"
            ? i.versions.filter(
                (v) =>
                  classifyIntegration(i.provider!, v.value, i.accountReference, i.schemaIdentity, i.valueMapping)
                    .runtimeValue,
              ).length
            : 0),
        0,
      ),
    },
    retainedBackups: retained.map(i => ({sourceId:i.sourceId,owner:i.owner,name:i.name,kind:i.kind,retentionReason:i.retentionReason!,versions:i.versions.length})),
    items: active.map((i) => ({
      sourceId: i.sourceId,
      owner: i.owner,
      name: i.name,
      kind: i.kind,
      custody: effectiveCustody({
        ...i.owner,
        kind: i.kind,
        custody: i.custody,
      }),
      versions: i.versions.length,
      requiresReauthorization: !!i.pendingRefresh || (i.kind === "integration" && !i.runtimeMetadata && i.versions.some(v=>!!classifyIntegration(i.provider!,v.value,i.accountReference,i.schemaIdentity,i.valueMapping).runtimeValue)),
    })),
  };
}
export class MigrationService {
  constructor(
    private readonly store: V2MongoStore,
    private readonly source: MigrationSource,
    private readonly runtime: RuntimeMigrationTarget,
    private readonly reviewKey: Buffer,
  ) {}
  private id(sourceId: string, suffix = "") {
    return createHmac("sha256", this.reviewKey)
      .update(sourceId + "\0" + suffix)
      .digest("hex")
      .slice(0, 32);
  }
  private retentionEntry(jobId: string, item: LegacyItem) {
    return {_id:jobId+"/"+this.id(item.sourceId),jobId,sourceId:item.sourceId,sourceRevision:item.revision,owner:item.owner,name:item.name,kind:item.kind,disposition:"retain-legacy-backup",retentionReason:item.retentionReason!,sourceVersionIds:item.versions.map(version=>version.id),sourceDigest:digest([item],this.reviewKey)};
  }
  async stage(reviewedDigest: string, jobId: string = randomUUID()) {
    if (
      await this.store.transaction((tx) =>
        tx.db
          .collection<any>("vault_platform_settings")
          .findOne(
            { _id: "v2-authority", enabled: true },
            { session: tx.session },
          ),
      )
    )
      throw Error("Active Vault requires a new maintenance window");
    const inventory = checked(structuredClone(await this.source.inventory()));
    if (digest(inventory, this.reviewKey) !== reviewedDigest)
      throw Error("Migration source changed");
    await this.store.transaction(async (tx) => {
      const jobs = tx.db.collection<any>("vault_migration_jobs"),
        existing = await jobs.findOne({ _id: jobId }, { session: tx.session });
      if (
        existing &&
        (existing.digest !== reviewedDigest ||
          !["staging", "staged"].includes(existing.phase))
      )
        throw Error("Migration job conflict");
      await jobs.updateOne(
        { _id: jobId },
        {
          $setOnInsert: {
            digest: reviewedDigest,
            phase: "staging",
            createdAt: Date.now(),
          },
        },
        { upsert: true, session: tx.session },
      );
    });
    for (const item of inventory) {
      if (item.disposition === "retain-legacy-backup") {
        await this.store.transaction(async tx => {
          const resourceId = this.id(item.sourceId), ledger = tx.db.collection<any>("vault_migration_retained_backups");
          if (await this.store.resources.findOne({_id:resourceId},{session:tx.session}) || await this.store.versions.findOne({resourceId},{session:tx.session})) throw Error("Retained backup has an active migration target");
          const entry = this.retentionEntry(jobId,item);
          const existing = await ledger.findOne({_id:entry._id},{session:tx.session});
          if (existing) {
            if (JSON.stringify(existing) !== JSON.stringify(entry)) throw Error("Migration retention ledger conflict");
          } else await ledger.insertOne(entry,{session:tx.session});
        });
        continue;
      }
      const resourceId = this.id(item.sourceId),
        runtimeVersions: { id: string; value: Record<string, unknown> }[] = [];
      for (let index = 0; index < item.versions.length; index++) {
        const sourceVersion = item.versions[index]!,
          versionId = this.id(item.sourceId, sourceVersion.id),
          split =
            item.kind === "integration"
              ? classifyIntegration(
                  item.provider!,
                  sourceVersion.value,
                  item.accountReference,
                  item.schemaIdentity,
                  item.valueMapping,
                )
              : undefined;
        if (split?.runtimeValue)
          runtimeVersions.push({
            id: sourceVersion.id,
            value: split.runtimeValue,
          });
        const staticValue = split?.staticValue ?? sourceVersion.value,
          bytes = Buffer.from(
            typeof staticValue === "string"
              ? staticValue
              : JSON.stringify(staticValue),
          ),
          schemaIdentity =
            item.kind === "integration"
              ? split!.schemaIdentity
              : item.kind + ":" + (item.valueFormat ?? "text") + "@1";
        try {
          await this.store.transaction(async (tx) => {
            const items = tx.db.collection<any>("vault_migration_items"),
              entryId = jobId + "/" + resourceId + "/" + versionId;
            if (
              await items.findOne(
                { _id: entryId, verified: true },
                { session: tx.session },
              )
            )
              return;
            const existing = await this.store.resources.findOne(
              { _id: resourceId },
              { session: tx.session },
            );
            if (
              existing &&
              !(await items.findOne(
                { jobId, resourceId },
                { session: tx.session },
              ))
            )
              throw Error("Migration target already exists");
            const record: ResourceRecord = {
                custody: effectiveCustody({
                  ...item.owner,
                  kind: item.kind,
                  custody: item.custody,
                }),
                ...item.owner,
                _id: resourceId,
                name: item.name,
                kind: item.kind,
                contentType:
                  item.kind === "integration"
                    ? "application/json"
                    : "text/plain",
                valueFormat: item.valueFormat ?? "text",
                schemaIdentity,
                enabled: true,
                revision: index + 1,
                currentVersionId: versionId,
                currentVersionNumber: index + 1,
              },
              version: ResourceVersion = {
                ...item.owner,
                _id: versionId,
                resourceId,
                versionNumber: index + 1,
                kind: record.kind,
                contentType: record.contentType,
                valueFormat: record.valueFormat,
                schemaIdentity,
                createdAt: Date.now(),
                createdBy: "migration:" + jobId,
                value: this.store.sealValue(
                  item.owner,
                  resourceId,
                  versionId,
                  schemaIdentity,
                  bytes,
                ),
              };
            if (!existing)
              await this.store.createResource(
                record,
                version,
                "migration:" + jobId,
                tx,
              );
            else
              await this.store.publishVersion(
                item.owner,
                resourceId,
                index,
                version,
                "migration:" + jobId,
                tx,
              );
            const decoded = await this.store.readValue(
              item.owner,
              resourceId,
              versionId,
              tx,
            );
            try {
              if (!decoded.equals(bytes))
                throw Error("Migration value verification failed");
            } finally {
              decoded.fill(0);
            }
            await items.insertOne(
              {
                _id: entryId,
                jobId,
                sourceId: item.sourceId,
                sourceRevision: item.revision,
                sourceVersionId: sourceVersion.id,
                resourceId,
                versionId,
                verified: true,
              },
              { session: tx.session },
            );
          });
        } finally {
          bytes.fill(0);
        }
      }
      if (runtimeVersions.length)
        await this.runtime.stage(
          jobId,
          item,
          runtimeVersions,
          resourceId,
          this.id(item.sourceId, item.versions.at(-1)!.id),
        );
    }
    await this.store.transaction((tx) =>
      tx.db
        .collection<any>("vault_migration_jobs")
        .updateOne(
          { _id: jobId, digest: reviewedDigest, phase: "staging" },
          { $set: { phase: "staged" } },
          { session: tx.session },
        ),
    );
    return { jobId, phase: "staged" };
  }
  async verify(jobId: string) {
    const preview = await previewMigration(this.source, this.reviewKey);
    const job = await this.store.transaction((tx) =>
      tx.db
        .collection<any>("vault_migration_jobs")
        .findOne({ _id: jobId }, { session: tx.session }),
    );
    if (
      !job ||
      !["staged", "verified", "activation-pending"].includes(job.phase) ||
      job.digest !== preview.digest
    )
      throw Error("Migration source changed or stage incomplete");
    const inventory = checked(structuredClone(await this.source.inventory()));
    if (digest(inventory,this.reviewKey) !== job.digest) throw Error("Migration source changed");
    for (const item of inventory) {
      if (item.disposition === "retain-legacy-backup") {
        const expected=this.retentionEntry(jobId,item),resourceId=this.id(item.sourceId);
        const actual=await this.store.transaction(tx=>tx.db.collection<any>("vault_migration_retained_backups").findOne({_id:expected._id},{session:tx.session}));
        if (!actual || JSON.stringify(actual)!==JSON.stringify(expected)) throw Error("Migration retention verification failed");
        if (await this.store.resources.findOne({_id:resourceId}) || await this.store.versions.findOne({resourceId})) throw Error("Retained backup has an active migration target");
        continue;
      }
      const head = await this.store.resources.findOne({
        _id: this.id(item.sourceId),
        ...item.owner,
      });
      if (
        !head ||
        head.name !== item.name ||
        head.kind !== item.kind ||
        !head.enabled ||
        head.deletedAt !== undefined ||
        head.custody !==
          effectiveCustody({
            ...item.owner,
            kind: item.kind,
            custody: item.custody,
          }) ||
        head.currentVersionNumber !== item.versions.length ||
        head.currentVersionId !==
          this.id(item.sourceId, item.versions.at(-1)!.id)
      )
        throw Error("Migration metadata verification failed");
      for (const version of item.versions) {
        const split =
            item.kind === "integration"
              ? classifyIntegration(
                  item.provider!,
                  version.value,
                  item.accountReference,
                  item.schemaIdentity,
                  item.valueMapping,
                )
              : undefined,
          expected = split?.staticValue ?? version.value,
          bytes = Buffer.from(
            typeof expected === "string" ? expected : JSON.stringify(expected),
          );
        const resourceId = this.id(item.sourceId),
          versionId = this.id(item.sourceId, version.id);
        const actual = await this.store.readValue(
          item.owner,
          resourceId,
          versionId,
        );
        try {
          if (!actual.equals(bytes))
            throw Error("Migration value verification failed");
        } finally {
          actual.fill(0);
          bytes.fill(0);
        }
      }
    }
    const count = await this.store.transaction((tx) =>
      tx.db
        .collection("vault_migration_items")
        .countDocuments({ jobId, verified: true }, { session: tx.session }),
    );
    const retainedCount=await this.store.transaction(tx=>tx.db.collection("vault_migration_retained_backups").countDocuments({jobId},{session:tx.session}));
    if (retainedCount !== preview.counts.retainedBackups) throw Error("Migration retention stage incomplete");
    if (count !== preview.counts.staticVersions)
      throw Error("Migration stage incomplete");
    await this.runtime.verify(jobId);
    await this.store.transaction((tx) =>
      tx.db
        .collection<any>("vault_migration_jobs")
        .updateOne(
          { _id: jobId, phase: { $in: ["staged", "verified"] } },
          { $set: { phase: "verified", verifiedAt: Date.now() } },
          { session: tx.session },
        ),
    );
    return { jobId, phase: "verified" };
  }
  async activate(jobId: string, evidence: CutoverEvidence) {
    await this.verify(jobId);
    await evidence.assertConsumersStopped();
    await evidence.assertLegacyWritersFenced();
    await evidence.assertLegacyReadersFenced();
    await evidence.assertFreshGrantsDelivered();
    await evidence.assertTenantEnrollmentApproved();
    await this.verify(jobId);
    await this.store.transaction((tx) =>
      tx.db
        .collection<any>("vault_migration_jobs")
        .updateOne(
          { _id: jobId, phase: { $in: ["verified", "activation-pending"] } },
          { $set: { phase: "activation-pending" } },
          { session: tx.session },
        ),
    );
    await this.runtime.activate(jobId);
    return this.store.transaction(async (tx) => {
      const job = await tx.db
        .collection<any>("vault_migration_jobs")
        .findOne(
          { _id: jobId, phase: "activation-pending" },
          { session: tx.session },
        );
      if (!job) throw Error("Migration job conflict");
      await tx.db.collection<any>("vault_platform_settings").updateOne(
        { _id: "v2-authority" },
        {
          $set: {
            jobId,
            enabled: true,
            verified: true,
            legacyWritersFenced: true,
            legacyReadersFenced: true,
          },
        },
        { upsert: true, session: tx.session },
      );
      await tx.db
        .collection<any>("vault_migration_jobs")
        .updateOne(
          { _id: jobId, phase: "activation-pending" },
          { $set: { phase: "active", activatedAt: Date.now() } },
          { session: tx.session },
        );
      return { jobId, phase: "active" };
    });
  }
  async rollback(jobId: string) {
    const job = await this.store.transaction((tx) =>
      tx.db
        .collection<any>("vault_migration_jobs")
        .findOne({ _id: jobId }, { session: tx.session }),
    );
    if (
      !job ||
      job.phase === "active" ||
      (await this.runtime.hasPostCutoverWrites(jobId))
    )
      throw Error("Post-cutover rollback requires a new coordinated migration");
    await this.runtime.rollback(jobId);
    return this.store.transaction(async (tx) => {
      await tx.db
        .collection<any>("vault_migration_jobs")
        .updateOne(
          { _id: jobId, phase: { $ne: "active" } },
          { $set: { phase: "rolled-back" } },
          { session: tx.session },
        );
      return { jobId, phase: "rolled-back" };
    });
  }
}
