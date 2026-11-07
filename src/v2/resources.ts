import { hasWorkloadOperator } from "./workload-operator.js";
import {
  assertAdministrativeValueAccess,
  effectiveCustody,
} from "./resource-custody.js";
import { ensureSchema } from "./schema-store.js";
import { randomUUID, randomBytes } from "node:crypto";
import { Authorization, AccessDenied, type Actor } from "./authorization.js";
import { V2MongoStore, scopeFilter } from "./mongo-store.js";
import { IntegrationSchemas } from "./integration-schemas.js";
import type {
  AuditRecord,
  ResourceKind,
  ResourceRecord,
  ResourceScope,
  ResourceVersion,
} from "./records.js";
import {
  validateSecretValueFormat,
  type SecretValueFormat,
} from "../secret-value-format.js";
export interface ResourceInput {
  name: string;
  kind: ResourceKind;
  value: unknown;
  schemaIdentity?: string;
  valueFormat?: SecretValueFormat;
}
export class ResourceService {
  constructor(
    private readonly store: V2MongoStore,
    private readonly authorization: Authorization,
    private readonly schemas: IntegrationSchemas,
  ) {}
  private async ownerFence(
    scope: ResourceScope,
    tx: import("./mongo-store.js").V2Transaction,
  ) {
    const collection = tx.db.collection(
        scope.ownerType === "tenant"
          ? "vault_tenant_environments"
          : "vault_application_environments",
      ),
      filter = {
        environment: scope.environment,
        [scope.ownerType === "tenant" ? "tenantId" : "applicationId"]:
          scope.ownerId,
        enabled: true,
      };
    const result = await collection.updateOne(
      filter,
      { $inc: { resourceFence: 1 } },
      { session: tx.session },
    );
    if (result.matchedCount !== 1) throw Error("Resource owner is unavailable");
  }
  private async prepare(
    scope: ResourceScope,
    input: ResourceInput,
  ): Promise<{
    bytes: Buffer;
    contentType: string;
    valueFormat: SecretValueFormat;
    schemaIdentity: string;
  }> {
    if (
      !input ||
      typeof input.name !== "string" ||
      !input.name.trim() ||
      input.name.length > 128 ||
      /[\x00-\x1f\x7f]/.test(input.name) ||
      !["secret", "integration", "encryption-key"].includes(input.kind)
    )
      throw Error("Invalid static resource");
    if (input.kind === "integration") {
      const identity = input.schemaIdentity;
      if (
        !identity ||
        (!identity.startsWith("builtin:") &&
          !identity.startsWith(
            `custom:${scope.environment}:${scope.ownerType}:${scope.ownerId}:`,
          ))
      )
        throw new AccessDenied();
      await ensureSchema(this.store, this.schemas, scope, identity);
      const value = this.schemas.validate(identity, input.value);
      return {
        bytes: Buffer.from(JSON.stringify(value)),
        contentType: "application/json",
        valueFormat: "text",
        schemaIdentity: identity,
      };
    }
    if (typeof input.value !== "string")
      throw Error("Invalid static resource value");
    const format = validateSecretValueFormat(
      input.value,
      input.valueFormat ?? "text",
    );
    if (input.kind === "encryption-key") {
      if (!["base64", "hex64"].includes(format))
        throw Error("Encryption key encoding is required");
      const decoded = Buffer.from(
        input.value,
        format === "hex64" ? "hex" : "base64",
      );
      try {
        if (decoded.length !== 32)
          throw Error("A 256-bit encryption key is required");
      } finally {
        decoded.fill(0);
      }
    }
    return {
      bytes: Buffer.from(input.value),
      contentType: "text/plain",
      valueFormat: format,
      schemaIdentity: input.kind + ":" + format + "@1",
    };
  }
  async create(
    actor: Actor,
    owner: ResourceScope,
    input: ResourceInput,
  ): Promise<ResourceRecord> {
    const scope = scopeFilter(owner),
      permit = await this.authorization.require(
        actor,
        "resources:write",
        scope,
      ),
      prepared = await this.prepare(scope, input),
      id = randomUUID(),
      versionId = randomUUID();
    try {
      // Interactive creation knows the supplied value; protected application keys
      // are provisioned only through the deployment/operator path.
      assertAdministrativeValueAccess(
        { ...scope, kind: input.kind, custody: "admin-managed" },
        actor,
      );
      const resource: ResourceRecord = {
        custody: hasWorkloadOperator(actor, scope)
          ? "workload-only"
          : effectiveCustody({
              ...scope,
              kind: input.kind,
              custody: "admin-managed",
            }),
        ...scope,
        _id: id,
        name: input.name.trim(),
        kind: input.kind,
        contentType: prepared.contentType,
        valueFormat: prepared.valueFormat,
        schemaIdentity: prepared.schemaIdentity,
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
        kind: resource.kind,
        contentType: resource.contentType,
        valueFormat: resource.valueFormat,
        schemaIdentity: resource.schemaIdentity,
        createdAt: Date.now(),
        createdBy: actor.issuer + "|" + actor.subject,
        value: this.store.sealValue(
          scope,
          id,
          versionId,
          prepared.schemaIdentity,
          prepared.bytes,
        ),
      };
      await this.store.transaction(async (tx) => {
        await this.authorization.fence(permit, tx);
        await this.ownerFence(scope, tx);
        await this.store.createResource(
          resource,
          version,
          version.createdBy,
          tx,
        );
      });
      return resource;
    } finally {
      prepared.bytes.fill(0);
    }
  }
  async update(
    actor: Actor,
    owner: ResourceScope,
    resourceId: string,
    expectedRevision: number,
    input: ResourceInput,
  ): Promise<ResourceRecord> {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)
      throw Error("Vault document conflict");
    const scope = scopeFilter(owner),
      permit = await this.authorization.require(
        actor,
        "resources:write",
        scope,
      );
    if (input.kind === "encryption-key")
      throw Error("Use the coordinated key rotation workflow");
    const prepared = await this.prepare(scope, input),
      versionId = randomUUID();
    try {
      return await this.store.transaction(async (tx) => {
        await this.authorization.fence(permit, tx);
        await this.ownerFence(scope, tx);
        const previous = await this.store.resources.findOne(
          {
            _id: resourceId,
            ...scope,
            revision: expectedRevision,
            deletedAt: { $exists: false },
          },
          { session: tx.session },
        );
        if (!previous || previous.kind !== input.kind)
          throw Error("Vault document conflict");
        assertAdministrativeValueAccess(previous, actor);
        const metadata = {
          name: input.name.trim(),
          contentType: prepared.contentType,
          valueFormat: prepared.valueFormat,
          schemaIdentity: prepared.schemaIdentity,
        };
        const version: ResourceVersion = {
          ...scope,
          _id: versionId,
          resourceId,
          versionNumber: previous.currentVersionNumber + 1,
          kind: previous.kind,
          contentType: prepared.contentType,
          valueFormat: prepared.valueFormat,
          schemaIdentity: prepared.schemaIdentity,
          createdAt: Date.now(),
          createdBy: actor.issuer + "|" + actor.subject,
          value: this.store.sealValue(
            scope,
            resourceId,
            versionId,
            prepared.schemaIdentity,
            prepared.bytes,
          ),
        };
        await this.store.publishVersion(
          scope,
          resourceId,
          expectedRevision,
          version,
          version.createdBy,
          tx,
          metadata,
        );
        return {
          ...previous,
          ...metadata,
          revision: expectedRevision + 1,
          currentVersionId: versionId,
          currentVersionNumber: version.versionNumber,
        };
      });
    } finally {
      prepared.bytes.fill(0);
    }
  }
  async remove(
    actor: Actor,
    owner: ResourceScope,
    resourceId: string,
    expectedRevision: number,
    confirmation: string,
  ): Promise<void> {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)
      throw Error("Vault document conflict");
    const scope = scopeFilter(owner),
      permit = await this.authorization.require(
        actor,
        "resources:write",
        scope,
      );
    await this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await this.ownerFence(scope, tx);
      const resource = await this.store.resources.findOne(
        {
          _id: resourceId,
          ...scope,
          revision: expectedRevision,
          deletedAt: { $exists: false },
        },
        { session: tx.session },
      );
      if (!resource || resource.name !== confirmation)
        throw Error("Vault document conflict");
      assertAdministrativeValueAccess(resource, actor);
      if (resource.kind === "encryption-key")
        throw Error("Use the coordinated key retirement workflow");
      if (
        await this.store.links.findOne(
          { resourceId, environment: scope.environment },
          { session: tx.session },
        )
      )
        throw Error("Resource is in use");
      const changed = await this.store.resources.updateOne(
        {
          _id: resourceId,
          ...scope,
          revision: expectedRevision,
          deletedAt: { $exists: false },
        },
        {
          $set: { enabled: false, deletedAt: Date.now() },
          $inc: { revision: 1 },
        },
        { session: tx.session },
      );
      if (changed.matchedCount !== 1) throw Error("Vault document conflict");
      await tx.db.collection<AuditRecord>("vault_audit_events").insertOne(
        {
          _id: randomUUID(),
          ...scope,
          actorId: actor.issuer + "|" + actor.subject,
          action: "resource.delete",
          targetId: resourceId,
          at: Date.now(),
        },
        { session: tx.session },
      );
      await tx.db
        .collection("vault_change_heads")
        .updateOne(
          { ...scope },
          { $inc: { revision: 1 } },
          { upsert: true, session: tx.session },
        );
    });
  }
  async setEnabled(
    actor: Actor,
    owner: ResourceScope,
    id: string,
    expectedRevision: number,
    enabled: boolean,
  ) {
    const scope = scopeFilter(owner);
    if (
      typeof enabled !== "boolean" ||
      !Number.isSafeInteger(expectedRevision) ||
      expectedRevision < 1
    )
      throw Error("Vault document conflict");
    const record = await this.store.resources.findOne({
      _id: id,
      ...scope,
      deletedAt: { $exists: false },
    });
    if (!record) throw Error("Vault document conflict");
    assertAdministrativeValueAccess(record, actor);
    const permit = await this.authorization.require(
      actor,
      record.kind === "encryption-key" ? "rotations:admin" : "resources:write",
      scope,
    );
    await this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await this.ownerFence(scope, tx);
      const result = await this.store.resources.updateOne(
        {
          _id: id,
          ...scope,
          revision: expectedRevision,
          deletedAt: { $exists: false },
        },
        { $set: { enabled }, $inc: { revision: 1 } },
        { session: tx.session },
      );
      if (result.matchedCount !== 1) throw Error("Vault document conflict");
      await tx.db.collection<AuditRecord>("vault_audit_events").insertOne(
        {
          _id: randomUUID(),
          ...scope,
          actorId: actor.issuer + "|" + actor.subject,
          action: enabled ? "resource.enable" : "resource.revoke",
          targetId: id,
          at: Date.now(),
        },
        { session: tx.session },
      );
    });
    return { enabled, revision: expectedRevision + 1 };
  }
  async stageGeneratedKey(
    actor: Actor,
    scope: ResourceScope,
    id: string,
    expectedRevision: number,
    rotations: import("./key-rotations.js").KeyRotationService,
  ) {
    await this.authorization.require(actor, "rotations:admin", scope);
    const resource = await this.store.resources.findOne({
      _id: id,
      ...scopeFilter(scope),
      kind: "encryption-key",
      enabled: true,
      revision: expectedRevision,
    });
    if (!resource) throw Error("Vault document conflict");
    assertAdministrativeValueAccess(resource, actor);
    const bytes = randomBytes(32),
      versionId = randomUUID();
    let encoded: Buffer | undefined;
    try {
      encoded = Buffer.from(
        bytes.toString(resource.valueFormat === "hex64" ? "hex" : "base64"),
      );
      return await rotations.prepare(actor, scope, id, expectedRevision, {
        ...scopeFilter(scope),
        _id: versionId,
        resourceId: id,
        versionNumber: resource.currentVersionNumber + 1,
        kind: "encryption-key",
        contentType: resource.contentType,
        valueFormat: resource.valueFormat,
        schemaIdentity: resource.schemaIdentity,
        createdAt: Date.now(),
        createdBy: actor.issuer + "|" + actor.subject,
        value: this.store.sealValue(
          scope,
          id,
          versionId,
          resource.schemaIdentity,
          encoded,
        ),
      });
    } finally {
      bytes.fill(0);
      encoded?.fill(0);
    }
  }
  async access(actor: Actor, scope: ResourceScope) {
    await this.authorization.require(actor, "metadata:list", scope);
    let canRead = false,
      canWrite = false,
      canRotate = false,
      canExportKeys = false, canManageGrants=false;
    try {
      await this.authorization.require(actor, "values:read", scope);
      canRead = true;
    } catch {}
    try {
      await this.authorization.require(actor, "resources:write", scope);
      canWrite = true;
    } catch {}
    try {
      await this.authorization.require(actor, "rotations:admin", scope);
      canRotate = true;
    } catch {}
    try {
      await this.authorization.require(actor, "keys:export", scope);
      canExportKeys = true;
    } catch {}
    try { await this.authorization.require(actor,"grants:admin",scope); canManageGrants=true; } catch {}
    return { canRead, canWrite, canRotate, canExportKeys, canManageGrants };
  }
  async versions(actor: Actor, scope: ResourceScope, id: string) {
    const permit = await this.authorization.require(
        actor,
        "metadata:list",
        scope,
      ),
      versions = await this.store.listVersions(scope, id);
    await this.authorization.assertCurrent(permit);
    return versions;
  }
  async list(
    actor: Actor,
    scope: ResourceScope,
    options: { limit: number; after?: string; kind?: ResourceKind },
  ) {
    const permit = await this.authorization.require(
        actor,
        "metadata:list",
        scope,
      ),
      result = await this.store.listResources(scope, options);
    await this.authorization.assertCurrent(permit);
    return result.map((resource) => ({
      ...resource,
      custody: effectiveCustody(resource),
    }));
  }
  async reveal(
    actor: Actor,
    owner: ResourceScope,
    resourceId: string,
    versionId: string,
  ): Promise<Buffer> {
    const scope = scopeFilter(owner);
    const metadata = await this.store.resources.findOne({
      _id: resourceId,
      ...scope,
      deletedAt: { $exists: false },
    });
    if (!metadata) throw new AccessDenied();
    const permit = await this.authorization.require(
        actor,
        metadata.kind === "encryption-key" ? "keys:export" : "values:read",
        scope,
      ),
      buffers = new Set<Buffer>();
    let result: Buffer | undefined;
    try {
      result = await this.store.transaction(async (tx) => {
        await this.authorization.fence(permit, tx);
        await this.ownerFence(scope, tx);
        const resource = await this.store.resources.findOne(
          { _id: resourceId, ...scope, deletedAt: { $exists: false } },
          { session: tx.session },
        );
        if (!resource || resource.kind !== metadata.kind)
          throw new AccessDenied();
        assertAdministrativeValueAccess(resource, actor);
        const value = await this.store.readValue(
          scope,
          resourceId,
          versionId,
          tx,
        );
        buffers.add(value);
        await tx.db.collection<AuditRecord>("vault_audit_events").insertOne(
          {
            _id: randomUUID(),
            ...scope,
            actorId: actor.issuer + "|" + actor.subject,
            action: "resource.reveal",
            targetId: resourceId,
            at: Date.now(),
          },
          { session: tx.session },
        );
        return value;
      });
      return result;
    } finally {
      for (const buffer of buffers) if (buffer !== result) buffer.fill(0);
    }
  }
}
