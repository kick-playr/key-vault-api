import { randomUUID } from "node:crypto";
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
  private prepare(
    scope: ResourceScope,
    input: ResourceInput,
  ): {
    bytes: Buffer;
    contentType: string;
    valueFormat: SecretValueFormat;
    schemaIdentity: string;
  } {
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
      prepared = this.prepare(scope, input),
      id = randomUUID(),
      versionId = randomUUID();
    try {
      const resource: ResourceRecord = {
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
    const scope = scopeFilter(owner),
      permit = await this.authorization.require(
        actor,
        "resources:write",
        scope,
      );
    if (input.kind === "encryption-key")
      throw Error("Use the coordinated key rotation workflow");
    const prepared = this.prepare(scope, input),
      versionId = randomUUID();
    try {
      return await this.store.transaction(async (tx) => {
        await this.authorization.fence(permit, tx);
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
    const scope = scopeFilter(owner),
      permit = await this.authorization.require(
        actor,
        "resources:write",
        scope,
      );
    await this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
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
      await tx.db
        .collection<AuditRecord>("vault_audit_events")
        .insertOne(
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
    return result;
  }
  async reveal(
    actor: Actor,
    owner: ResourceScope,
    resourceId: string,
    versionId: string,
  ): Promise<Buffer> {
    const scope = scopeFilter(owner),
      permit = await this.authorization.require(actor, "values:read", scope),
      buffers = new Set<Buffer>();
    let result: Buffer | undefined;
    try {
      result = await this.store.transaction(async (tx) => {
        await this.authorization.fence(permit, tx);
        const value = await this.store.readValue(
          scope,
          resourceId,
          versionId,
          tx,
        );
        buffers.add(value);
        await tx.db
          .collection<AuditRecord>("vault_audit_events")
          .insertOne(
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
