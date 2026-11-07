import { randomUUID } from "node:crypto";
import { scopeFilter, type V2MongoStore } from "./mongo-store.js";
import type { Actor, Authorization } from "./authorization.js";
import type { ResourceScope } from "./records.js";
import { IntegrationSchemas } from "./integration-schemas.js";
export function schemaVersionId(
  scope: ResourceScope,
  name: string,
  version: number,
) {
  const owner = scopeFilter(scope);
  if (
    !/^[a-z][a-z0-9-]{0,63}$/.test(name) ||
    !Number.isSafeInteger(version) ||
    version < 1
  )
    throw Error("Invalid integration schema");
  return `custom:${owner.environment}:${owner.ownerType}:${owner.ownerId}:${name}@${version}`;
}
export class SchemaService {
  constructor(
    private readonly store: V2MongoStore,
    private readonly authorization: Authorization,
    readonly schemas: IntegrationSchemas,
  ) {}
  async create(
    actor: Actor,
    scope: ResourceScope,
    name: string,
    version: number,
    schema: unknown,
  ) {
    const owner = scopeFilter(scope),
      permit = await this.authorization.require(
        actor,
        "resources:write",
        owner,
      ),
      identity = schemaVersionId(owner, name, version),
      checked = new IntegrationSchemas();
    checked.registerCustom(owner, name, version, schema);
    const definition = checked.schema(identity);
    await this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      const current = await tx.db
        .collection<any>("vault_integration_schemas")
        .findOne(
          {
            _id: `${owner.environment}/${owner.ownerType}/${owner.ownerId}/${name}`,
          },
          { session: tx.session },
        );
      if ((current?.version ?? 0) + 1 !== version)
        throw Error("Vault schema conflict");
      await tx.db
        .collection<any>("vault_integration_schema_versions")
        .insertOne(
          {
            _id: identity,
            ...owner,
            name,
            version,
            schema: definition,
            createdAt: Date.now(),
            createdBy: actor.issuer + "|" + actor.subject,
          },
          { session: tx.session },
        );
      await tx.db
        .collection<any>("vault_integration_schemas")
        .updateOne(
          {
            _id: `${owner.environment}/${owner.ownerType}/${owner.ownerId}/${name}`,
          },
          { $set: { ...owner, name, version, identity } },
          { upsert: true, session: tx.session },
        );
      await tx.db
        .collection<any>("vault_audit_events")
        .insertOne(
          {
            _id: randomUUID(),
            ...owner,
            actorId: actor.issuer + "|" + actor.subject,
            action: "schema.create",
            targetId: identity,
            at: Date.now(),
          },
          { session: tx.session },
        );
    });
    this.schemas.registerCustom(owner, name, version, definition);
    return { identity, version };
  }
  async get(actor: Actor, scope: ResourceScope, identity: string) {
    await this.authorization.require(actor, "metadata:list", scope);
    await ensureSchema(this.store, this.schemas, scope, identity);
    return this.schemas.schema(identity);
  }
  async load() {
    const rows = await this.store.transaction((tx) =>
      tx.db
        .collection("vault_integration_schema_versions")
        .find({}, { session: tx.session })
        .limit(509)
        .toArray(),
    );
    if (rows.length > 508) throw Error("Integration schema capacity reached");
    for (const row of rows)
      this.schemas.registerCustom(
        scopeFilter(row as unknown as ResourceScope),
        row.name,
        row.version,
        row.schema,
      );
  }
}

export async function ensureSchema(
  store: V2MongoStore,
  schemas: IntegrationSchemas,
  scope: ResourceScope,
  identity: string,
) {
  const checkedOwner = scopeFilter(scope);
  if (identity.startsWith("custom:") && !identity.startsWith(
    `custom:${checkedOwner.environment}:${checkedOwner.ownerType}:${checkedOwner.ownerId}:`,
  )) throw Error("Integration schema unavailable");
  try {
    schemas.schema(identity);
    return;
  } catch {}
  const owner = scopeFilter(scope),
    row = await store.transaction((tx) =>
      tx.db
        .collection<any>("vault_integration_schema_versions")
        .findOne({ _id: identity, ...owner }, { session: tx.session }),
    );
  if (
    !row ||
    schemas.registerCustom(owner, row.name, row.version, row.schema) !==
      identity
  )
    throw Error("Integration schema unavailable");
}
