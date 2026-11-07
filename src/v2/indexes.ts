import type { Db, Document, IndexDescription } from "mongodb";
const string = { bsonType: "string" },
  numeric = { bsonType: ["int", "long", "double"], minimum: 0 };
const scoped = {
  environment: string,
  ownerType: { enum: ["application", "tenant"] },
  ownerId: string,
};
const kinds = { enum: ["secret", "encryption-key", "integration"] };
const formats = { enum: ["text", "base64", "hex64"] };
const capabilities = [
  "metadata:list",
  "secrets:read",
  "keys:export",
  "resources:write",
  "assignments:write",
  "grants:admin",
  "rotations:admin",
];
const shape = (
  properties: Document,
  required = Object.keys(properties),
): Document => ({
  $jsonSchema: {
    bsonType: "object",
    required,
    additionalProperties: false,
    properties,
  },
});
export const collectionDefinitions: Record<
  string,
  { validator: Document; indexes: IndexDescription[] }
> = {
  vault_grants: {
    validator: {
      $and: [
        shape(
          {
            _id: string,
            authorizationFence: numeric,
            tokenHash: { bsonType: "string", pattern: "^[a-f0-9]{64}$" },
            grantClass: {
              enum: ["application", "interactive-provisioner", "operator"],
            },
            applicationId: string,
            environment: string,
            capabilities: {
              bsonType: "array",
              uniqueItems: true,
              minItems: 1,
              maxItems: 7,
              items: { enum: capabilities },
            },
            enabled: { bsonType: "bool" },
            revision: numeric,
            createdAt: numeric,
          },
          [
            "_id",
            "tokenHash",
            "grantClass",
            "environment",
            "capabilities",
            "enabled",
            "revision",
            "createdAt",
          ],
        ),
        {
          $or: [
            { grantClass: { $in: ["interactive-provisioner", "operator"] } },
            {
              grantClass: "application",
              applicationId: { $type: "string" },
              capabilities: {
                $not: {
                  $elemMatch: {
                    $nin: ["metadata:list", "secrets:read", "keys:export"],
                  },
                },
              },
            },
          ],
        },
      ],
    },
    indexes: [
      { key: { tokenHash: 1 }, unique: true, name: "grant_token_hash" },
      {
        key: { applicationId: 1, environment: 1, enabled: 1 },
        name: "grant_deployment",
      },
    ],
  },
  vault_deployment_custody: {
    validator: shape({ _id: string, applicationId: string, environment: string,
      mode: { enum: ["deployment-only"] }, deliveryId: string,
      enabled: { bsonType: "bool" }, revision: numeric, authorizationFence: numeric,
    }, ["_id", "applicationId", "environment", "mode", "deliveryId", "enabled", "revision"]),
    indexes: [{ key: { applicationId: 1, environment: 1 }, unique: true, name: "deployment_custody" }],
  },
  vault_machine_enrollments: {
    validator: { $and: [shape({
      _id: { bsonType: ["string", "objectId"] }, applicationId: string, tenantId: string, environment: string,
      approved: { bsonType: "bool" }, approvedBy: string, approvedAt: numeric,
      revision: numeric, authorizationFence: numeric,
    }, ["_id", "applicationId", "tenantId", "environment", "approved"]),
    { $or: [{ approved: false }, { approved: true, approvedBy: { $type: "string" }, approvedAt: { $type: "number" } }] }] },
    indexes: [{ key: { applicationId: 1, environment: 1, tenantId: 1 }, unique: true, name: "v2_entity_identity" }],
  },
  vault_grant_scopes: {
    validator: shape(
      {
        _id: string,
        grantId: string,
        ...scoped,
        revision: numeric,
        authorizationFence: numeric,
      },
      ["_id", "grantId", "environment", "ownerType", "ownerId"],
    ),
    indexes: [
      {
        key: { grantId: 1, environment: 1, ownerType: 1, ownerId: 1 },
        unique: true,
        name: "grant_explicit_scope",
      },
    ],
  },
  vault_resources: {
    validator: shape(
      {
        _id: string,
        ...scoped,
        name: string,
        custody: { enum: ["admin-managed", "workload-only"] },
        kind: kinds,
        contentType: string,
        valueFormat: formats,
        schemaIdentity: string,
        enabled: { bsonType: "bool" },
        revision: numeric,
        currentVersionId: string,
        currentVersionNumber: numeric,
        deletedAt: numeric,
        linkFence: numeric,
      },
      [
        "_id",
        "environment",
        "ownerType",
        "ownerId",
        "name",
        "kind",
        "contentType",
        "valueFormat",
        "schemaIdentity",
        "enabled",
        "revision",
        "currentVersionId",
        "currentVersionNumber",
      ],
    ),
    indexes: [
      {
        key: { environment: 1, ownerType: 1, ownerId: 1, name: 1 },
        unique: true,
        name: "resource_owner_name",
      },
      {
        key: { environment: 1, ownerType: 1, ownerId: 1, kind: 1, _id: 1 },
        name: "resource_inventory",
      },
    ],
  },
  vault_resource_versions: {
    validator: shape({
      _id: string,
      ...scoped,
      resourceId: string,
      versionNumber: numeric,
      kind: kinds,
      contentType: string,
      valueFormat: formats,
      schemaIdentity: string,
      createdAt: numeric,
      createdBy: string,
      value: { bsonType: "object" },
    }),
    indexes: [
      {
        key: { resourceId: 1, versionNumber: 1 },
        unique: true,
        name: "resource_version",
      },
      {
        key: { environment: 1, ownerType: 1, ownerId: 1, resourceId: 1 },
        name: "version_scope",
      },
    ],
  },
  vault_resource_links: {
    validator: shape(
      {
        _id: string,
        applicationId: string,
        environment: string,
        tenantId: string,
        resourceId: string,
        accessName: string,
        versionPolicy: string,
        capability: string,
        revision: numeric,
      },
      [
        "_id",
        "applicationId",
        "environment",
        "resourceId",
        "accessName",
        "versionPolicy",
        "revision",
      ],
    ),
    indexes: [
      {
        key: { applicationId: 1, environment: 1, tenantId: 1, accessName: 1 },
        unique: true,
        name: "link_access_name",
      },
      { key: { resourceId: 1 }, name: "link_resource_usage" },
    ],
  },
};
/** Initialize individual collections; never installs a namespace/grant aggregate. */
export async function installCollections(db: Db): Promise<void> {
  const existing = new Map(
    (await db.listCollections().toArray()).map((c) => [c.name, c]),
  );
  const canonical = (value: any): string =>
    JSON.stringify(
      value && typeof value === "object"
        ? Array.isArray(value)
          ? value.map((v) => JSON.parse(canonical(v)))
          : Object.fromEntries(
              Object.keys(value)
                .sort()
                .map((k) => [k, JSON.parse(canonical(value[k]))]),
            )
        : value,
    );
  for (const [name, definition] of Object.entries(collectionDefinitions)) {
    if (!existing.has(name))
      await db.createCollection(name, {
        validator: definition.validator,
        validationLevel: "strict",
        validationAction: "error",
      });
    else {
      const info = existing.get(name)!;
      const options = "options" in info ? info.options : undefined;
      if (
        !options ||
        options.validationLevel !== "strict" ||
        options.validationAction !== "error" ||
        canonical(options.validator) !== canonical(definition.validator)
      )
        throw Error(
          "Existing Vault collection schema requires explicit migration",
        );
    }
    await db.collection(name).createIndexes(definition.indexes);
  }
  for (const [name, key] of Object.entries({
    vault_application_environments: { applicationId: 1, environment: 1 },
    vault_application_tenants: {
      applicationId: 1,
      environment: 1,
      tenantId: 1,
    },
    vault_tenant_admin_consents: { environment: 1, tenantId: 1 },
    vault_integration_schemas: {
      environment: 1,
      ownerType: 1,
      ownerId: 1,
      name: 1,
    },
    vault_key_rotation_participants: { rotationId: 1, instanceId: 1 },
    vault_identity_policies: { environment: 1 },
  }))
    await db
      .collection(name)
      .createIndex(key as any, { unique: true, name: "v2_entity_identity" });
  await db
    .collection("vault_change_heads")
    .createIndex(
      { environment: 1, ownerType: 1, ownerId: 1 },
      { unique: true, name: "change_owner" },
    );
  await db
    .collection("vault_audit_events")
    .createIndex(
      { environment: 1, ownerType: 1, ownerId: 1, at: -1 },
      { name: "audit_owner_time" },
    );
}
