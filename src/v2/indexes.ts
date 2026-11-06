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
  vault_resources: {
    validator: shape(
      {
        _id: string,
        ...scoped,
        name: string,
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
  const existing = new Set(
    (await db.listCollections({}, { nameOnly: true }).toArray()).map(
      (c) => c.name,
    ),
  );
  for (const [name, definition] of Object.entries(collectionDefinitions)) {
    if (!existing.has(name))
      await db.createCollection(name, {
        validator: definition.validator,
        validationLevel: "strict",
        validationAction: "error",
      });
    await db.collection(name).createIndexes(definition.indexes);
  }
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
