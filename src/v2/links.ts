import { effectiveCustody, isWorkloadAccessName } from "./resource-custody.js";
import { barrier, affected } from "./instances.js";
import { randomUUID } from "node:crypto";
import {
  AccessDenied,
  type Actor,
  type Authorization,
} from "./authorization.js";
import {
  scopeFilter,
  type V2MongoStore,
  type V2Transaction,
} from "./mongo-store.js";
import type { ResourceScope, ResourceLink, AuditRecord } from "./records.js";
export function validateLink(
  resource: ResourceScope & { enabled: boolean; deletedAt?: number },
  applicationId: string,
  environment: string,
  tenantId: string | undefined,
  assigned: boolean,
  accessName: string,
  versionPolicy: string,
) {
  scopeFilter({
    environment,
    ownerType: "application",
    ownerId: applicationId,
  });
  if (
    !resource.enabled ||
    resource.deletedAt !== undefined ||
    resource.environment !== environment ||
    typeof accessName !== "string" ||
    /^(NEXT_PUBLIC_|PUBLIC_|VITE_|NODE_|NPM_|VAULT_|LOCAL_KEYVAULT_|LD_|DYLD_)/.test(
      accessName,
    ) ||
    ["PATH", "HOME", "SHELL", "SECRETS_KEYS_STRATEGY"].includes(accessName) ||
    !/^[A-Z][A-Z0-9_]{0,127}$/.test(accessName) ||
    typeof versionPolicy !== "string" ||
    !(
      versionPolicy === "latest" ||
      /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(versionPolicy)
    )
  )
    throw new AccessDenied();
  if (resource.ownerType === "tenant") {
    if (!assigned || tenantId !== resource.ownerId) throw new AccessDenied();
  } else if (tenantId !== undefined)
    throw new AccessDenied();
  return { ...(tenantId ? { tenantId } : {}), accessName, versionPolicy };
}
export class LinkService {
  constructor(
    private readonly store: V2MongoStore,
    private readonly authorization: Authorization,
  ) {}
  async create(
    actor: Actor,
    scope: ResourceScope,
    input: {
      applicationId: string;
      resourceId: string;
      tenantId?: string;
      accessName: string;
      versionPolicy: string;
    },
    transaction?: V2Transaction,
  ): Promise<ResourceLink> {
    const owner = scopeFilter(scope),
      permit = await this.authorization.require(actor, "links:write", owner);
    const work = async (tx: V2Transaction) => {
      await this.authorization.fence(permit, tx);
      await barrier(tx, owner.environment);
      const deployment = await tx.db
        .collection("vault_application_environments")
        .findOne(
          {
            applicationId: input.applicationId,
            environment: owner.environment,
            enabled: true,
          },
          { session: tx.session },
        );
      if (!deployment) throw new AccessDenied();
      const resource = await this.store.resources.findOne(
        { _id: input.resourceId, environment: owner.environment },
        { session: tx.session },
      );
      if (!resource || resource.ownerType !== owner.ownerType ||
          (owner.ownerType === "tenant" && resource.ownerId !== owner.ownerId)) throw new AccessDenied();
      const source = scopeFilter(resource);
      const target = scopeFilter({ environment: owner.environment, ownerType: "application", ownerId: input.applicationId });
      if (owner.ownerType === "application") {
        for (const additional of [source, target]) {
          if (additional.ownerId === owner.ownerId) continue;
          const additionalPermit = await this.authorization.require(actor, "links:write", additional);
          await this.authorization.fence(additionalPermit, tx);
        }
      }
      const sourceDeployment = owner.ownerType === "application" && source.ownerId !== target.ownerId
        ? await tx.db.collection("vault_application_environments").findOne(
            { applicationId: source.ownerId, environment: owner.environment, enabled: true },
            { session: tx.session },
          ) : undefined;
      if (owner.ownerType === "application" && source.ownerId !== target.ownerId && !sourceDeployment) throw new AccessDenied();
      if (owner.ownerType === "application" && isWorkloadAccessName(input.accessName)
        && effectiveCustody(resource) !== "workload-only") throw new AccessDenied();
      if (
        /(?:WRAPPING_KEY_V[0-9]+|INDEX_KEY|CONTROL_KEY|CREDENTIAL_KEY|PROXY_KEY|CLERK_ENCRYPTION_KEY|MANAGER_INVITATION_FLOW_KEY)$/.test(
          input.accessName,
        ) &&
        resource.kind !== "encryption-key"
      )
        throw new AccessDenied();
      {
        // Bind both the owning resource slot and every consuming application slot.
        // These identities survive unlinking, so a different source cannot replace a key.
        const identities = [source];
        if (source.ownerType === "application" && source.ownerId !== target.ownerId) identities.push(target);
        for (const identityScope of identities) {
          const identity = { ...identityScope, accessName: input.accessName },
            bindings = tx.db.collection<any>("vault_key_access_bindings"),
            previous = await bindings.findOne(identity, { session: tx.session });
          if (previous && previous.resourceId !== resource._id)
            throw Error("Key access names require coordinated rotation, not resource replacement");
          if (!previous && resource.kind === "encryption-key")
            await bindings.insertOne({
              _id: identityScope.environment + "/" + identityScope.ownerType + "/" + identityScope.ownerId + "/" + input.accessName,
              ...identity, resourceId: resource._id,
            }, { session: tx.session });
        }
      }

      const assignment =
        owner.ownerType === "tenant"
          ? await tx.db.collection("vault_application_tenants").findOne(
              {
                applicationId: input.applicationId,
                environment: owner.environment,
                tenantId: owner.ownerId,
                enabled: true,
              },
              { session: tx.session },
            )
          : null;
      if (
        await this.store.links.findOne(
          {
            resourceId: resource._id,
            environment: owner.environment,
            accessName: { $ne: input.accessName },
          },
          { session: tx.session },
        )
      )
        throw new AccessDenied();
      const data = validateLink(
        resource,
        input.applicationId,
        owner.environment,
        input.tenantId,
        !!assignment,
        input.accessName,
        input.versionPolicy,
      );
      if (
        input.versionPolicy !== "latest" &&
        !(await this.store.versions.findOne(
          { _id: input.versionPolicy, resourceId: resource._id, ...source },
          { session: tx.session },
        ))
      )
        throw new AccessDenied();
      // Writes serialize linking against deletion, deployment revocation and unassignment.
      if (
        (
          await this.store.resources.updateOne(
            {
              _id: resource._id,
              ...source,
              enabled: true,
              deletedAt: { $exists: false },
              revision: resource.revision,
            },
            { $inc: { linkFence: 1 } },
            { session: tx.session },
          )
        ).matchedCount !== 1
      )
        throw new AccessDenied();
      await tx.db
        .collection("vault_application_environments")
        .updateOne(
          { _id: deployment._id, revision: deployment.revision },
          { $inc: { authorizationFence: 1 } },
          { session: tx.session },
        );
      if (sourceDeployment)
        await tx.db.collection("vault_application_environments").updateOne(
          { _id: sourceDeployment._id, revision: sourceDeployment.revision, enabled: true },
          { $inc: { authorizationFence: 1 } }, { session: tx.session },
        );
      if (assignment)
        await tx.db
          .collection("vault_application_tenants")
          .updateOne(
            { _id: assignment._id, revision: assignment.revision },
            { $inc: { authorizationFence: 1 } },
            { session: tx.session },
          );
      const link: ResourceLink = {
        _id: randomUUID(),
        applicationId: input.applicationId,
        environment: owner.environment,
        resourceId: resource._id,
        ...data,
        revision: 1,
      };
      await this.store.links.insertOne(link, { session: tx.session });
      const rotations = await tx.db
        .collection<any>("vault_key_rotations")
        .find(
          {
            resourceId: resource._id,
            environment: owner.environment,
            state: "prepared",
          },
          { session: tx.session },
        )
        .toArray();
      const instances = await tx.db
        .collection<any>("vault_application_instances")
        .find(
          {
            applicationId: input.applicationId,
            environment: owner.environment,
            retired: false,
          },
          { session: tx.session },
        )
        .toArray();
      for (const rotation of rotations)
        for (const instance of instances)
          await tx.db
            .collection<any>("vault_key_rotation_participants")
            .updateOne(
              { _id: rotation._id + ":" + instance._id },
              {
                $setOnInsert: {
                  rotationId: rotation._id,
                  instanceId: instance._id,
                  environment: owner.environment,
                  acknowledged: false,
                  retired: false,
                },
              },
              { upsert: true, session: tx.session },
            );

      await tx.db.collection<AuditRecord>("vault_audit_events").insertOne(
        {
          _id: randomUUID(),
          ...owner,
          actorId: actor.issuer + "|" + actor.subject,
          action: "link.create",
          targetId: link._id,
          at: Date.now(),
        },
        { session: tx.session },
      );
      await tx.db
        .collection("vault_change_heads")
        .updateOne(
          owner,
          { $inc: { revision: 1 } },
          { upsert: true, session: tx.session },
        );
      return link;
    };
    return transaction ? work(transaction) : this.store.transaction(work);
  }
  async list(actor: Actor, owner: ResourceScope, applicationId: string) {
    const scope = scopeFilter(owner),
      permit = await this.authorization.require(actor, "metadata:list", scope);
    if (scope.ownerType === "application" && scope.ownerId !== applicationId) throw new AccessDenied();
    const result = await this.store.transaction(async (tx) => {
      const links = await this.store.links
        .find(
          {
            applicationId,
            environment: scope.environment,
            ...(scope.ownerType === "tenant"
              ? { tenantId: scope.ownerId }
              : { tenantId: { $exists: false } }),
          },
          { session: tx.session },
        )
        .limit(10001)
        .toArray();
      const sharedResources = scope.ownerType === "application"
        ? await this.store.resources.find({
            _id: { $in: links.map(link => link.resourceId) }, environment: scope.environment,
            ownerType: "application", ownerId: { $ne: applicationId },
          }, { session: tx.session }).toArray() : [];
      const deployment = await tx.db
        .collection("vault_application_environments")
        .findOne(
          { applicationId, environment: scope.environment },
          {
            session: tx.session,
            projection: { applicationId: 1, environment: 1, revision: 1 },
          },
        );
      return { links, deployment, sharedResources: sharedResources.map(resource => ({ ...resource, custody: effectiveCustody(resource) })) };
    });
    await this.authorization.assertCurrent(permit);
    return result;
  }
  async save(
    actor: Actor,
    owner: ResourceScope,
    applicationId: string,
    expectedRevision: number,
    rows: { resourceId: string; accessName: string; versionPolicy: string }[],
  ) {
    const scope = scopeFilter(owner),
      permit = await this.authorization.require(actor, "links:write", scope);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)
      throw new AccessDenied();
    if (
      !Array.isArray(rows) ||
      rows.length > 1000 ||
      new Set(rows.map((r) => r.resourceId)).size !== rows.length
    )
      throw new AccessDenied();
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await barrier(tx, scope.environment);
      if (
        (
          await tx.db
            .collection("vault_application_environments")
            .updateOne(
              {
                applicationId,
                environment: scope.environment,
                enabled: true,
                revision: expectedRevision,
              },
              { $inc: { revision: 1 } },
              { session: tx.session },
            )
        ).matchedCount !== 1
      )
        throw Error("Vault document conflict");
      const filter = {
        applicationId,
        environment: scope.environment,
        ...(scope.ownerType === "tenant"
          ? { tenantId: scope.ownerId }
          : { tenantId: { $exists: false } }),
      };
      if (scope.ownerType === "application" && scope.ownerId !== applicationId)
        throw new AccessDenied();
      // The complete selection is published in one transaction. No key participants are removed.
      await this.store.links.deleteMany(filter, { session: tx.session });
      for (const row of rows)
        await this.create(
          actor,
          scope,
          {
            applicationId,
            resourceId: row.resourceId,
            accessName: row.accessName,
            versionPolicy: row.versionPolicy,
            ...(scope.ownerType === "tenant"
              ? { tenantId: scope.ownerId }
              : {}),
          },
          tx,
        );
      return { saved: true, revision: expectedRevision + 1 };
    });
  }
}
