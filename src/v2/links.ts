import { randomUUID } from "node:crypto";
import {
  AccessDenied,
  type Actor,
  type Authorization,
} from "./authorization.js";
import { scopeFilter, type V2MongoStore } from "./mongo-store.js";
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
  } else if (resource.ownerId !== applicationId || tenantId !== undefined)
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
  ): Promise<ResourceLink> {
    const owner = scopeFilter(scope),
      permit = await this.authorization.require(actor, "links:write", owner);
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      const deployment = await tx.db
        .collection("vault_application_deployments")
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
        { _id: input.resourceId, ...owner },
        { session: tx.session },
      );
      if (!resource) throw new AccessDenied();
      const assignment =
        owner.ownerType === "tenant"
          ? await tx.db
              .collection("vault_application_tenants")
              .findOne(
                {
                  applicationId: input.applicationId,
                  environment: owner.environment,
                  tenantId: owner.ownerId,
                  enabled: true,
                },
                { session: tx.session },
              )
          : null;
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
          { _id: input.versionPolicy, resourceId: resource._id, ...owner },
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
              ...owner,
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
        .collection("vault_application_deployments")
        .updateOne(
          { _id: deployment._id, revision: deployment.revision },
          { $inc: { authorizationFence: 1 } },
          { session: tx.session },
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
      await tx.db
        .collection<AuditRecord>("vault_audit_events")
        .insertOne(
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
    });
  }
}
