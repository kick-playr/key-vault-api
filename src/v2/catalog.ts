import { randomUUID } from "node:crypto";
import {
  AccessDenied,
  type Actor,
  type Authorization,
} from "./authorization.js";
import { scopeFilter, type V2MongoStore } from "./mongo-store.js";
import type { ResourceScope } from "./records.js";
import { barrier, affected } from "./instances.js";
export function applicationIdentity(id: string) {
  if (
    typeof id !== "string" ||
    !/^[a-z][a-z0-9-]{0,63}$/.test(id) ||
    ["app", "explorer"].includes(id)
  )
    throw Error("Use a canonical application identity");
  return id;
}
export class CatalogService {
  constructor(
    private readonly store: V2MongoStore,
    private readonly authorization: Authorization,
  ) {}
  async list(actor: Actor, input: ResourceScope) {
    const scope = scopeFilter(input),
      permit = await this.authorization.require(actor, "metadata:list", scope);
    const result = await this.store.transaction(async (tx) => {
      const opts = { session: tx.session },
        assignments = await tx.db
          .collection("vault_application_tenants")
          .find(
            {
              environment: scope.environment,
              ...(scope.ownerType === "tenant"
                ? { tenantId: scope.ownerId }
                : {}),
            },
            opts,
          )
          .limit(10001)
          .toArray();
      const apps = await tx.db
        .collection("vault_applications")
        .find({ deletedAt: { $exists: false } }, opts)
        .limit(101)
        .toArray();
      const tenants = await tx.db
        .collection("vault_tenants")
        .find(
          scope.ownerType === "tenant" ? ({ _id: scope.ownerId } as any) : {},
          opts,
        )
        .limit(1001)
        .toArray();
      const grants =
        scope.ownerType === "application"
          ? await this.store.grants
              .find(
                { environment: scope.environment },
                { ...opts, projection: { tokenHash: 0 } },
              )
              .limit(1001)
              .toArray()
          : [];
      const instances = await tx.db
        .collection("vault_application_instances")
        .find(
          {
            environment: scope.environment,
            ...(scope.ownerType === "tenant"
              ? {
                  applicationId: {
                    $in: assignments.map((a) => a.applicationId),
                  },
                }
              : {}),
          },
          { ...opts, projection: { passwordHash: 0 } },
        )
        .limit(1001)
        .toArray();
      return { applications: apps, tenants, assignments, grants, instances };
    });
    await this.authorization.assertCurrent(permit);
    return result;
  }
  async saveApplication(
    actor: Actor,
    environment: string,
    input: { id: string; name: string; description: string; revision: number },
  ) {
    const id = applicationIdentity(input.id),
      scope = scopeFilter({
        environment,
        ownerType: "application",
        ownerId: id,
      }),
      permit = await this.authorization.require(
        actor,
        "resources:write",
        scope,
      );
    if (
      typeof input.name !== "string" ||
      !input.name.trim() ||
      input.name.length > 128 ||
      typeof input.description !== "string" ||
      input.description.length > 1000 ||
      !Number.isSafeInteger(input.revision) ||
      input.revision < 0
    )
      throw Error("Invalid application metadata");
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      const apps = tx.db.collection<any>("vault_applications"),
        current = await apps.findOne({ _id: id }, { session: tx.session });
      if ((current?.revision ?? 0) !== input.revision)
        throw Error("Vault document conflict");
      const next = {
        _id: id,
        name: input.name.trim(),
        description: input.description,
        revision: input.revision + 1,
      };
      if (current)
        await apps.replaceOne({ _id: id, revision: input.revision }, next, {
          session: tx.session,
        });
      else await apps.insertOne(next, { session: tx.session });
      await tx.db
        .collection<any>("vault_application_environments")
        .updateOne(
          { applicationId: id, environment },
          {
            $setOnInsert: {
              _id: environment + "/" + id,
              enabled: true,
              revision: 1,
            },
          },
          { upsert: true, session: tx.session },
        );
      return next;
    });
  }
  async assign(
    actor: Actor,
    owner: ResourceScope,
    applicationId: string,
    enabled: boolean,
    expectedRevision: number,
  ) {
    const scope = scopeFilter(owner);
    applicationIdentity(applicationId);
    if (scope.ownerType !== "tenant" || typeof enabled !== "boolean")
      throw new AccessDenied();
    const permit = await this.authorization.require(
      actor,
      "links:write",
      scope,
    );
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await barrier(tx, scope.environment);
      const opts = { session: tx.session };
      if (
        !(await tx.db
          .collection("vault_application_environments")
          .findOne(
            { applicationId, environment: scope.environment, enabled: true },
            opts,
          )) ||
        !(await tx.db
          .collection<any>("vault_tenants")
          .findOne({ _id: scope.ownerId }, opts))
      )
        throw new AccessDenied();
      // Initial enrollment/custody approval is controlled by the tenant's club admin, separately from human global-admin consent.
      if (
        enabled &&
        !(await tx.db
          .collection("vault_machine_enrollments")
          .findOne(
            {
              tenantId: scope.ownerId,
              environment: scope.environment,
              applicationId,
              approved: true,
            },
            opts,
          ))
      )
        throw new AccessDenied();
      const assignment = {
          applicationId,
          environment: scope.environment,
          tenantId: scope.ownerId,
        },
        collection = tx.db.collection<any>("vault_application_tenants"),
        current = await collection.findOne(assignment, opts);
      if ((current?.revision ?? 0) !== expectedRevision)
        throw Error("Vault document conflict");
      const next = {
        ...assignment,
        _id: current?._id ?? randomUUID(),
        enabled,
        revision: expectedRevision + 1,
      };
      if (current)
        await collection.replaceOne(
          { _id: current._id, revision: expectedRevision },
          next,
          opts,
        );
      else await collection.insertOne(next, opts);
      // Original rotation participants are never removed by unassignment.
      if (enabled) {
        const rotations = await tx.db
            .collection<any>("vault_key_rotations")
            .find({ environment: scope.environment, state: "prepared" }, opts)
            .toArray(),
          instances = await tx.db
            .collection<any>("vault_application_instances")
            .find(
              { applicationId, environment: scope.environment, retired: false },
              opts,
            )
            .toArray();
        for (const rotation of rotations)
          if (
            await affected(
              tx,
              applicationId,
              scope.environment,
              rotation.resourceId,
            )
          )
            for (const instance of instances)
              await tx.db
                .collection<any>("vault_key_rotation_participants")
                .updateOne(
                  { _id: rotation._id + ":" + instance._id },
                  {
                    $setOnInsert: {
                      rotationId: rotation._id,
                      environment: scope.environment,
                      instanceId: instance._id,
                      acknowledged: false,
                      retired: false,
                    },
                  },
                  { ...opts, upsert: true },
                );
      }
      await tx.db
        .collection("vault_application_environments")
        .updateOne(
          { applicationId, environment: scope.environment },
          { $inc: { revision: 1 } },
          opts,
        );
      return next;
    });
  }
  async approveEnrollment(
    actor: Actor,
    owner: ResourceScope,
    applicationId: string,
  ) {
    const scope = scopeFilter(owner);
    applicationIdentity(applicationId);
    if (scope.ownerType !== "tenant") throw new AccessDenied();
    const permit = await this.authorization.require(
      actor,
      "consent:write",
      scope,
    );
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await tx.db
        .collection("vault_machine_enrollments")
        .updateOne(
          {
            tenantId: scope.ownerId,
            environment: scope.environment,
            applicationId,
          },
          {
            $set: {
              approved: true,
              approvedBy: actor.issuer + "|" + actor.subject,
              approvedAt: Date.now(),
            },
          },
          { upsert: true, session: tx.session },
        );
      return { approved: true };
    });
  }
  async removeApplication(
    actor: Actor,
    environment: string,
    id: string,
    expectedRevision: number,
    confirmation: string,
  ) {
    applicationIdentity(id);
    const scope = scopeFilter({
        environment,
        ownerType: "application",
        ownerId: id,
      }),
      permit = await this.authorization.require(
        actor,
        "resources:write",
        scope,
      );
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)
      throw Error("Vault document conflict");
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await barrier(tx, environment);
      const opts = { session: tx.session },
        record = await tx.db
          .collection<any>("vault_applications")
          .findOne(
            {
              _id: id,
              revision: expectedRevision,
              deletedAt: { $exists: false },
            },
            opts,
          );
      if (!record || record.name !== confirmation)
        throw Error("Application confirmation does not match");
      for (const [collection, filter] of [
        ["vault_resource_links", { applicationId: id }],
        ["vault_application_tenants", { applicationId: id, enabled: true }],
        ["vault_application_instances", { applicationId: id, retired: false }],
      ] as const)
        if (await tx.db.collection(collection).findOne(filter, opts))
          throw Error("Application is in use");
      const sharedUsage = await this.store.resources.aggregate([
        { $match: { ownerType: "application", ownerId: id } },
        { $project: { _id: 1 } },
        { $lookup: { from: "vault_resource_links", localField: "_id", foreignField: "resourceId", as: "consumers" } },
        { $match: { "consumers.0": { $exists: true } } },
        { $limit: 1 },
      ], opts).toArray();
      if (sharedUsage.length) throw Error("Application is in use");
      await tx.db
        .collection<any>("vault_applications")
        .updateOne(
          { _id: id, revision: expectedRevision },
          { $set: { deletedAt: Date.now() }, $inc: { revision: 1 } },
          opts,
        );
      await tx.db
        .collection("vault_application_environments")
        .updateMany(
          { applicationId: id },
          { $set: { enabled: false }, $inc: { revision: 1 } },
          opts,
        );
      return { deleted: true, secretsKept: true };
    });
  }
}
