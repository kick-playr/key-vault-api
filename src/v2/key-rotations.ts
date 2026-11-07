import { assertAdministrativeValueAccess } from "./resource-custody.js";
import { randomUUID } from "node:crypto";
import type { Actor, Authorization } from "./authorization.js";
import { AccessDenied } from "./authorization.js";
import type { ResourceScope, ResourceVersion } from "./records.js";
import { scopeFilter, type V2MongoStore } from "./mongo-store.js";
import { affected, barrier } from "./instances.js";
export function assertActivationReady(
  participants: readonly {
    acknowledged: boolean;
    retired: boolean;
    lastSeen?: number;
    instanceId?: string;
  }[],
  _now?: number,
) {
  if (participants.some((p) => !p.acknowledged && !p.retired))
    throw Error("Waiting for instance key acknowledgements");
}
export class KeyRotationService {
  constructor(
    private readonly store: V2MongoStore,
    private readonly authorization: Authorization,
  ) {}
  async prepare(
    actor: Actor,
    scope: ResourceScope,
    resourceId: string,
    expectedRevision: number,
    version: ResourceVersion,
  ) {
    const owner = scopeFilter(scope),
      permit = await this.authorization.require(
        actor,
        "rotations:admin",
        owner,
      ),
      rotationId = randomUUID();
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await barrier(tx, owner.environment);
      const resource = await this.store.resources.findOne(
        {
          _id: resourceId,
          ...owner,
          kind: "encryption-key",
          enabled: true,
          revision: expectedRevision,
          deletedAt: { $exists: false },
        },
        { session: tx.session },
      );
      if (resource) assertAdministrativeValueAccess(resource, actor);
      if (
        !resource ||
        version.resourceId !== resourceId ||
        version.kind !== "encryption-key" ||
        version.environment !== owner.environment ||
        version.ownerType !== owner.ownerType ||
        version.ownerId !== owner.ownerId ||
        version.versionNumber !== resource.currentVersionNumber + 1 ||
        version.valueFormat !== resource.valueFormat ||
        version.schemaIdentity !== resource.schemaIdentity
      )
        throw Error("Vault key conflict");
      if (
        await tx.db
          .collection("vault_key_rotations")
          .findOne(
            { resourceId, environment: owner.environment, state: "prepared" },
            { session: tx.session },
          )
      )
        throw Error("Vault key conflict");
      await this.store.versions.insertOne(version, { session: tx.session });
      const plain = await this.store.readValue(
        owner,
        resourceId,
        version._id,
        tx,
      );
      try {
        const encoded = plain.toString(),
          key = Buffer.from(
            encoded,
            version.valueFormat === "hex64" ? "hex" : "base64",
          );
        try {
          if (
            key.length !== 32 ||
            (version.valueFormat === "hex64"
              ? !/^[a-fA-F0-9]{64}$/.test(encoded)
              : key.toString("base64") !== encoded)
          )
            throw Error("Invalid encryption key");
        } finally {
          key.fill(0);
        }
      } finally {
        plain.fill(0);
      }
      await tx.db.collection<any>("vault_key_rotations").insertOne(
        {
          _id: rotationId,
          ...owner,
          resourceId,
          oldVersionId: resource.currentVersionId,
          newVersionId: version._id,
          state: "prepared",
          revision: 1,
          createdAt: Date.now(),
        },
        { session: tx.session },
      );
      for (const [id, state] of [
        [resource.currentVersionId, "active-for-encryption"],
        [version._id, "prepared"],
      ])
        await tx.db
          .collection<any>("vault_key_version_states")
          .updateOne(
            { _id: id },
            { $set: { resourceId, ...owner, state } },
            { upsert: true, session: tx.session },
          );
      await tx.db
        .collection<any>("vault_key_version_states")
        .updateOne(
          { _id: version._id },
          { $set: { rotationId } },
          { session: tx.session },
        );
      await tx.db.collection<any>("vault_key_version_states").updateOne(
        { _id: resource.currentVersionId, keyLabel: { $exists: false } },
        {
          $set: {
            keyLabel:
              resource.currentVersionNumber === 1
                ? "v1"
                : resource.currentVersionId,
          },
        },
        { session: tx.session },
      );
      const instances = await tx.db
        .collection("vault_application_instances")
        .find(
          { environment: owner.environment, retired: false },
          { session: tx.session },
        )
        .toArray();
      for (const instance of instances)
        if (
          await affected(
            tx,
            instance.applicationId,
            owner.environment,
            resourceId,
          )
        )
          await tx.db
            .collection<any>("vault_key_rotation_participants")
            .insertOne(
              {
                _id: rotationId + ":" + instance._id,
                rotationId,
                environment: owner.environment,
                instanceId: instance._id,
                acknowledged: false,
                retired: false,
              },
              { session: tx.session },
            );
      await this.store.resources.updateOne(
        { _id: resourceId, ...owner, revision: expectedRevision },
        { $inc: { revision: 1 } },
        { session: tx.session },
      );
      return { rotationId, state: "prepared" };
    });
  }
  async status(actor: Actor, scope: ResourceScope, resourceId: string) {
    const owner = scopeFilter(scope),
      permit = await this.authorization.require(actor, "metadata:list", owner),
      result = await this.store.transaction(async (tx) => {
        const rotations = await tx.db
          .collection<any>("vault_key_rotations")
          .find({ ...owner, resourceId }, { session: tx.session })
          .sort({ createdAt: -1 })
          .limit(100)
          .toArray();
        const participants = await tx.db
          .collection("vault_key_rotation_participants")
          .find(
            {
              environment: owner.environment,
              rotationId: { $in: rotations.map((r) => r._id) },
            },
            { session: tx.session },
          )
          .limit(10001)
          .toArray();
        return { rotations, participants };
      });
    await this.authorization.assertCurrent(permit);
    return result;
  }
  async activate(actor: Actor, scope: ResourceScope, rotationId: string) {
    const owner = scopeFilter(scope),
      permit = await this.authorization.require(
        actor,
        "rotations:admin",
        owner,
      );
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await barrier(tx, owner.environment);
      const rotation = await tx.db
        .collection<any>("vault_key_rotations")
        .findOne(
          { _id: rotationId, ...owner, state: "prepared" },
          { session: tx.session },
        );
      if (!rotation) throw Error("Vault key conflict");
      const resource = await this.store.resources.findOne(
        { _id: rotation.resourceId, ...owner },
        { session: tx.session },
      );
      if (!resource) throw Error("Vault key conflict");
      assertAdministrativeValueAccess(resource, actor);
      const sensitiveLinks = await this.store.links
        .find(
          { resourceId: rotation.resourceId, environment: owner.environment },
          { session: tx.session },
        )
        .toArray();
      if (
        sensitiveLinks.some((l) =>
          /(?:INDEX_KEY|CONTROL_KEY|CLERK_ENCRYPTION_KEY)$/.test(l.accessName),
        ) &&
        !(await tx.db.collection("vault_key_migration_evidence").findOne(
          {
            rotationId,
            environment: owner.environment,
            oldVersionId: rotation.oldVersionId,
            newVersionId: rotation.newVersionId,
            verified: true,
            quiescent: true,
          },
          { session: tx.session },
        ))
      )
        throw Object.assign(
          Error("Verified application-side key migration is required"),
          { status: 409 },
        );
      const participants = await tx.db
        .collection<any>("vault_key_rotation_participants")
        .find(
          { rotationId, environment: owner.environment },
          { session: tx.session },
        )
        .toArray();
      assertActivationReady(participants as any);
      const version = await this.store.versions.findOne(
        {
          _id: rotation.newVersionId,
          resourceId: rotation.resourceId,
          ...owner,
        },
        { session: tx.session },
      );
      if (!version) throw Error("Vault key conflict");
      await this.store.resources.updateOne(
        {
          _id: rotation.resourceId,
          ...owner,
          currentVersionId: rotation.oldVersionId,
        },
        {
          $set: {
            currentVersionId: version._id,
            currentVersionNumber: version.versionNumber,
          },
          $inc: { revision: 1 },
        },
        { session: tx.session },
      );
      await tx.db
        .collection<any>("vault_key_version_states")
        .updateOne(
          { _id: rotation.oldVersionId },
          { $set: { state: "decrypt-only" } },
          { session: tx.session },
        );
      await tx.db
        .collection<any>("vault_key_version_states")
        .updateOne(
          { _id: version._id },
          { $set: { state: "active-for-encryption" } },
          { session: tx.session },
        );
      await tx.db.collection<any>("vault_key_rotations").updateOne(
        { _id: rotationId, state: "prepared" },
        {
          $set: { state: "active", activatedAt: Date.now() },
          $inc: { revision: 1 },
        },
        { session: tx.session },
      );
      return { state: "active" };
    });
  }
  async retireInstance(
    actor: Actor,
    scope: ResourceScope,
    instanceId: string,
    confirmation: string,
    reason: string,
  ) {
    const owner = scopeFilter(scope);
    if (
      owner.ownerType !== "application" ||
      confirmation !== `PERMANENTLY STOPPED ${instanceId}` ||
      typeof reason !== "string" ||
      !reason.trim() ||
      reason.length > 512
    )
      throw new AccessDenied();
    const permit = await this.authorization.require(
      actor,
      "rotations:admin",
      owner,
    );
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await barrier(tx, owner.environment);
      const result = await tx.db
        .collection<any>("vault_application_instances")
        .updateOne(
          {
            _id: instanceId,
            applicationId: owner.ownerId,
            environment: owner.environment,
            retired: false,
          },
          {
            $set: {
              retired: true,
              retiredBy: actor.issuer + "|" + actor.subject,
              retiredAt: Date.now(),
              retirementReason: reason,
            },
            $inc: { revision: 1 },
          },
          { session: tx.session },
        );
      if (result.matchedCount !== 1) throw new AccessDenied();
      await tx.db.collection("vault_key_rotation_participants").updateMany(
        { instanceId, environment: owner.environment },
        {
          $set: {
            retired: true,
            retiredBy: actor.issuer + "|" + actor.subject,
            retiredAt: Date.now(),
          },
        },
        { session: tx.session },
      );
      return { retired: true };
    });
  }
}
