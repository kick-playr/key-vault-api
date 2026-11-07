import { createHash, randomBytes, randomUUID } from "node:crypto";
import { AccessDenied } from "./authorization.js";
import {
  scopeFilter,
  type V2MongoStore,
  type V2Transaction,
} from "./mongo-store.js";
export const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export async function machineGrant(
  tx: V2Transaction,
  header: unknown,
  applicationId: string,
  environment: string,
) {
  scopeFilter({
    environment,
    ownerType: "application",
    ownerId: applicationId,
  });
  if (typeof header !== "string" || !/^Bearer [A-Za-z0-9_-]{43}$/.test(header))
    throw new AccessDenied();
  const grant = await tx.db.collection<any>("vault_grants").findOne(
    {
      tokenHash: hash(header.slice(7)),
      applicationId,
      environment,
      grantClass: "application",
      enabled: true,
    },
    { session: tx.session },
  );
  if (!grant) throw new AccessDenied();
  return grant;
}
export async function barrier(tx: V2Transaction, environment: string) {
  await tx.db
    .collection<any>("vault_rotation_barriers")
    .updateOne(
      { _id: environment },
      { $inc: { revision: 1 } },
      { upsert: true, session: tx.session },
    );
}
export async function affected(
  tx: V2Transaction,
  applicationId: string,
  environment: string,
  resourceId: string,
) {
  const link = await tx.db
    .collection("vault_resource_links")
    .findOne(
      { applicationId, environment, resourceId },
      { session: tx.session },
    );
  if (!link) return false;
  if (!link.tenantId) return true;
  return !!(await tx.db
    .collection("vault_application_tenants")
    .findOne(
      { applicationId, environment, tenantId: link.tenantId, enabled: true },
      { session: tx.session },
    ));
}
export class InstanceService {
  constructor(private readonly store: V2MongoStore) {}
  async register(header: unknown, applicationId: string, environment: string) {
    const instanceId = randomUUID(),
      password = randomBytes(32).toString("base64url");
    return this.store.transaction(async (tx) => {
      const grant = await machineGrant(tx, header, applicationId, environment);
      await barrier(tx, environment);
      if (
        !(await tx.db
          .collection("vault_application_environments")
          .findOne(
            { applicationId, environment, enabled: true },
            { session: tx.session },
          ))
      )
        throw new AccessDenied();
      await tx.db.collection<any>("vault_application_instances").insertOne(
        {
          _id: instanceId,
          applicationId,
          environment,
          grantId: grant._id,
          passwordHash: hash(password),
          retired: false,
          registeredAt: Date.now(),
          lastSeen: Date.now(),
          revision: 1,
        },
        { session: tx.session },
      );
      const rotations = await tx.db
        .collection("vault_key_rotations")
        .find({ environment, state: "prepared" }, { session: tx.session })
        .toArray();
      for (const rotation of rotations)
        if (await affected(tx, applicationId, environment, rotation.resourceId))
          await tx.db
            .collection<any>("vault_key_rotation_participants")
            .insertOne(
              {
                _id: rotation._id + ":" + instanceId,
                rotationId: rotation._id,
                instanceId,
                environment,
                acknowledged: false,
                retired: false,
              },
              { session: tx.session },
            );
      return { instanceId, password };
    });
  }
  async acknowledge(
    header: unknown,
    applicationId: string,
    environment: string,
    input: {
      instanceId: string;
      password: string;
      rotationId: string;
      versionId: string;
    },
  ) {
    return this.store.transaction(async (tx) => {
      const grant = await machineGrant(tx, header, applicationId, environment);
      await barrier(tx, environment);
      const instance = await tx.db
        .collection<any>("vault_application_instances")
        .findOne(
          {
            _id: input.instanceId,
            applicationId,
            environment,
            grantId: grant._id,
            retired: false,
            passwordHash: hash(input.password),
          },
          { session: tx.session },
        );
      if (!instance) throw new AccessDenied();
      const rotation = await tx.db
        .collection<any>("vault_key_rotations")
        .findOne(
          {
            _id: input.rotationId,
            environment,
            state: "prepared",
            newVersionId: input.versionId,
          },
          { session: tx.session },
        );
      if (
        !rotation ||
        !(await affected(tx, applicationId, environment, rotation.resourceId))
      )
        throw new AccessDenied();
      const result = await tx.db
        .collection<any>("vault_key_rotation_participants")
        .updateOne(
          {
            rotationId: input.rotationId,
            instanceId: input.instanceId,
            retired: false,
          },
          { $set: { acknowledged: true, acknowledgedAt: Date.now() } },
          { session: tx.session },
        );
      if (result.matchedCount !== 1) throw new AccessDenied();
      return { acknowledged: true };
    });
  }
}
