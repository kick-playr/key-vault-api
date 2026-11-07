import { createHash } from "node:crypto";
import { Authorization, AccessDenied, type Actor } from "./authorization.js";
import { bindProvisioning } from "./provisioning-proof.js";
import {
  scopeFilter,
  type V2MongoStore,
  type V2Transaction,
} from "./mongo-store.js";
import type { ResourceScope } from "./records.js";
const operators = new WeakMap<Actor, ResourceScope>();
export function hasWorkloadOperator(
  actor: Actor | undefined,
  resource: ResourceScope,
): boolean {
  const scope = actor && operators.get(actor);
  return (
    !!scope &&
    scope.environment === resource.environment &&
    scope.ownerType === resource.ownerType &&
    scope.ownerId === resource.ownerId
  );
}
/** Deployment-only library entry point. Never exposed by the interactive HTTP API.
 * The password must belong to a separately provisioned operator grant with an
 * explicit application scope. Every operation rechecks and fences that grant.
 */
export async function createWorkloadOperator(
  store: V2MongoStore,
  header: string,
  input: ResourceScope,
) {
  const scope = scopeFilter(input);
  if (
    scope.ownerType !== "application" ||
    !/^Bearer [A-Za-z0-9_-]{43}$/.test(header)
  )
    throw new AccessDenied();
  const tokenHash = createHash("sha256").update(header.slice(7)).digest("hex");
  async function observation(tx: V2Transaction) {
    const grant = await store.grants.findOne(
      {
        tokenHash,
        grantClass: "operator",
        environment: scope.environment,
        enabled: true,
      },
      { session: tx.session },
    );
    const enrollment =
      grant &&
      (await tx.db
        .collection("vault_grant_scopes")
        .findOne({ grantId: grant._id, ...scope }, { session: tx.session }));
    if (!grant || !enrollment) throw new AccessDenied();
    return { grant, enrollment };
  }
  const initial = await store.transaction(observation);
  const actor = bindProvisioning(
    { issuer: "vault:deployment-operator", subject: initial.grant._id },
    {
      grantId: initial.grant._id,
      revision: initial.grant.revision,
      environment: scope.environment,
      tokenHash,
      capabilities: initial.grant.capabilities,
    },
  );
  Object.freeze(actor);
  operators.set(actor, Object.freeze({ ...scope }));
  const authority = {
    async roles(identity: Actor, owner: ResourceScope) {
      if (
        identity.issuer !== actor.issuer ||
        identity.subject !== actor.subject ||
        JSON.stringify(scopeFilter(owner)) !== JSON.stringify(scope)
      )
        throw new AccessDenied();
      const { grant, enrollment } = await store.transaction(observation);
      if (grant.revision !== initial.grant.revision) throw new AccessDenied();
      return {
        revision: JSON.stringify([grant.revision, enrollment._id]),
        globalAdmin: true,
        clubAdminTenantIds: [],
      };
    },
    async fence(
      identity: Actor,
      owner: ResourceScope,
      revision: string,
      tx: V2Transaction,
    ) {
      if (
        identity.issuer !== actor.issuer ||
        identity.subject !== actor.subject ||
        JSON.stringify(scopeFilter(owner)) !== JSON.stringify(scope)
      )
        throw new AccessDenied();
      const { grant, enrollment } = await observation(tx);
      if (
        grant.revision !== initial.grant.revision ||
        revision !== JSON.stringify([grant.revision, enrollment._id])
      )
        throw new AccessDenied();
      const updated = await store.grants.updateOne(
        { _id: grant._id, tokenHash, enabled: true, revision: grant.revision },
        { $inc: { authorizationFence: 1 } },
        { session: tx.session },
      );
      if (updated.matchedCount !== 1) throw new AccessDenied();
      await tx.db
        .collection("vault_grant_scopes")
        .updateOne(
          { _id: enrollment._id },
          { $inc: { authorizationFence: 1 } },
          { session: tx.session },
        );
    },
  };
  return {
    actor,
    authorization: new Authorization(authority, { read: async () => null }),
  };
}
