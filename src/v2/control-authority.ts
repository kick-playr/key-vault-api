import { provisioningProof } from "./provisioning-proof.js";
import { createHash } from "node:crypto";
import {
  AccessDenied,
  type Actor,
  type RoleAuthority,
  type RoleSnapshot,
} from "./authorization.js";
import {
  scopeFilter,
  type V2MongoStore,
  type V2Transaction,
} from "./mongo-store.js";
import { databaseNames } from "./database-names.js";
import type { ResourceScope } from "./records.js";
/** Control data is authoritative; Vault never maintains a second editable club-admin list. Both databases must use the same transaction-capable Mongo deployment. */
export class ControlRoleAuthority implements RoleAuthority {
  constructor(
    private readonly store: Pick<V2MongoStore, "transaction">,
    private readonly requireProvisioning = false,
  ) {}
  private async observation(
    actor: Actor,
    input: ResourceScope,
    tx: V2Transaction,
  ) {
    const scope = scopeFilter(input),
      db = tx.db.client.db(databaseNames.control),
      opts = { session: tx.session };
    const proof = provisioningProof(actor);
    if (this.requireProvisioning && !proof) throw new AccessDenied();
    let provisioning;
    if (proof) {
      provisioning = await tx.db
        .collection<any>("vault_grants")
        .findOne(
          {
            _id: proof.grantId,
            revision: proof.revision,
            environment: scope.environment,
            tokenHash: proof.tokenHash,
            grantClass: "interactive-provisioner",
            enabled: true,
          },
          opts,
        );
      if (
        !provisioning ||
        !(await tx.db
          .collection("vault_grant_scopes")
          .findOne(
            {
              grantId: proof.grantId,
              environment: scope.environment,
              ownerType: scope.ownerType,
              $or: [
                { ownerId: scope.ownerId },
                ...(scope.ownerType === "application"
                  ? [{ ownerId: "*" }]
                  : []),
              ],
            },
            opts,
          ))
      )
        throw new AccessDenied();
    }
    const policy = await db
      .collection("vault_identity_policies")
      .findOne({ environment: scope.environment, enabled: true }, opts);
    const global =
      policy?.issuer === actor.issuer &&
      Array.isArray(policy.adminSubjects) &&
      policy.adminSubjects.includes(actor.subject);
    const definition =
      scope.ownerType === "tenant"
        ? await db
            .collection("tenantDefinitions")
            .findOne(
              { id: scope.ownerId, environment: scope.environment },
              opts,
            )
        : null;
    const authority =
      scope.ownerType === "tenant"
        ? await db
            .collection("tenantRuntimeAuthorities")
            .findOne(
              { tenantId: scope.ownerId, environment: scope.environment },
              opts,
            )
        : null;
    const users = Array.isArray(authority?.users)
      ? authority.users.filter(
          (u: any) => u.issuer === actor.issuer && u.subject === actor.subject,
        )
      : [];
    const club = !!(
      definition?.status === "active" &&
      authority?.schema === 1 &&
      authority.status === "active" &&
      definition.configRevision === authority.configRevision &&
      authority.identityRealm === actor.issuer &&
      Array.isArray(authority.hostnames) &&
      authority.hostnames.includes(definition.hostname) &&
      users.length === 1 &&
      users[0].status === "active" &&
      Array.isArray(users[0].permissions) &&
      ["club:settings:read", "club:settings:write"].every((p) =>
        users[0].permissions.includes(p),
      )
    );
    const revision = createHash("sha256")
      .update(
        JSON.stringify([
          policy?.revision,
          policy?.issuer,
          policy?.adminSubjects,
          definition?.configRevision,
          definition?.status,
          authority?.authorityRevision,
          authority?.status,
          authority?.identityRealm,
          authority?.hostnames,
          users,
        ]),
      )
      .digest("hex");
    const roles: RoleSnapshot = {
      revision,
      globalAdmin: !!global,
      clubAdminTenantIds: club ? [scope.ownerId] : [],
    };
    return { roles, policy, definition, authority, db, provisioning };
  }
  roles(actor: Actor, scope: ResourceScope) {
    return this.store.transaction(
      async (tx) => (await this.observation(actor, scope, tx)).roles,
    );
  }
  async fence(
    actor: Actor,
    scope: ResourceScope,
    revision: string,
    tx: V2Transaction,
  ) {
    const o = await this.observation(actor, scope, tx);
    if (o.roles.revision !== revision) throw new AccessDenied();
    if (o.provisioning)
      await tx.db
        .collection<any>("vault_grants")
        .updateOne(
          { _id: o.provisioning._id, revision: o.provisioning.revision },
          { $inc: { authorizationFence: 1 } },
          { session: tx.session },
        );
    // Writes conflict with concurrent revocations/definition replacements in the same cluster.
    if (o.policy)
      await o.db
        .collection("vault_identity_policies")
        .updateOne(
          { _id: o.policy._id },
          { $inc: { vaultAuthorizationFence: 1 } },
          { session: tx.session },
        );
    if (o.definition)
      await o.db
        .collection("tenantDefinitions")
        .updateOne(
          { _id: o.definition._id },
          { $inc: { vaultAuthorizationFence: 1 } },
          { session: tx.session },
        );
    if (o.authority)
      await o.db
        .collection("tenantRuntimeAuthorities")
        .updateOne(
          { _id: o.authority._id },
          { $inc: { vaultAuthorizationFence: 1 } },
          { session: tx.session },
        );
  }
}
