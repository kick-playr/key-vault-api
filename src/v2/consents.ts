import { randomUUID } from "node:crypto";
import {
  AccessDenied,
  type Actor,
  type Authorization,
  type ConsentReader,
} from "./authorization.js";
import {
  scopeFilter,
  type V2MongoStore,
  type V2Transaction,
} from "./mongo-store.js";
import type { AuditRecord, ResourceScope } from "./records.js";
interface ConsentRecord {
  _id: string;
  environment: string;
  tenantId: string;
  enabled: boolean;
  revision: number;
  changedAt: number;
  changedBy: string;
  authorizationFence: number;
}
function identity(scope: ResourceScope) {
  const owner = scopeFilter(scope);
  if (owner.ownerType !== "tenant") throw new AccessDenied();
  return {
    _id: owner.environment + "/" + owner.ownerId,
    environment: owner.environment,
    tenantId: owner.ownerId,
  };
}
export function consentReader(
  store: Pick<V2MongoStore, "transaction">,
): ConsentReader & {
  fence(
    scope: ResourceScope,
    expectedRevision: number,
    tx: V2Transaction,
  ): Promise<void>;
} {
  return {
    read: (scope) =>
      store.transaction(async (tx) => {
        const r = await tx.db
          .collection<ConsentRecord>("vault_tenant_admin_consents")
          .findOne(identity(scope), { session: tx.session });
        return r ? { enabled: r.enabled, revision: r.revision } : null;
      }),
    fence: async (scope, expectedRevision, tx) => {
      const result = await tx.db
        .collection<ConsentRecord>("vault_tenant_admin_consents")
        .updateOne(
          { ...identity(scope), enabled: true, revision: expectedRevision },
          { $inc: { authorizationFence: 1 } },
          { session: tx.session },
        );
      if (result.matchedCount !== 1) throw new AccessDenied();
    },
  };
}
export class ConsentService {
  constructor(
    private readonly store: Pick<V2MongoStore, "transaction">,
    private readonly authorization: Authorization,
  ) {}
  approve(actor: Actor, scope: ResourceScope, expectedRevision: number) {
    return this.save(actor, scope, expectedRevision, true);
  }
  revoke(actor: Actor, scope: ResourceScope, expectedRevision: number) {
    return this.save(actor, scope, expectedRevision, false);
  }
  private async save(
    actor: Actor,
    scope: ResourceScope,
    expectedRevision: number,
    enabled: boolean,
  ): Promise<{ enabled: boolean; revision: number }> {
    const target = identity(scope),
      permit = await this.authorization.require(actor, "consent:write", scope);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)
      throw Error("Vault document conflict");
    return this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      const collection = tx.db.collection<ConsentRecord>(
          "vault_tenant_admin_consents",
        ),
        current = await collection.findOne(target, { session: tx.session });
      if ((current?.revision ?? 0) !== expectedRevision)
        throw Error("Vault document conflict");
      const next: ConsentRecord = {
        ...target,
        enabled,
        revision: expectedRevision + 1,
        changedAt: Date.now(),
        changedBy: actor.issuer + "|" + actor.subject,
        authorizationFence: current?.authorizationFence ?? 0,
      };
      if (current) {
        const result = await collection.replaceOne(
          { ...target, revision: expectedRevision },
          next,
          { session: tx.session },
        );
        if (result.matchedCount !== 1) throw Error("Vault document conflict");
      } else await collection.insertOne(next, { session: tx.session });
      await tx.db
        .collection<AuditRecord>("vault_audit_events")
        .insertOne(
          {
            _id: randomUUID(),
            ...scopeFilter(scope),
            actorId: next.changedBy,
            action: enabled ? "consent.approve" : "consent.revoke",
            targetId: target._id,
            at: Date.now(),
          },
          { session: tx.session },
        );
      return { enabled, revision: next.revision };
    });
  }
}
