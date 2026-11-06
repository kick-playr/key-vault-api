import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  AccessDenied,
  type Actor,
  type Authorization,
} from "./authorization.js";
import type { V2MongoStore, V2Transaction } from "./mongo-store.js";
import type { AuditRecord, GrantRecord } from "./records.js";
export type GrantMetadata = Omit<GrantRecord, "tokenHash">;
export interface DeliveryApproval {
  readonly applicationId: string;
  readonly environment: string;
  readonly approvedTenantIds: readonly string[];
  /** Recheck/fence approved enrollment, custody and consent in the publishing transaction. */
  fence(transaction: V2Transaction): Promise<void>;
  /** Trusted deployment-only staging channel; preserve the active deployment credential until publication is confirmed. Never a value returned to the administrator UI. */
  deliver(password: string): Promise<void>;
}
export interface GrantDelivery {
  approve(
    actor: Actor,
    applicationId: string,
    environment: string,
  ): Promise<DeliveryApproval>;
}
const metadata = (record: GrantRecord): GrantMetadata => {
  const { tokenHash: _, ...publicMetadata } = record;
  return publicMetadata;
};
const conflict = () => Error("Vault grant conflict");
export class GrantService {
  constructor(
    private readonly store: Pick<V2MongoStore, "grants" | "transaction">,
    private readonly authorization: Authorization,
    private readonly delivery: GrantDelivery,
  ) {}
  async authorize(
    header: unknown,
    applicationId: string,
    environment: string,
  ): Promise<GrantRecord> {
    if (
      typeof header !== "string" ||
      header.length !== 50 ||
      !/^Bearer [A-Za-z0-9_-]{43}$/.test(header)
    )
      throw new AccessDenied();
    const tokenHash = createHash("sha256")
        .update(header.slice(7))
        .digest("hex"),
      grant = await this.store.grants.findOne({ tokenHash });
    if (
      !grant ||
      !grant.enabled ||
      grant.grantClass !== "application" ||
      grant.applicationId !== applicationId ||
      grant.environment !== environment
    )
      throw new AccessDenied();
    return grant;
  }
  async rotate(
    actor: Actor,
    id: string,
    expectedRevision: number,
  ): Promise<GrantMetadata> {
    const current = await this.store.grants.findOne({ _id: id });
    if (
      !current ||
      current.grantClass !== "application" ||
      !current.applicationId
    )
      throw conflict();
    return this.issue(actor, {
      applicationId: current.applicationId,
      environment: current.environment,
      replaces: { id, revision: expectedRevision },
    });
  }
  async revoke(
    actor: Actor,
    id: string,
    expectedRevision: number,
  ): Promise<void> {
    const record = await this.store.grants.findOne({ _id: id });
    if (!record || record.grantClass !== "application" || !record.applicationId)
      throw conflict();
    const scope = {
        environment: record.environment,
        ownerType: "application" as const,
        ownerId: record.applicationId,
      },
      permit = await this.authorization.require(actor, "grants:admin", scope);
    await this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      const changed = await this.store.grants.updateOne(
        {
          _id: id,
          applicationId: record.applicationId,
          environment: record.environment,
          enabled: true,
          revision: expectedRevision,
        },
        { $set: { enabled: false }, $inc: { revision: 1 } },
        { session: tx.session },
      );
      if (changed.matchedCount !== 1) throw conflict();
      await tx.db
        .collection<AuditRecord>("vault_audit_events")
        .insertOne(
          {
            _id: randomUUID(),
            ...scope,
            actorId: actor.issuer + "|" + actor.subject,
            action: "grant.revoke",
            targetId: id,
            at: Date.now(),
          },
          { session: tx.session },
        );
    });
  }
  async issue(
    actor: Actor,
    input: {
      applicationId: string;
      environment: string;
      replaces?: { id: string; revision: number };
    },
  ): Promise<GrantMetadata> {
    const scope = {
      environment: input.environment,
      ownerType: "application" as const,
      ownerId: input.applicationId,
    };
    const permit = await this.authorization.require(
        actor,
        "grants:admin",
        scope,
      ),
      approval = await this.delivery.approve(
        actor,
        input.applicationId,
        input.environment,
      );
    if (
      approval.applicationId !== input.applicationId ||
      approval.environment !== input.environment
    )
      throw new AccessDenied();
    const approved = new Set(approval.approvedTenantIds);
    // Resolve ownership and the membership revision under a coherent pre-delivery observation.
    const observation = await this.store.transaction(async (tx) => {
      const deployment = await tx.db
        .collection("vault_application_environments")
        .findOne(
          {
            applicationId: input.applicationId,
            environment: input.environment,
            enabled: true,
          },
          { session: tx.session },
        );
      if (
        !deployment ||
        !Number.isSafeInteger(deployment.revision) ||
        deployment.revision < 1
      )
        throw conflict();
      const active = await this.store.grants.findOne(
        {
          applicationId: input.applicationId,
          environment: input.environment,
          grantClass: "application",
          enabled: true,
        },
        { session: tx.session },
      );
      if (
        input.replaces
          ? !active ||
            active._id !== input.replaces.id ||
            active.revision !== input.replaces.revision
          : !!active
      )
        throw conflict();
      const tenants = await tx.db
        .collection("vault_application_tenants")
        .find(
          {
            applicationId: input.applicationId,
            environment: input.environment,
            enabled: true,
          },
          { session: tx.session },
        )
        .toArray();
      if (
        tenants.some(
          (t) => typeof t.tenantId !== "string" || !approved.has(t.tenantId),
        )
      )
        throw new AccessDenied();
      return deployment.revision as number;
    });
    const password = randomBytes(32).toString("base64url"),
      record: GrantRecord = {
        _id: randomUUID(),
        tokenHash: createHash("sha256").update(password).digest("hex"),
        grantClass: "application",
        applicationId: input.applicationId,
        environment: input.environment,
        capabilities: ["metadata:list", "secrets:read", "keys:export"],
        enabled: false,
        revision: 1,
        createdAt: Date.now(),
      };
    await this.store.grants.insertOne(record);
    await approval.deliver(password);
    await this.store.transaction(async (tx) => {
      await this.authorization.fence(permit, tx);
      await approval.fence(tx);
      const guard = await tx.db
        .collection("vault_application_environments")
        .updateOne(
          {
            applicationId: input.applicationId,
            environment: input.environment,
            revision: observation,
            enabled: true,
          },
          { $inc: { authorizationFence: 1 } },
          { session: tx.session },
        );
      if (guard.matchedCount !== 1) throw conflict();
      if (input.replaces) {
        const old = await this.store.grants.updateOne(
          {
            _id: input.replaces.id,
            applicationId: input.applicationId,
            environment: input.environment,
            grantClass: "application",
            enabled: true,
            revision: input.replaces.revision,
          },
          { $set: { enabled: false }, $inc: { revision: 1 } },
          { session: tx.session },
        );
        if (old.matchedCount !== 1) throw conflict();
      } else if (
        await this.store.grants.findOne(
          {
            applicationId: input.applicationId,
            environment: input.environment,
            grantClass: "application",
            enabled: true,
          },
          { session: tx.session },
        )
      )
        throw conflict();
      const activated = await this.store.grants.updateOne(
        { _id: record._id, enabled: false, revision: 1 },
        { $set: { enabled: true }, $inc: { revision: 1 } },
        { session: tx.session },
      );
      if (activated.matchedCount !== 1) throw conflict();
      await tx.db
        .collection<AuditRecord>("vault_audit_events")
        .insertOne(
          {
            _id: randomUUID(),
            ...scope,
            actorId: actor.issuer + "|" + actor.subject,
            action: input.replaces ? "grant.rotate" : "grant.issue",
            targetId: record._id,
            at: Date.now(),
          },
          { session: tx.session },
        );
    });
    return metadata({ ...record, enabled: true, revision: 2 });
  }
}
