import type { ResourceScope } from "./records.js";
import { scopeFilter, type V2Transaction } from "./mongo-store.js";
export interface Actor {
  issuer: string;
  subject: string;
}
export interface RoleSnapshot {
  revision: string;
  globalAdmin: boolean;
  clubAdminTenantIds: readonly string[];
}
/** Implemented only by the server's verified identity/control-authority adapter. */
export interface RoleAuthority {
  roles(actor: Actor, scope: ResourceScope): Promise<RoleSnapshot>;
  fence?(
    actor: Actor,
    scope: ResourceScope,
    revision: string,
    tx: V2Transaction,
  ): Promise<void>;
}
export interface ConsentState {
  enabled: boolean;
  revision: number;
}
export interface ConsentReader {
  read(scope: ResourceScope): Promise<ConsentState | null>;
  fence?(
    scope: ResourceScope,
    revision: number,
    tx: V2Transaction,
  ): Promise<void>;
}
export type AdminAction =
  | "metadata:list"
  | "values:read"
  | "resources:write"
  | "links:write"
  | "grants:admin"
  | "rotations:admin"
  | "consent:write";
export interface Permit {
  readonly allowed: true;
}
export class AccessDenied extends Error {
  readonly status = 403;
  constructor() {
    super("Vault access denied");
  }
}
export class AuthorityUnavailable extends Error {
  readonly status = 503;
  constructor() {
    super("Vault authorization unavailable");
  }
}
interface Observation {
  actor: Actor;
  action: AdminAction;
  scope: ResourceScope;
  roles: string;
  roleRevision: string;
  consentRequired: boolean;
  consent: ConsentState | null;
}
export class Authorization {
  private readonly permits = new WeakMap<Permit, Observation>();
  constructor(
    private readonly authority: RoleAuthority,
    private readonly consents: ConsentReader,
  ) {}
  private async observe(
    actor: Actor,
    action: AdminAction,
    scope: ResourceScope,
  ): Promise<Observation> {
    const owner = scopeFilter(scope),
      identity = { issuer: actor.issuer, subject: actor.subject };
    if (
      ![identity.issuer, identity.subject].every(
        (v) =>
          typeof v === "string" &&
          v.length > 0 &&
          v.length <= 2048 &&
          !/[\x00-\x1f\x7f]/.test(v),
      )
    )
      throw new AccessDenied();
    let roles: RoleSnapshot, consent: ConsentState | null;
    try {
      roles = await this.authority.roles(identity, owner);
      consent =
        owner.ownerType === "tenant" ? await this.consents.read(owner) : null;
    } catch {
      throw new AuthorityUnavailable();
    }
    if (
      !roles ||
      typeof roles.revision !== "string" ||
      !roles.revision ||
      typeof roles.globalAdmin !== "boolean" ||
      !Array.isArray(roles.clubAdminTenantIds) ||
      roles.clubAdminTenantIds.some((id) => typeof id !== "string")
    )
      throw new AuthorityUnavailable();
    if (
      consent &&
      (typeof consent.enabled !== "boolean" ||
        !Number.isSafeInteger(consent.revision) ||
        consent.revision < 1)
    )
      throw new AuthorityUnavailable();
    const club =
        owner.ownerType === "tenant" &&
        roles.clubAdminTenantIds.includes(owner.ownerId),
      global = roles.globalAdmin;
    const known: AdminAction[] = [
      "metadata:list",
      "values:read",
      "resources:write",
      "links:write",
      "grants:admin",
      "rotations:admin",
      "consent:write",
    ];
    let allowed = false;
    if (known.includes(action)) {
      if (action === "consent:write") allowed = club;
      else if (action === "grants:admin")
        allowed =
          global &&
          (owner.ownerType === "application" || consent?.enabled === true);
      else if (owner.ownerType === "application") allowed = global;
      else
        allowed =
          club ||
          (global && (action === "metadata:list" || consent?.enabled === true));
    }
    if (!allowed) throw new AccessDenied();
    return {
      actor: identity,
      action,
      scope: owner,
      roleRevision: roles.revision,
      consentRequired:
        owner.ownerType === "tenant" &&
        !club &&
        action !== "metadata:list" &&
        action !== "consent:write",
      roles: JSON.stringify([
        roles.revision,
        global,
        [...roles.clubAdminTenantIds].sort(),
      ]),
      consent: consent
        ? { enabled: consent.enabled, revision: consent.revision }
        : null,
    };
  }
  async require(
    actor: Actor,
    action: AdminAction,
    scope: ResourceScope,
  ): Promise<Permit> {
    const observed = await this.observe(actor, action, scope),
      permit = Object.freeze({ allowed: true as const });
    this.permits.set(permit, observed);
    return permit;
  }
  async fence(permit: Permit, tx: V2Transaction): Promise<void> {
    await this.assertCurrent(permit);
    const observation = this.permits.get(permit)!;
    if (!this.authority.fence) throw new AuthorityUnavailable();
    await this.authority.fence(
      observation.actor,
      observation.scope,
      observation.roleRevision,
      tx,
    );
    if (observation.consentRequired) {
      if (!observation.consent?.enabled || !this.consents.fence)
        throw new AccessDenied();
      await this.consents.fence(
        observation.scope,
        observation.consent.revision,
        tx,
      );
    }
  }
  async assertCurrent(permit: Permit): Promise<void> {
    const original = this.permits.get(permit);
    if (!original) throw new AccessDenied();
    const current = await this.observe(
      original.actor,
      original.action,
      original.scope,
    );
    if (
      current.roles !== original.roles ||
      JSON.stringify(current.consent) !== JSON.stringify(original.consent)
    )
      throw new AccessDenied();
  }
}
