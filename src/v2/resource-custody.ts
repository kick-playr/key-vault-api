import { hasWorkloadOperator } from "./workload-operator.js";
import { AccessDenied, type Actor } from "./authorization.js";
import type { ResourceKind, ResourceScope } from "./records.js";
export type ResourceCustody = "admin-managed" | "workload-only";
type CustodyMetadata = Pick<ResourceScope, "ownerType"> &
  Partial<Pick<ResourceScope, "environment" | "ownerId">> & {
    kind: ResourceKind;
    custody?: ResourceCustody;
  };
/** Missing classification is fail-closed for application-owned material. */
export function effectiveCustody(resource: CustodyMetadata): ResourceCustody {
  if (
    resource.ownerType === "application" &&
    resource.kind === "encryption-key"
  )
    return "workload-only";
  return (
    resource.custody ??
    (resource.ownerType === "application" ? "workload-only" : "admin-managed")
  );
}
export function assertAdministrativeValueAccess(
  resource: CustodyMetadata,
  actor?: Actor,
): void {
  if (
    effectiveCustody(resource) === "workload-only" &&
    !hasWorkloadOperator(actor, resource as ResourceScope)
  )
    throw new AccessDenied();
}
/** Code-owned bootstrap mappings cannot be backed by human-managed resources. */
export function isWorkloadAccessName(name: string): boolean {
  return /(?:^|_)(?:CLERK_SECRET_KEY|MONGODB_URI|MONGO_URI|DATABASE_URL|REDIS_URL|INDEX_KEY|CONTROL_KEY|CREDENTIAL_KEY|PROXY_KEY|WRAPPING_KEY(?:_V[0-9]+)?|ENCRYPTION_KEY|MANAGER_INVITATION_FLOW_KEY)$/.test(
    name,
  );
}
