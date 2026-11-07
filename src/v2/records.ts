export interface ResourceScope {
  environment: string;
  ownerType: "application" | "tenant";
  ownerId: string;
}
export type ResourceKind = "secret" | "encryption-key" | "integration";
export interface CipherPart {
  readonly iv: string;
  readonly ciphertext: string;
  readonly tag: string;
}
export interface ValueEnvelope extends CipherPart {
  readonly format: 1;
  readonly algorithm: "A256GCM";
  readonly wrappedKey: CipherPart;
}
export interface ResourceRecord extends ResourceScope {
  custody?: "admin-managed" | "workload-only";
  _id: string;
  name: string;
  kind: ResourceKind;
  contentType: string;
  valueFormat: "text" | "base64" | "hex64";
  schemaIdentity: string;
  enabled: boolean;
  revision: number;
  currentVersionId: string;
  currentVersionNumber: number;
  deletedAt?: number;
  linkFence?: number;
}
export interface ResourceVersion extends ResourceScope {
  _id: string;
  resourceId: string;
  versionNumber: number;
  kind: ResourceKind;
  contentType: string;
  valueFormat: "text" | "base64" | "hex64";
  schemaIdentity: string;
  createdAt: number;
  createdBy: string;
  value: ValueEnvelope;
}
export type GrantCapability =
  | "metadata:list"
  | "secrets:read"
  | "keys:export"
  | "resources:write"
  | "assignments:write"
  | "grants:admin"
  | "rotations:admin";
export interface GrantRecord {
  _id: string;
  tokenHash: string;
  authorizationFence?: number;
  grantClass: "application" | "interactive-provisioner" | "operator";
  applicationId?: string;
  environment: string;
  capabilities: GrantCapability[];
  enabled: boolean;
  revision: number;
  createdAt: number;
}
export interface ResourceLink {
  _id: string;
  applicationId: string;
  environment: string;
  tenantId?: string;
  resourceId: string;
  accessName: string;
  versionPolicy: "latest" | string;
  capability?: string;
  revision: number;
}
export interface AuditRecord {
  _id: string;
  environment: string;
  ownerType: ResourceScope["ownerType"];
  ownerId: string;
  actorId: string;
  action: string;
  targetId: string;
  at: number;
}
