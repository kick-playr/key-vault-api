export interface Scope { environment: string; tenant: string }
export interface KeySetDescriptor {
  reference: string;
  mappings: { wrapping: string; index: string; control: string };
  wrappingVersions: { keyVersion: string; vaultVersion: string }[];
  currentWrappingVersion: string;
  indexVersion: string;
  controlVersion: string;
}
export interface SecretDescriptor { mapping: string; purpose: string; version: string }
export interface RuntimeSnapshotRequest {
  schemaVersion: 1; bindingRevision: number; bindingDigest: string;
  keySets: KeySetDescriptor[]; secrets: SecretDescriptor[];
}
export interface Attributes { enabled: boolean; created: number; updated: number; recoveryLevel: 'Purgeable'; nbf?: number; exp?: number }
export interface ResolvedValue { vaultVersion: string; value: string; attributes: Attributes }
export interface RuntimeKeySet {
  reference: string; mappings: KeySetDescriptor['mappings']; currentWrappingVersion: string;
  wrappingVersions: (ResolvedValue & { keyVersion: string })[];
  index: ResolvedValue; control: ResolvedValue;
}
export interface RuntimeSnapshot {
  schemaVersion: 1; environment: string; tenant: string; bindingRevision: number; bindingDigest: string;
  generation: number; loadedAt: number; keySets: RuntimeKeySet[];
  secrets: (SecretDescriptor & { value: string; attributes: Attributes })[];
}
export type Strategy = 'ENV_VARIABLES' | 'LOCAL_KEYVAULT';
export interface ProcessPolicy { allowedMappings: readonly string[]; requiredMappings?: readonly string[] }
export interface ProcessSecrets { strategy: Strategy; mappings: Readonly<Record<string, string>>; snapshot?: RuntimeSnapshot }
export interface SecretsRuntime {
  load(scope: Scope, request: RuntimeSnapshotRequest): Promise<RuntimeSnapshot>;
  loadProcess(application: string, policy: ProcessPolicy): Promise<ProcessSecrets>;
  loadTenant(tenant: string, bindingRevision: number): Promise<RuntimeSnapshot>;
  close(): void;
}
export function selectSecretsStrategy(environment?: Record<string, string | undefined>): Strategy;
export function bindingDigest(request: Omit<RuntimeSnapshotRequest, 'bindingDigest'> | RuntimeSnapshotRequest): string;
export function parseSnapshotRequest(input: unknown): RuntimeSnapshotRequest;
export function snapshotMappings(snapshot: RuntimeSnapshot): Readonly<Record<string, string>>;
export function createSecretsRuntime(options: { environment: Record<string, string | undefined>; fetch?: typeof globalThis.fetch; credentialSupplier?: (scope: Readonly<Scope>) => string | Promise<string> }): SecretsRuntime;
