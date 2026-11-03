import type { SecretValueFormat } from './secret-value-format.js';
import type { RuntimeManifest } from '@kick-playr/local-key-vault/runtime-client';
import type { RuntimeInstanceRecord } from './application-runtime.js';
import type { JsonWebKey } from 'node:crypto';
export interface Attributes { enabled: boolean; created: number; updated: number; nbf?: number; exp?: number; recoveryLevel: 'Purgeable' }
export interface Version {
  oauthRenewal?: {mapping: string; operationId: string; previousVersion: string};
  version: string; attributes: Attributes; tags?: Record<string, string>; contentType?: string;
  valueFormat?: SecretValueFormat; value?: string; privateKey?: JsonWebKey; publicKey?: JsonWebKey; keySize?: number; keyOps?: string[];
}
export interface OAuthCredential {
 application: 'club-api'; provider: 'bexio' | 'dropbox'; purpose: string; anchorVersion: string; currentVersion: string; versions: string[];
 attempts: {operationId: string; expectedVersion: string; version?: string; digest?: string}[];
}
export interface ResourceAssociation { envName: string; memberships: Record<string, string> }
export interface Namespace {
  runtimeTenantPublications?:Record<string,string>;
  runtimePublicationReservation?:string;
  runtimeLinkPublications?:Record<string,{baseGeneration:number;applicationRevision:number;associations:Record<string,ResourceAssociation>}>;
  runtimeIdentities?: Record<string,import('./runtime-identity.js').RuntimeIdentity>;
  runtimeConfiguration?: import('./runtime-configuration.js').RuntimeConfigurationRecord;
  internalScope?: Scope;
  deletedApplications?: string[];
  applicationReservations?: Record<string,Record<string,boolean>>;
  applications?: Record<string, { displayName: string; description: string; liveEnabled?: boolean }>;
  resourceAssociations?: Record<string, ResourceAssociation>;
  applicationRevision?: number;
  runtimeInstances?: Record<string, RuntimeInstanceRecord>;
  oauthCredentials?: Record<string, OAuthCredential>;
  generation: number; keys: Record<string, Version[]>; secrets: Record<string, Version[]>;
  tombstones: string[];
  runtimeManifests?: Record<string, { currentRevision: number; versions: Record<string, RuntimeManifest> }>;
  reconciliation?: { revision: number; digest: string; manifestDigest: string };
  audit: { time: number; action: string; name: string }[];
}
export interface Scope { environment: string; tenant: string }
export const scopeId = (scope: Scope) => JSON.stringify([scope.environment, scope.tenant]);
export function emptyNamespace(): Namespace {
  return { generation: 0, keys: {}, secrets: {}, tombstones: [], audit: [] };
}
