import type { SchemaObject } from '@nestjs/swagger';

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const text = { type: 'string' as const };
const tags: SchemaObject = { type: 'object', maxProperties: 15, additionalProperties: { type: 'string', maxLength: 512 } };
const ops: SchemaObject = { type: 'array', minItems: 1, maxItems: 2, uniqueItems: true, items: { type: 'string', enum: ['encrypt', 'decrypt'] }, default: ['encrypt', 'decrypt'] };
const purpose = { type: 'string' as const, pattern: '^[a-zA-Z0-9-]{1,127}$' };
const entry = {
  purpose, scope: { type: 'string' as const, enum: ['tenant', 'process'], description: 'Use process only with reserved tenant _shared.' },
  envName: { type: 'string' as const, pattern: '^[A-Z][A-Z0-9_]{0,127}$', description: 'Server-only mapping; public prefixes and dangerous runtime variable names are rejected.' },
};
const obj = (properties: SchemaObject['properties'], required: string[] = []): SchemaObject => ({ type: 'object', additionalProperties: false, properties, ...(required.length ? { required } : {}) });
export const schemas: Record<string, SchemaObject> = {
  KeyTreeNode: obj({ name: text, children: { type: 'array', items: ref('KeyTreeNode') }, envName: text, secretName: text, id: { type: 'string', format: 'uri' }, version: text, versionId: { type: 'string', format: 'uri' }, attributes: ref('Attributes') }, ['name']),
  TenantKeyTree: obj({ environment: text, tenant: text, keySets: { type: 'array', items: obj({ name: text, profile: text, children: { type: 'array', items: ref('KeyTreeNode') } }, ['name', 'profile', 'children']) } }, ['environment', 'tenant', 'keySets']),
  Session: obj({ authenticated: { type: 'boolean', enum: [true] }, environment: text, tenant: text }, ['authenticated', 'environment', 'tenant']),
  InputAttributes: obj({ enabled: { type: 'boolean', default: true }, nbf: { type: 'integer', minimum: 0, description: 'Not-before epoch seconds.' }, exp: { type: 'integer', minimum: 0, description: 'Expiry epoch seconds; must be after nbf.' } }),
  Attributes: { type: 'object', properties: { enabled: { type: 'boolean' }, nbf: { type: 'integer' }, exp: { type: 'integer' }, created: { type: 'integer' }, updated: { type: 'integer' }, recoveryLevel: { type: 'string', enum: ['Purgeable'] } }, required: ['enabled', 'created', 'updated', 'recoveryLevel'] },
  SetSecret: obj({ value: { type: 'string', maxLength: 25600, description: 'At most 25 KiB of UTF-8 bytes.' }, attributes: ref('InputAttributes'), tags, contentType: { type: 'string', maxLength: 255 } }, ['value']),
  CreateKey: obj({ kty: { type: 'string', enum: ['RSA'] }, key_size: { type: 'integer', enum: [2048, 3072], default: 2048 }, key_ops: ops, attributes: ref('InputAttributes'), tags }, ['kty']),
  PatchSecret: obj({ attributes: ref('InputAttributes'), tags, contentType: { type: 'string', maxLength: 255 } }),
  PatchKey: obj({ attributes: ref('InputAttributes'), tags, key_ops: ops }),
  SecretBundle: { type: 'object', properties: { id: { type: 'string', format: 'uri' }, value: text, attributes: ref('Attributes'), tags, contentType: text }, required: ['id', 'value', 'attributes'] },
  SecretMetadata: { type: 'object', properties: { id: { type: 'string', format: 'uri' }, attributes: ref('Attributes'), tags, contentType: text }, required: ['id', 'attributes'] },
  KeyBundle: { type: 'object', properties: { key: obj({ kid: { type: 'string', format: 'uri' }, kty: { type: 'string', enum: ['RSA'] }, n: text, e: text, key_ops: ops }, ['kid', 'kty', 'n', 'e', 'key_ops']), attributes: ref('Attributes'), tags }, required: ['key', 'attributes'] },
  KeyMetadata: { type: 'object', properties: { kid: { type: 'string', format: 'uri' }, attributes: ref('Attributes'), tags }, required: ['kid', 'attributes'] },
  SecretVersions: { type: 'object', properties: { value: { type: 'array', items: ref('SecretMetadata') } }, required: ['value'] },
  KeyVersions: { type: 'object', properties: { value: { type: 'array', items: ref('KeyMetadata') } }, required: ['value'] },
  CryptoInput: obj({ alg: { type: 'string', enum: ['RSA-OAEP-256'] }, value: { type: 'string', pattern: '^[A-Za-z0-9_-]*$', maxLength: 8192, description: 'Canonical unpadded base64url. Encrypt supports one RSA block (190 bytes for 2048-bit keys, 318 for 3072-bit keys).' } }, ['alg', 'value']),
  CryptoResult: obj({ kid: { type: 'string', format: 'uri' }, value: { type: 'string', description: 'Base64url result.' } }, ['kid', 'value']),
  KeyEntry: obj({ ...entry, kind: { type: 'string', enum: ['key'] }, kty: { type: 'string', enum: ['RSA'] }, keySize: { type: 'integer', enum: [2048, 3072], default: 2048 }, keyOps: ops }, ['purpose', 'kind', 'scope', 'envName', 'kty']),
  SecretEntry: obj({ ...entry, kind: { type: 'string', enum: ['secret'] } }, ['purpose', 'kind', 'scope', 'envName']),
  Manifest: obj({ schemaVersion: { type: 'integer', enum: [1] }, entries: { type: 'array', minItems: 1, maxItems: 100, items: { oneOf: [ref('KeyEntry'), ref('SecretEntry')] }, description: 'Purposes and environment mappings must each be unique.' } }, ['schemaVersion', 'entries']),
  Reconcile: obj({ revision: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, manifest: ref('Manifest'), secrets: { type: 'object', additionalProperties: { type: 'string', maxLength: 25600 }, description: 'Provided credentials keyed by manifest purpose. Never supply private key material.' } }, ['revision', 'manifest']),
  SnapshotRequest: obj({ manifest: ref('Manifest') }, ['manifest']),
  Snapshot: obj({ environment: text, tenant: text, generation: { type: 'integer' }, revision: { type: 'integer' }, manifestDigest: text, expiresAt: { type: 'integer', description: 'Expiry in Unix milliseconds; at most 30 seconds.' }, mappings: { type: 'object', additionalProperties: text, description: 'Secret values or versioned public key references; server consumers only.' } }, ['environment', 'tenant', 'generation', 'revision', 'manifestDigest', 'expiresAt', 'mappings']),
  RuntimeMappings: obj({ wrapping: entry.envName, index: entry.envName, control: entry.envName }, ['wrapping', 'index', 'control']),
  RuntimeWrappingPin: obj({ keyVersion: text, vaultVersion: { type: 'string', pattern: '^[a-f0-9]{32}$' } }, ['keyVersion', 'vaultVersion']),
  RuntimeKeySetDescriptor: obj({ reference: text, mappings: ref('RuntimeMappings'), wrappingVersions: { type: 'array', minItems: 1, maxItems: 100, items: ref('RuntimeWrappingPin') }, currentWrappingVersion: text, indexVersion: text, controlVersion: text }, ['reference', 'mappings', 'wrappingVersions', 'currentWrappingVersion', 'indexVersion', 'controlVersion']),
  RuntimeSecretDescriptor: obj({ mapping: entry.envName, purpose, version: text }, ['mapping', 'purpose', 'version']),
  RuntimeSnapshotRequest: obj({ schemaVersion: { type: 'integer', enum: [1] }, bindingRevision: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, bindingDigest: { type: 'string', pattern: '^[a-f0-9]{64}$' }, keySets: { type: 'array', maxItems: 100, items: ref('RuntimeKeySetDescriptor') }, secrets: { type: 'array', maxItems: 100, items: ref('RuntimeSecretDescriptor') } }, ['schemaVersion', 'bindingRevision', 'bindingDigest', 'keySets', 'secrets']),
  RuntimeResolvedValue: obj({ vaultVersion: text, value: text, attributes: ref('Attributes') }, ['vaultVersion', 'value', 'attributes']),
  RuntimeWrappingValue: obj({ keyVersion: text, vaultVersion: text, value: text, attributes: ref('Attributes') }, ['keyVersion', 'vaultVersion', 'value', 'attributes']),
  RuntimeKeySet: obj({ reference: text, mappings: ref('RuntimeMappings'), currentWrappingVersion: text, wrappingVersions: { type: 'array', items: ref('RuntimeWrappingValue') }, index: ref('RuntimeResolvedValue'), control: ref('RuntimeResolvedValue') }, ['reference', 'mappings', 'currentWrappingVersion', 'wrappingVersions', 'index', 'control']),
  RuntimeSecret: obj({ mapping: entry.envName, purpose, version: text, value: text, attributes: ref('Attributes') }, ['mapping', 'purpose', 'version', 'value', 'attributes']),
  RuntimeSnapshot: obj({ schemaVersion: { type: 'integer', enum: [1] }, environment: text, tenant: text, bindingRevision: { type: 'integer' }, bindingDigest: text, generation: { type: 'integer' }, loadedAt: { type: 'integer', description: 'Startup load time, not a TTL. Loaded values remain in memory until restart.' }, keySets: { type: 'array', items: ref('RuntimeKeySet') }, secrets: { type: 'array', items: ref('RuntimeSecret') } }, ['schemaVersion', 'environment', 'tenant', 'bindingRevision', 'bindingDigest', 'generation', 'loadedAt', 'keySets', 'secrets']),
  VaultError: obj({ error: obj({ code: text, message: text }, ['code', 'message']) }, ['error']),
  KeyInventory: obj({ value: { type: 'array', items: ref('KeyMetadata') }, nextLink: { type: 'string', format: 'uri' } }, ['value']),
  SecretInventory: obj({ value: { type: 'array', items: ref('SecretMetadata') }, nextLink: { type: 'string', format: 'uri' } }, ['value']),
  InventoryItem: obj({ name: text, kind: { type: 'string', enum: ['key', 'secret'] }, id: { type: 'string', format: 'uri' }, version: text, versionId: { type: 'string', format: 'uri' }, attributes: ref('Attributes'), tags, purpose: text, contentType: text }, ['name', 'kind', 'id', 'version', 'versionId', 'attributes']),
  Inventory: obj({ value: { type: 'array', items: ref('InventoryItem') }, nextLink: { type: 'string', format: 'uri' } }, ['value']),
};
