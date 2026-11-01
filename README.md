# Local Key Vault

NestJS/TypeScript implementation of APP-35 for **local development**. It provisions manifest-defined keys with deterministic names, stores supplied secrets in an encrypted file, and loads tenant-scoped runtime snapshots. No secret copying into application `.env` files is needed after initial provisioning. This repository was empty; existing application/tenant lifecycle integrations are supplied as an integration contract below, not changes to another application's code.

## Run

Use Node.js 22 or newer and npm. Install and verify:

```sh
npm ci
npm run build
npm test
```

Supply bootstrap configuration through your shell, OS credential manager, or development launcher:

| Variable | Required | Meaning |
| --- | --- | --- |
| `VAULT_MASTER_KEY` | yes | Base64 encoding of exactly 32 random bytes, kept outside the store |
| `VAULT_GRANTS` | yes | JSON array of caller grants, shown below |
| `VAULT_STORE_PATH` | no | Default `.vault/store.vault`; use a dedicated private directory |
| `VAULT_BASE_URL` | no | Default `http://127.0.0.1:4567`; only loopback HTTP is accepted |

The following is a **configuration shape**, not usable credentials. Generate the master key and separate caller tokens with a cryptographically secure credential source; retain them securely across restarts. The service intentionally does not invent or print bootstrap credentials.

```json
[
  {
    "token": "<at-least-32-characters-of-random-token-material>",
    "environment": "dev",
    "tenant": "tenant-123",
    "permissions": ["read", "write", "crypto"]
  }
]
```

```sh
npm start
```

The process binds to `127.0.0.1`. Store directories must be owned by the process user and mode `0700`; existing store files must be mode `0600`, owned by that user, regular files with one hard link. New directories/files get those modes. Final directory/file symlinks are rejected. Use a trusted local filesystem and trusted parent directories. Do not place the store in a synchronized, shared or network directory. The master key and grants cannot be retrieved from this vault: this avoids circular bootstrap dependencies.

A lifetime `<store>.lock` prevents competing server processes. Clean shutdown releases it. After a crash, confirm the recorded PID is no longer running before manually removing the stale lock. Never delete an active process's lock. Ciphertext is AES-256-GCM with a fresh nonce per commit and authenticated format marker. Commits serialize, fsync a temporary ciphertext file and atomically rename it before publishing memory. This does not promise crash consistency on every filesystem or power-loss durability of directory entries; retain encrypted backups and the master key separately. Master-key rotation/recovery tooling is outside this subset.

## Callers and namespaces

All endpoints require a bearer token plus `x-vault-environment` and `x-vault-tenant`. Grants match these identifiers exactly. A `read` caller can read plaintext secrets in its own namespace; a `write` caller can create/rotate, update and delete; `crypto` permits operations on keys in that namespace. Reconciliation requires both `write` and `read` because it returns a complete snapshot. Bootstrap grants must be changed by a trusted launcher and require a service restart. HTTP errors contain safe codes, never input values or stack traces. Responses are `Cache-Control: no-store`; browser Origins are rejected and CORS is not enabled.

Environment and tenant identifiers are case-sensitive stable opaque IDs, 1–64 characters of letters/digits/underscore/hyphen starting with a letter or digit. `_shared` is reserved for process-scoped values. Do not use human names or identifiers that change on tenant rename.

Object IDs use `/namespaces/{environment}/{tenant}/keys|secrets/{name}/{version}`. Those paths can also be called with matching authorization headers; mismatched path/header namespaces fail. The shorter `/keys/...` and `/secrets/...` routes select their namespace from headers. This namespace selection and local bearer authentication are **local extensions**, not Azure Entra ID authentication.

## Automatic provisioning

Use [examples/manifest.json](examples/manifest.json) as an illustrative tenant manifest. Its purposes are examples; align the actual inventory with APP-28/APP-33 consumers before adoption. The schema is versioned independently from the monotonically increasing tenant configuration `revision`.

Each entry specifies a unique purpose and environment-name mapping, a key or secret kind, and tenant or process scope. Keys support RSA 2048/3072 with encrypt/decrypt usages only. Names are `kv-` followed by the complete lowercase SHA-256 digest of JSON `[environment,tenant,kind,purpose]`; they contain only provider-compatible characters, are stable across retries, and are 67 characters long. No manual vault names are required. Keep stable purpose identifiers when changing display names.

`POST /local/reconcile` with JSON:

```json
{
  "revision": 1,
  "manifest": {
    "schemaVersion": 1,
    "entries": [
      { "purpose": "data-encryption", "kind": "key", "scope": "tenant", "envName": "APP_DATA_KEY_ID", "kty": "RSA", "keySize": 2048, "keyOps": ["encrypt", "decrypt"] },
      { "purpose": "database", "kind": "secret", "scope": "tenant", "envName": "APP_DATABASE_URL" }
    ]
  },
  "secrets": { "database": "<provided-by-authorized-database-provisioner>" }
}
```

The transaction generates missing keys, stores supplied secrets, and returns complete mappings with namespace, generation, revision, manifest fingerprint and expiry. Key mappings contain versioned **key IDs**, never private keys. Secret mappings contain secret values for authorized server consumers. Encryption keys are generated only when absent. Concurrent retries and restarts reuse existing versions. A missing externally issued credential fails the whole transaction; credentials cannot be invented by the vault.

Same-revision retries must use the same normalized manifest and supplied-secret payload. Changed payloads or older revisions return `409 RevisionConflict`. On a newer revision, omitted secrets reuse existing active values; changed supplied secrets create versions. Keep an event's payload stable across retries, including its supplied secrets. Do not put supplied secrets into a tracked manifest file. Ordinary reconciliation will not regenerate deleted/disabled/expired keys, or accept a key with mismatched size/usages. Removed manifest entries stop being mapped but are retained in storage until explicitly retired.

`POST /local/snapshot` with `{ "manifest": <manifest> }` requires `read` and returns the complete currently validated snapshot. An unprovisioned or different manifest fails. These `/local` endpoints are extensions and do not take an Azure API version.

## Runtime startup and tenant changes

Import `RuntimeVault` from `src/runtime.ts` (or compiled `dist/runtime.js`) **only in server code**. It uses the local REST API, so consumers can run in another server process. It is not published as a package yet.

```ts
const runtime = new RuntimeVault({
  baseUrl: bootstrap.vaultUrl,
  token: scope => bootstrap.tokenFor(scope),
});
const scope = { environment: 'dev', tenant: tenant.id };

// Await this in a Nest async provider factory or bootstrap, before creating clients
// or marking that tenant ready. Externally issued credentials come from their
// authorized provisioner, not from application dotenv files.
const initial = await runtime.initialize(scope, manifest, tenant.configRevision, suppliedSecrets);
const db = createDatabaseClient(initial.mappings.APP_DATABASE_URL);

// An authenticated tenant/configuration event repeats initialization with its new
// revision and stable event payload, then recreates clients from the new snapshot.
const next = await runtime.initialize(scope, newManifest, event.revision, event.suppliedSecrets);
await replaceTenantClients(scope, next.mappings);

// After explicit vault rotation, fetch the complete new snapshot. The revision
// is a minimum accepted configuration revision; generation detects store changes.
await runtime.refresh(scope, manifest, tenant.configRevision);
const current = runtime.get(scope);
```

Wire tenant-creation events to `initialize` and configuration/rotation events to `initialize`/`refresh` in the consuming application. Authenticate those upstream events with the application's own mechanism; the vault independently authenticates every call. No event bus or existing consumers are present in this repository.

| Mapping category | Example | Initialization and refresh |
| --- | --- | --- |
| Tenant key reference | `APP_DATA_KEY_ID` | Tenant snapshot; crypto uses that explicit version; recreate dependent clients after refresh |
| Tenant secret | `APP_DATABASE_URL` | Tenant snapshot; recreate DB client/pool after refresh |
| Process secret | Application-specific mapping in `_shared` | Explicit process startup only; restart the consumer process to change `process.env` |
| Bootstrap | `VAULT_MASTER_KEY`, caller tokens | External source before vault/runtime initialization; never mapped from the manifest |

Tenant calls never modify `process.env`. Snapshots are complete and frozen, keyed by environment and tenant; refreshes serialize per namespace. Stale revision events are rejected and lower-generation responses cannot replace newer snapshots. Failed newer events retain their revision watermark; retry that revision or a newer one to restore readiness. No partial snapshot is published. Startup failure must keep dependent clients and application readiness off; the consumer must await the promise and propagate failure. See [the Nest async provider example](examples/nest-runtime-provider.ts).

For legacy process-only clients, `await runtime.initializeProcess(environment, processManifest, revision, suppliedSecrets)` only accepts `process` entries in reserved `_shared`. It validates all mappings before any writes, refuses conflicting existing values and will not silently overwrite on rotation. Existing identical values are allowed. Public frontend prefixes, `NODE_*`, `NPM_*`, `VAULT_*` and dangerous runtime/loader names are rejected. Application-selected mappings must still be reviewed for their own side effects. The service and library never emit values into frontend bundles; already bundled frontend configuration cannot be refreshed this way.

The default maximum snapshot age is **30 seconds** (callers can shorten it). `get` fails once expired. Refresh failures immediately invalidate that namespace: there is no stale fallback. Fetches time out after 5 seconds; retries are explicit, bounded by the consumer, using the same event revision/payload. `get` is unavailable while a refresh is in flight. Already obtained references cannot be remotely erased: consumers must stop using old clients/snapshots when they expire, a refresh fails or a tenant becomes unready. Revocation is observed on refresh/expiry, at most TTL for cooperating consumers; there is no distributed push invalidation. Each cryptographic operation independently checks current key status.

## Supported Azure contract

Every data-plane request requires exactly `?api-version=2025-07-01`. The tested subset follows Microsoft's [key create](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/create-key/create-key?view=rest-keyvault-keys-2025-07-01), [secret set](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret?view=rest-keyvault-secrets-2025-07-01) and [encryption](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/encrypt/encrypt?view=rest-keyvault-keys-2025-07-01) contracts. Contract tests assert the supported request/response/error shapes locally; they are not a live Azure conformance certification.

| Method and path | Supported behavior |
| --- | --- |
| `POST /keys/{name}/create` | RSA 2048 (default)/3072, `key_ops` encrypt/decrypt; **creates a new version**, including when name exists |
| `GET /keys/{name}[/{version}]` | Public JWK only; latest if version omitted |
| `GET /keys/{name}/versions` | Version metadata with `kid`, no private material |
| `PATCH /keys/{name}/{version}` | Attributes, tags, key operations |
| `DELETE /keys/{name}` | Permanently removes all versions locally; returns metadata |
| `POST /keys/{name}/{version}/encrypt` or `/decrypt` | `alg: RSA-OAEP-256`, base64url `value`; single RSA block, not bulk encryption |
| `PUT /secrets/{name}` | String value up to 25 KiB, optional attributes/contentType/tags; always creates a version |
| `GET /secrets/{name}[/{version}]` | Secret bundle with value; latest if version omitted |
| `GET /secrets/{name}/versions` | Version metadata without values |
| `PATCH /secrets/{name}/{version}` | Attributes, tags, contentType; metadata response omits the value so metadata writers cannot read existing secrets |
| `DELETE /secrets/{name}` | Permanently removes all versions locally; returns metadata without value |

Attributes support `enabled`, epoch-second `nbf` and `exp`; responses include created/updated times and `recoveryLevel: Purgeable`. Tags are limited to 15 string pairs, each key/value at most 512 characters. Names use letters/digits/hyphen, at most 127 characters. Unsupported fields and algorithms fail `400 BadParameter`; disabled, expired and not-yet-valid versions fail `403 Forbidden`. Errors use `{ "error": { "code": "...", "message": "..." } }`; missing resources are `404 KeyNotFound`/`SecretNotFound`.

### Rotation and deletion

Explicit key create / secret set creates a new version; retain old version IDs alongside encrypted data. Existing enabled versions remain usable, so ciphertext from before a rotation can still be decrypted. Disable a version with PATCH to revoke access, then refresh affected consumers. Delete removes **all** versions permanently and blocks ordinary reconciliation from recreating that purpose. To deliberately reprovision, perform an explicit administrative create/set first or introduce a new manifest purpose under a newer revision. Never delete a key needed for old data.

This subset does not implement soft deletion, recovery, purge, certificates, key import/export, symmetric/HSM keys, signing, backup/restore, rotation policies, list-all endpoints, pagination, Entra ID, TLS or comprehensive Azure SDK compatibility. Version lists return the complete local list without pagination. Metadata/delete responses and namespace-bearing IDs are explicitly limited local semantics. Use the narrow REST surface described here; do not treat this service as a drop-in replacement for the entire Azure service.

It is not an HSM or production security boundary. Local administrators/processes able to read bootstrap credentials can access the store. There is no live key generation, migration of existing secrets, credential change or deployment performed as part of this implementation. Freddie/Chris approval referenced by APP-35 is not implied by these tests or this code.
