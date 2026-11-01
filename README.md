# Local Key Vault

NestJS/TypeScript implementation of APP-35 for **local development**. It provisions manifest-defined keys with deterministic names, stores supplied secrets in encrypted MongoDB documents, and loads tenant-scoped runtime snapshots. No secret copying into application `.env` files is needed after initial provisioning. This repository was empty; existing application/tenant lifecycle integrations are supplied as an integration contract below, not changes to another application's code.

## Run

Use **Node.js 24.x**, npm, and MongoDB 7 or 8. `.nvmrc` selects Node 24 (`nvm use`), and the package engine and Node type definitions target that major version. Tests require a local `mongod` executable (or `MONGOD_BINARY` pointing to one); they launch disposable loopback databases and never use your configured MongoDB URI. Install and verify:

```sh
npm ci
npm run build
npm test
```

The current dependency baseline is NestJS 12, MongoDB driver 7, and TypeScript 6. The project uses native ESM with explicit `.js` paths in TypeScript imports and NodeNext module resolution. `npm run start:dev` compiles TypeScript before launching Node; no ts-node loader is required. Jest runs through the supplied Node VM-modules flag and may print Node's experimental VM warning. TypeScript stays on 6 because the current ts-jest peer range excludes 7; `@types/node` stays on 24 even when a newer Node major is available.


Copy the bootstrap template and fill the required values:

```sh
cp env.example .env
chmod 600 .env
```

Both `npm start` and `npm run start:dev` read `.env` from the current working directory before validating bootstrap configuration. The server uses Node 24's built-in dotenv parser; no additional dotenv package is required. Existing exported environment variables take precedence. A missing `.env` is allowed when all required values come from the shell, credential manager or launcher. Invalid or unreadable configuration stops startup with safe diagnostics. `.env` is ignored by Git; [env.example](env.example) contains only blank credentials and illustrative shapes.

Supply the following bootstrap values:

| Variable | Required | Meaning |
| --- | --- | --- |
| `VAULT_MASTER_KEY` | yes | Base64 encoding of exactly 32 random bytes, kept outside the store |
| `VAULT_GRANTS` | yes | JSON array of caller grants, shown below |
| `VAULT_MONGODB_URI` | yes | Complete connection URL, e.g. `mongodb://127.0.0.1:27017/key-vault` |
| `VAULT_BASE_URL` | no | Default `http://127.0.0.1:4000`; only loopback HTTP is accepted |

Run `./create-grants.sh` to print a ready-to-copy `VAULT_GRANTS` assignment with a fresh random token for environment `dev`, tenant `tenant-123`, and `read`/`write`/`crypto`/`list` permissions. Copy that line into `.env`, adjusting the tenant/environment to your application, then restart the API.

The following is a **configuration shape**, not usable credentials. Generate the master key and separate caller tokens with a cryptographically secure credential source; retain them securely across restarts. The service intentionally does not invent or print bootstrap credentials.

```json
[
  {
    "token": "<at-least-32-characters-of-random-token-material>",
    "environment": "dev",
    "tenant": "tenant-123",
    "permissions": ["read", "write", "crypto", "list"]
  }
]
```

```sh
npm start
```

Startup errors identify the invalid configuration variable or failing phase (MongoDB URL, connection, database selection, key verifier, master-key verification or HTTP listener). Known error codes such as `ECONNREFUSED`, MongoDB authentication code `18`, permission code `13` and `EADDRINUSE` include actionable hints. For example:

```text
[startup] InvalidBootstrap: VAULT_GRANTS is missing or invalid JSON; use a quoted JSON array of caller grants in .env.
```

Use the original `VAULT_MASTER_KEY` when reconnecting to an existing database. Diagnostics report safe names/codes and static hints while keeping secret values and credential-bearing URLs out of output.

The vault HTTP process binds to `127.0.0.1`. MongoDB must already be available; startup checks its connection and an encrypted master-key verifier before accepting requests. Keep MongoDB credentials and the master key outside the database and outside source control. Configure a dedicated database/user with read/write access to `vault_metadata` and `vault_namespaces`; never grant callers direct database access. Use authentication and TLS for non-loopback MongoDB connections.

For an optional local MongoDB container, run:

```sh
docker compose up -d mongodb
```

Use the URL from `env.example`:

```dotenv
VAULT_MONGODB_URI=mongodb://127.0.0.1:27017/key-vault
```

MongoDB has a single configuration variable. The URL must include an explicit database path, such as `/key-vault`. Missing, empty or whitespace-only database paths stop startup with an `InvalidBootstrap` error before connecting; no default database is used. `authSource` specifies authentication and does not replace the required database path. Both `vault_namespaces` and `vault_metadata` use that same database. If your MongoDB requires credentials or TLS, include them in the URL. The optional Compose service runs without authentication and binds its published port to loopback for local development. It persists data in a named volume.

### MongoDB persistence and concurrency

The official MongoDB Node driver stores each tenant/environment namespace as one AES-256-GCM-encrypted document in `vault_namespaces`. Keys, secrets, versions, audit metadata, tombstones and reconciliation revisions remain inside the ciphertext. The only visible fields are a hashed namespace `_id`, format/storage revision, nonce, authentication tag and ciphertext. A separate encrypted verifier in `vault_metadata` rejects a wrong master key at startup; corruption of namespace ciphertext fails safely when that namespace is accessed. Nonces are fresh for every commit. Authentication binds ciphertext to both namespace ID and storage revision, preventing swapping documents or editing revision headers.

Each complete namespace mutation uses MongoDB's atomic single-document insert or conditional replacement. The update filter includes the previous storage revision; concurrent writers reload and retry conflicts up to 20 times, then return `409 StorageConflict`. This follows MongoDB's [atomic update guidance](https://www.mongodb.com/docs/manual/core/write-operations-atomicity/). No replica-set transaction or file lock is needed. Reads use the primary with majority read concern; writes require majority acknowledgement with a 5-second write-concern timeout. Driver connection/server-selection timeouts are 3 seconds and socket timeout is 5 seconds. Multiple vault instances must use the same database, master key, grants and canonical base URL.

The server keeps no plaintext namespace cache: reads and cryptographic operations reload current committed MongoDB state, so another server's rotation/revocation is visible without restarting. Runtime consumers still have the bounded snapshot cache described below. Database failures return safe `503 StoreUnavailable` errors without connection strings or driver diagnostics. A write timeout may mean the database committed but acknowledgement was lost; idempotent reconciliation can retry its original event payload safely. Raw key create/secret set requests retain their normal new-version semantics.

A namespace is limited to **8 MiB of serialized plaintext** (including retained versions and metadata), leaving room for base64 encoding below MongoDB's 16 MiB BSON document limit. Oversized writes fail atomically with `507 NamespaceTooLarge`; previous data remains intact. This bounded, per-namespace model keeps complete provisioning atomic on standalone local MongoDB. It is not intended for unlimited secret-version history or bulk data storage. Back up MongoDB and the master key separately. Ciphertext does not provide protection from rollback of a complete database backup; there is no external anti-rollback ledger or automatic master-key rotation.

The former file backend is removed. Existing `.vault` files are left untouched and are **not imported automatically**. If you already provisioned local keys, retain the old encrypted store and master key until an explicit migration is designed; starting with a new empty MongoDB database creates new keys and cannot decrypt data tied to the old keys. No migration was performed by this change.

## Swagger documentation

After starting or restarting the API, open [Swagger UI](http://127.0.0.1:4000/docs). The [OpenAPI JSON](http://127.0.0.1:4000/docs-json) is generated from the controller annotations at startup and can be downloaded for client tooling. Both use the configured API port.

The documentation includes every supported key/secret, version, crypto, reconciliation and snapshot endpoint, including namespace aliases, request/response schemas, errors, required permissions, tenant headers and the exact Azure API version. The local documentation pages/assets and JSON need no token. API operations still require authentication.

Endpoints are organized into **Provisioning**, **Runtime**, **Inventory**, **Keys**, **Secrets**, **Cryptography**, and **Namespace aliases**, each with a description. Namespace aliases are grouped separately to keep the primary operations easy to find. Sections start collapsed; expand the relevant group or use the filter box to narrow the list.

Click **Authorize** and paste a token from your `VAULT_GRANTS` configuration (without the `Bearer` prefix). For each request, fill `x-vault-environment` and `x-vault-tenant` to match that token's grant, and select `api-version=2025-07-01` for data-plane operations. Then use **Try it out**. These are real API calls; mutating operations create versions or permanently delete data.

Swagger UI uses local bundled assets, disables external validation and does not persist authorization tokens in browser storage. Same-origin browser API requests are accepted with the usual permissions; other Origins remain rejected, and CORS is disabled. Use the `127.0.0.1` URL shown above rather than `localhost`, matching the existing loopback host policy.

## Callers and namespaces

All endpoints require a bearer token plus `x-vault-environment` and `x-vault-tenant`. Grants match these identifiers exactly. A `read` caller can read plaintext secrets in its own namespace; a `write` caller can create/rotate, update and delete; `crypto` permits operations on keys in that namespace. The separate `list` permission grants access to latest-object metadata inventory without allowing secret values, runtime snapshots, writes or crypto. Existing version-history endpoints retain their `read` requirement. Reconciliation requires both `write` and `read` because it returns a complete snapshot. Bootstrap grants must be changed by a trusted launcher and require a service restart. HTTP errors contain safe codes, never input values or stack traces. Responses are `Cache-Control: no-store`; browser requests must use the same origin and CORS is not enabled.

Environment and tenant identifiers are case-sensitive stable opaque IDs, 1–64 characters of letters/digits/underscore/hyphen starting with a letter or digit. `_shared` is reserved for process-scoped values. Do not use human names or identifiers that change on tenant rename.

Object IDs use `/namespaces/{environment}/{tenant}/keys|secrets/{name}/{version}`. Those paths can also be called with matching authorization headers; mismatched path/header namespaces fail. The shorter `/keys/...` and `/secrets/...` routes select their namespace from headers. This namespace selection and local bearer authentication are **local extensions**, not Azure Entra ID authentication.

## Listing, inventory and metadata search

Add `list` to a caller's grant in `.env` and restart the API to enable inventory. Existing grants are not changed automatically. For a metadata-only caller, use `"permissions": ["list"]`; `read` does not imply `list`. The grant generator includes all four permissions for its default development caller.

Azure-compatible listing endpoints return latest-object metadata with versionless IDs:

```text
GET /keys?api-version=2025-07-01&maxresults=25
GET /secrets?api-version=2025-07-01&maxresults=25
```

The local extension combines keys and secrets, adding names, kind, latest version, versioned ID and purpose:

```text
GET /local/inventory?kind=secret&namePrefix=db-&enabled=false
GET /local/inventory?purpose=data-encryption
GET /local/inventory?tagName=owner&tagValue=team-a&expiresBefore=1800000000
```

All endpoints require the usual bearer token and tenant/environment headers and have matching `/namespaces/{environment}/{tenant}/...` aliases. Filters are ANDed: `kind=key|secret`, exact `name`, `namePrefix`, exact `purpose`, `enabled=true|false`, `expiresBefore` (inclusive Unix seconds), and paired `tagName`/`tagValue` (exact equality). General tag values are literal strings, not regexes. Azure list endpoints support only their standard version/pagination parameters. Local inventory takes no API version.

Both list and inventory responses use `{ "value": [...], "nextLink": "..." }`. `maxresults` is 1–25, default 25. Follow `nextLink` with the same authorization and namespace headers; it contains an opaque `$skiptoken`. Cursors expire after 15 minutes and bind namespace, endpoint, filters, page size and generation. Tampered/mismatched/expired cursors fail `400 InvalidContinuationToken`; a namespace mutation invalidates pagination with `409 PaginationInvalidated`, so restart from the first page. Empty or final pages omit `nextLink`.

Inventory includes disabled, expired and future-dated objects for auditing, but excludes permanently deleted objects and returns only each object's latest metadata. It never includes secret values, public JWKs or private key material. New manifest-provisioned keys/secrets receive a `purpose` tag; reconciliation-created secret versions retain existing tags. Existing versions are not automatically modified or rotated: tag legacy objects with metadata PATCH to search their purpose. Listing scans/decrypts only the authorized encrypted namespace; no plaintext search index is created.

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

The default maximum snapshot age is **30 seconds** (callers can shorten it). `get` fails once expired. Refresh failures immediately invalidate that namespace: there is no stale fallback. Fetches time out after 5 seconds; retries are explicit, bounded by the consumer, using the same event revision/payload. `get` is unavailable while a refresh is in flight. Already obtained references cannot be remotely erased: consumers must stop using old clients/snapshots when they expire, a refresh fails or a tenant becomes unready. Revocation is observed on refresh/expiry, at most TTL for cooperating consumers; there is no distributed push invalidation. Each cryptographic operation reads current MongoDB state and independently checks key status.

## Supported Azure contract

Every data-plane request requires exactly `?api-version=2025-07-01`. The tested subset follows Microsoft's [key create](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/create-key/create-key?view=rest-keyvault-keys-2025-07-01), [secret set](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret?view=rest-keyvault-secrets-2025-07-01) and [encryption](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/encrypt/encrypt?view=rest-keyvault-keys-2025-07-01) contracts. Contract tests assert the supported request/response/error shapes locally; they are not a live Azure conformance certification.

| Method and path | Supported behavior |
| --- | --- |
| `GET /keys` / `GET /secrets` | Paginated latest-object metadata; separate `list` permission, no key material or values |
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

This subset does not implement soft deletion, recovery, purge, certificates, key import/export, symmetric/HSM keys, signing, backup/restore, rotation policies, Entra ID, TLS or comprehensive Azure SDK compatibility. Version lists return the complete local list without pagination. Metadata/delete responses and namespace-bearing IDs are explicitly limited local semantics. Use the narrow REST surface described here; do not treat this service as a drop-in replacement for the entire Azure service.

It is not an HSM or production security boundary. Local administrators/processes able to read bootstrap credentials can access the database contents. There is no live key generation, migration of existing secrets, credential change or deployment performed as part of this implementation. Freddie/Chris approval referenced by APP-35 is not implied by these tests or this code.
