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
| `VAULT_MONGODB_URI` | yes | Complete connection URL, e.g. `mongodb://127.0.0.1:27017/key-vault` |
| `VAULT_BASE_URL` | no | Default `http://127.0.0.1:4000`; only loopback HTTP is accepted |
| `VAULT_AUDIT_DESTINATIONS` | no | JSON routing per operation category; defaults write/crypto to MongoDB and read/list to console. See [audit logging](docs/AUDIT.md). |

Every shell script supports `--help` (or `-h`) with its own usage, arguments and examples, without compiling or connecting to MongoDB: `./create-key.sh --help`, `./create-grants.sh --help`, `./migrate-grants.sh --help`, `./rotate.sh --help`, `./grants.sh --help`, `./import-fcrww-keys.sh --help`, and `./create-tenant-keys.sh --help`.

### Configure simple vault startup

Consumers authenticate with their scoped grants and discover published application
manifests directly from the vault. They do not need generated bindings environment
variables. Use the existing `grants.sh` administration commands for access, and
[the one-time manifest publisher](docs/BINDINGS.md) to configure references.

Create the first persisted grant (MongoDB must be running):

```sh
./create-grants.sh dev tenant-123 read,write,crypto,list
```

The command prints JSON containing the grant ID, scope, permissions and a fresh bearer token. Save the token securely: it is shown only at creation and cannot be recovered from MongoDB. With no arguments, the script uses `dev`, `tenant-123` and all four permissions. The master key stays in `.env`; generate it with `./create-key.sh` and retain it across restarts.

For an existing installation, import its current tokens before removing `VAULT_GRANTS`:

```sh
./migrate-grants.sh
# After success, remove the VAULT_GRANTS assignment from .env and restart the API.
```

Migration reads the legacy JSON array from `.env` or exported variables, preserving token values, exact scopes and permissions. It combines permissions for duplicate token/namespace entries and validates the whole array before one atomic update and prints imported/skipped counts without tokens. Repeating the import skips existing grants, including revoked grants, so stale configuration cannot restore access or old permissions. The API never reads `VAULT_GRANTS` for authorization and never imports it automatically. With an empty grant registry, the server starts but denies every API caller until a grant is created/imported. CLI wrappers compile the current sources before running and use the project-root `.env` (exported values take precedence).

Grant administration is local to the trusted operator with MongoDB access and the master key. There is no grant-management HTTP endpoint; an API bearer token cannot create grants or expand its permissions:

```sh
./grants.sh list
./grants.sh permissions <grant-id> read,list
./grants.sh revoke <grant-id>
./rotate.sh <grant-id>
```

`list` includes enabled and revoked grants but excludes token hashes and tokens. Revocation disables the grant permanently; create a new grant/token to replace it. `./rotate.sh <grant-id>` atomically disables an active grant and creates a replacement with a new ID and token, preserving its environment, tenant and current permissions. Save the printed replacement token immediately and update callers; the old token stops working at commit, with no overlap or restart. The token is shown only once. Rotation refuses revoked grants and preserves their records so re-importing old tokens cannot restore access. Concurrent rotations of one grant permit only one replacement. Permission edits do not reactivate a revoked grant. Creating, changing permissions and revoking take effect on subsequent requests across running server instances without restart. An already authorized in-flight request may complete.

```sh
npm start
```

Startup errors identify the invalid configuration variable or failing phase (MongoDB URL, connection, database selection, key verifier, master-key verification or HTTP listener). Known error codes such as `ECONNREFUSED`, MongoDB authentication code `18`, permission code `13` and `EADDRINUSE` include actionable hints. For example:

```text
[startup] InvalidBootstrap: VAULT_MASTER_KEY is missing or invalid; supply the base64 encoding of exactly 32 bytes.
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

MongoDB has a single configuration variable. The URL must include an explicit database path, such as `/key-vault`. Missing, empty or whitespace-only database paths stop startup with an `InvalidBootstrap` error before connecting; no default database is used. `authSource` specifies authentication and does not replace the required database path. All of `vault_namespaces`, `vault_metadata` and `vault_grants` use that same database. If your MongoDB requires credentials or TLS, include them in the URL. The optional Compose service runs without authentication and binds its published port to loopback for local development. It persists data in a named volume.

### MongoDB persistence and concurrency

The official MongoDB Node driver stores each tenant/environment namespace as one AES-256-GCM-encrypted document in `vault_namespaces`. Keys, secrets, versions, audit metadata, tombstones and reconciliation revisions remain inside the ciphertext. The only visible fields are a hashed namespace `_id`, format/storage revision, nonce, authentication tag and ciphertext. A separate encrypted verifier in `vault_metadata` rejects a wrong master key at startup; corruption of namespace ciphertext fails safely when that namespace is accessed. Nonces are fresh for every commit. Authentication binds ciphertext to both namespace ID and storage revision, preventing swapping documents or editing revision headers.

Each complete namespace mutation uses MongoDB's atomic single-document insert or conditional replacement. The update filter includes the previous storage revision; concurrent writers reload and retry conflicts up to 20 times, then return `409 StorageConflict`. This follows MongoDB's [atomic update guidance](https://www.mongodb.com/docs/manual/core/write-operations-atomicity/). No replica-set transaction or file lock is needed. Reads use the primary with majority read concern; writes require majority acknowledgement with a 5-second write-concern timeout. Driver connection/server-selection timeouts are 3 seconds and socket timeout is 5 seconds. Multiple vault instances must use the same database, master key and canonical base URL.

The server keeps no plaintext namespace cache: reads and cryptographic operations reload current committed MongoDB state, so another server's rotation/revocation is visible without restarting. Runtime consumers still have the bounded snapshot cache described below. Database failures return safe `503 StoreUnavailable` errors without connection strings or driver diagnostics. A write timeout may mean the database committed but acknowledgement was lost; idempotent reconciliation can retry its original event payload safely. Raw key create/secret set requests retain their normal new-version semantics.

A namespace is limited to **8 MiB of serialized plaintext** (including retained versions and metadata), leaving room for base64 encoding below MongoDB's 16 MiB BSON document limit. Oversized writes fail atomically with `507 NamespaceTooLarge`; previous data remains intact. This bounded, per-namespace model keeps complete provisioning atomic on standalone local MongoDB. It is not intended for unlimited secret-version history or bulk data storage. Back up MongoDB and the master key separately. Ciphertext does not provide protection from rollback of a complete database backup; there is no external anti-rollback ledger or automatic master-key rotation.

The former file backend is removed. Existing `.vault` files are left untouched and are **not imported automatically**. If you already provisioned local keys, retain the old encrypted store and master key until an explicit migration is designed; starting with a new empty MongoDB database creates new keys and cannot decrypt data tied to the old keys. No migration was performed by this change.

## Tenant key naming and tree

Every key set belongs to the exact authorized environment/tenant namespace. Its logical reference is `<profile>:<tenant>:key`, for example `workflow-local:fcrww:key`. Profiles use lowercase kebab-case (at most 48 characters); the tenant must match the selected grant scope exactly. Profile and environment are separate: the logical profile name does not infer a deployment environment or the source variable prefix.

```text
development/
└── fcrww/
    └── workflow-local:fcrww:key/
        ├── wrapping/
        │   └── v1  -> WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1
        ├── index   -> WORKFLOW_REAL_FCRWW_INDEX_KEY
        └── control -> WORKFLOW_REAL_FCRWW_CONTROL_KEY
```

Each leaf is an encrypted secret with a deterministic Azure-compatible physical name `tk-<role>-<sha256>`. The full hash includes environment, tenant, logical key-set reference and role path, preventing collisions caused by replacing colons/slashes with hyphens. Tags retain `keySet`, `keyProfile`, `keyRole`, `logicalPath`, `envName`, `purpose` and `source`. The explicit environment-variable mapping is preserved exactly; `workflow-local` does not rename the provided `WORKFLOW_REAL_...` variables. `wrapping/v1` is the supplied wrapping-key generation; the vault also maintains its own immutable version IDs. Index/control names stay stable.

`GET /local/key-tree` (and its namespace alias) returns the selected tenant tree under the separate `list` permission. Leaves include env names, physical names, versioned IDs and attributes, never values or key material. Disabled/expired leaves remain visible for auditing; permanently deleted leaves disappear. Other namespaces are not queried. Legacy unstructured secrets remain accessible by their existing names and ordinary inventory; they are not silently renamed or assigned to a key set. Re-import into the chosen named set is explicit and never deletes legacy records. No runtime binding changes happen automatically.

## Create a new tenant key set

```sh
./create-tenant-keys.sh
```

The script prompts for the **environment, tenant and key-set name** when they are not supplied as parameters. It prompts privately for the grant token unless `VAULT_TOKEN` or `--token` supplies it. Key names are automatic: `WORKFLOW_REAL_<TENANT>_WRAPPING_KEY_V1`, `WORKFLOW_REAL_<TENANT>_INDEX_KEY`, and `WORKFLOW_REAL_<TENANT>_CONTROL_KEY` (uppercase tenant, hyphens replaced by underscores).

For the three key values, choose either hidden prompts (default) or an explicitly selected dotenv file:

```sh
# Ask for environment, tenant, key-set name and hidden key values.
./create-tenant-keys.sh

# Read matching keys from this file; still ask for tenant and other metadata.
# Missing/blank key entries are prompted privately.
./create-tenant-keys.sh --env-file /path/to/source.env

# Optionally provide non-secret metadata as parameters instead of prompting.
./create-tenant-keys.sh --environment development --tenant fcrww \
  --name workflow-local:fcrww:key --env-file /path/to/source.env
```

Relative source paths resolve from the caller's working directory. The selected source dotenv is parsed without execution and never modified; no FCRWW file is discovered automatically, and key values are not taken from exported variables. Raw key-value command-line options are rejected. Complete supplied strings are preserved exactly and must be distinct canonical Base64-encoded 32-byte values. Before writes, the script displays only each last three characters and the exact logical reference/namespace/mappings, then requires `yes`. Other responses, Ctrl+C or EOF cancel.

`--generate` explicitly generates three fresh random 256-bit keys instead of file/manual input; it cannot be combined with `--env-file`. `--yes` explicitly pre-approves the final confirmation while retaining the suffix preview. Fully non-interactive use needs all metadata, a grant token, a complete `--env-file` (or `--generate`) and `--yes`.

The grant requires exact scoped `read` and `write`. All three writes are atomic and create-only: existing/deleted sets and concurrent races cannot overwrite, rotate or reactivate keys. No full values are printed or written to plaintext files. The vault project bootstrap `.env` supplies MongoDB/master-key configuration even when invoked from another directory, with exported bootstrap variables taking precedence. The API can remain stopped. View metadata via `/local/key-tree` with `list` permission; runtime bindings are not changed automatically. Run `./create-tenant-keys.sh --help` for all options.

## Import existing FCRWW encryption keys

`import-fcrww-keys.sh` asks for a key-set name and the three existing canonical Base64-encoded 32-byte symmetric key values. It never reads the FCRWW `.env`. The role/environment-name mappings are shown in the tree above.

Use an existing grant token with **read and write** for the exact target namespace. For FCRWW the defaults are environment `development`, tenant `fcrww`. Other permissions can remain on the grant; `crypto` is not required to import raw symmetric key strings as secrets.

```sh
./import-fcrww-keys.sh development fcrww
```

Enter the grant bearer token, then the key-set name `workflow-local:fcrww:key`, wrapping key, index key and control key when prompted. Input is hidden; paste only each raw value without quotes or variable assignments. Before import, the script shows the last three characters of each validated key (including Base64 padding) and the target namespace. Type `yes` to proceed; any other answer cancels without importing. An exported `VAULT_TOKEN` skips the token prompt. Keys are always entered interactively, never read from files or environment variables. Ctrl+C or EOF cancels without importing keys; an interactive terminal is required.

The script connects directly to MongoDB using the vault project's `VAULT_MONGODB_URI` and `VAULT_MASTER_KEY`, so the API can remain stopped. It compiles current sources first. Only the vault bootstrap `.env` is read; exported bootstrap variables take precedence.

The grant is checked on every atomic-write attempt. All three entered keys must be present, valid and distinct. Original strings are preserved without key generation or rotation. All three secrets commit in one namespace transaction: identical existing active values are skipped, while conflicting values or inactive/deleted targets abort the whole import. Repeating or concurrently repeating the same import does not generate new secret versions. The confirmation displays only the final three characters per key; final output contains namespace, names and imported/skipped counts. Full key values, token hashes and bearer tokens are never printed.

This imports storage only. Keep the source `.env` keys until Kick-Playr's runtime bindings are explicitly changed and verified to load the vault secrets. Its current `env:` references do not switch automatically. The import does not modify source files or Kick-Playr configuration. Run `./import-fcrww-keys.sh --help` for standalone usage.

## Swagger documentation

After starting or restarting the API, open [Swagger UI](http://127.0.0.1:4000/docs). The [OpenAPI JSON](http://127.0.0.1:4000/docs-json) is generated from the controller annotations at startup and can be downloaded for client tooling. Both use the configured API port.

The documentation includes every supported key/secret, version, crypto, reconciliation and snapshot endpoint, including namespace aliases, request/response schemas, errors, required permissions, tenant headers and the exact Azure API version. The local documentation pages/assets and JSON need no token. API operations still require authentication.

Endpoints are organized into **Provisioning**, **Runtime**, **Inventory**, **Keys**, **Secrets**, **Cryptography**, and **Namespace aliases**, each with a description. Namespace aliases are grouped separately to keep the primary operations easy to find. Sections start collapsed; expand the relevant group or use the filter box to narrow the list.

Click **Authorize** and paste a token saved when creating a grant (or retained from migration) (without the `Bearer` prefix). For each request, fill `x-vault-environment` and `x-vault-tenant` to match that token's grant, and select `api-version=2025-07-01` for data-plane operations. Then use **Try it out**. These are real API calls; mutating operations create versions or permanently delete data.

Swagger UI uses local bundled assets, disables external validation and does not persist authorization tokens in browser storage. Same-origin browser API requests are accepted with the usual permissions; other Origins remain rejected, and CORS is disabled. Use the `127.0.0.1` URL shown above rather than `localhost`, matching the existing loopback host policy.

## Callers and namespaces

All endpoints require a bearer token plus `x-vault-environment` and `x-vault-tenant`. Grants match these identifiers exactly. A `read` caller can read plaintext secrets in its own namespace; a `write` caller can create/rotate, update and delete; `crypto` permits operations on keys in that namespace. The separate `list` permission grants access to latest-object metadata inventory without allowing secret values, runtime snapshots, writes or crypto. Existing version-history endpoints retain their `read` requirement. Reconciliation requires both `write` and `read` because it returns a complete snapshot. Grants are stored in an AES-256-GCM-encrypted `vault_grants` registry containing only SHA-256 token hashes, exact scopes, permissions, IDs and enabled status. Authorization reloads it from MongoDB on each request; a database failure fails closed with `503 StoreUnavailable`. Registry writes use the same atomic revision/CAS model as namespace writes, with a separate authenticated ID and collection. The registry has the same 8 MiB plaintext limit as a namespace. Manage grants through the local CLI; grants are never returned by the data-plane API. HTTP errors contain safe codes, never input values or stack traces. Responses are `Cache-Control: no-store`; browser requests must use the same origin and CORS is not enabled.

Environment and tenant identifiers are case-sensitive stable opaque IDs, 1–64 characters of letters/digits/underscore/hyphen starting with a letter or digit. `_shared` is reserved for process-scoped values. Do not use human names or identifiers that change on tenant rename.

Object IDs use `/namespaces/{environment}/{tenant}/keys|secrets/{name}/{version}`. Those paths can also be called with matching authorization headers; mismatched path/header namespaces fail. The shorter `/keys/...` and `/secrets/...` routes select their namespace from headers. This namespace selection and local bearer authentication are **local extensions**, not Azure Entra ID authentication.

## Listing, inventory and metadata search

Use `./grants.sh permissions <grant-id> read,write,crypto,list` to enable inventory for an existing full-access caller without restarting. Existing grants are not changed automatically. For a metadata-only caller, use `"permissions": ["list"]`; `read` does not imply `list`. The grant generator includes all four permissions for its default development caller.

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

### Connection authentication

`GET /local/session` (also under the namespace alias) validates the complete bearer token and selected environment/tenant without accessing resources. Any enabled grant in that exact scope can connect, even if it has only write or crypto permission. Response: `{ "authenticated": true, "environment": "...", "tenant": "..." }`. Altered/suffixed/truncated tokens return 401; a valid token for a different scope returns 403. No token, hash or grant list is returned. The endpoint is local and does not take an API version. Restart the running API to load this endpoint after upgrading.

## APP-36 read-only startup snapshots

`POST /local/runtime-snapshot` (or its `/namespaces/{environment}/{tenant}` alias) reads a complete, explicitly version-pinned set from **one** committed namespace document. It requires only `read`, exact namespace headers and bearer authentication. It never reconciles, creates, rotates or repairs resources. The request body is limited to 64 KiB, at most 100 resolved values; responses are limited to 4 MiB and marked `no-store`. There is no Azure `api-version` query on this local extension.

The v1 request contains `schemaVersion`, a positive `bindingRevision`, `bindingDigest`, `keySets` and `secrets`. Named sets retain `<profile>:<tenant>:key` and the existing `tk-<role>-<hash>` physical names. `wrappingVersions` associates each application `keyVersion` with an exact immutable `vaultVersion`; `currentWrappingVersion`, `indexVersion` and `controlVersion` pin the complete set. Historical wrapping pins remain readable for old ciphertext if those versions remain enabled. Ordinary secret descriptors `{mapping,purpose,version}` resolve the existing `kv-<hash>` purpose convention. No naming or data migration happens. The current endpoint rejects `latest`; operators must select/review immutable versions through existing metadata/version tools before preparing an operational binding.

The response echoes the exact namespace/revision/digest and includes namespace `generation`, `loadedAt`, the complete key sets and ordinary secret values with version/status metadata. These are **server-only values**; never expose this endpoint through a browser proxy without a separately reviewed authorization and display policy. A missing, inactive, mismatched or denied member fails the entire read. Revisions are correlation values supplied by trusted consumer configuration, not a proof that the vault validated a separate control database revision. No cross-namespace atomicity or backup-rollback protection is claimed.

### Server-only consumer module

The root package exports `@kick-playr/local-key-vault/runtime-client` as dependency-free CommonJS with CJS/ESM TypeScript declarations. It does not import Nest or require the vault master key/database bootstrap. Install a reviewed immutable source revision, not a workstation path or floating branch.

```js
const { bindingDigest, createSecretsRuntime } = require('@kick-playr/local-key-vault/runtime-client');
const request = {
  schemaVersion: 1,
  bindingRevision: 1,
  keySets: [],
  secrets: [{ mapping: 'WORKFLOW_SHARED_WRAPPING_KEY_V1', purpose: 'shared-configuration-key', version: '<immutable-32-hex-version>' }],
};
request.bindingDigest = bindingDigest(request); // Only after replacing the version placeholder.
// Put {schemaVersion:1,applications:{'club-api':{scope:{environment:'development',tenant:'_shared'},request}},tenants:[]}
// into LOCAL_KEYVAULT_BINDINGS_JSON. This is reference metadata, never values.
const runtime = createSecretsRuntime({ environment: process.env });
const loaded = await runtime.loadProcess('club-api', {
  allowedMappings: ['WORKFLOW_SHARED_WRAPPING_KEY_V1'],
  requiredMappings: ['WORKFLOW_SHARED_WRAPPING_KEY_V1'],
});
// Validate application-specific key format, then inject only process-scoped values
// before dependent imports/client construction. Tenant values never enter process.env.
```

`SECRETS_KEYS_STRATEGY` absent defaults to `ENV_VARIABLES`; only exact `ENV_VARIABLES` or `LOCAL_KEYVAULT` are accepted. Environment mode returns only caller-allowlisted values with existing missing/optional semantics. Vault mode requires `NODE_ENV=development` (or isolated test mode), rejects Vercel/AWS serverless activation and production namespaces, and has **no environment-secret fallback**. `LOCAL_KEYVAULT_URL` defaults to `http://127.0.0.1:4000` and must be a credential-free loopback HTTP origin.

`LOCAL_KEYVAULT_AUTH_JSON` is the initial local authentication exception:

```json
{"schemaVersion":1,"grants":[{"environment":"development","tenant":"_shared","token":"<application-specific-read-only-token>"}]}
```

Use one exact per-application/per-namespace read-only grant; no wildcard lookup or file-token fallback. Never use an operator write token for runtime. All other application secrets, including the shared configuration key, belong in the vault in LOCAL_KEYVAULT mode. The vault service's own unseal/master key is a separate infrastructure root. A server may inject a `credentialSupplier(scope)` for a reviewed authentication adapter; the default local adapter reads the scoped environment JSON. This does not enable cloud mode; cloud hosting/workload identity remains APP-47.

`LOCAL_KEYVAULT_BINDINGS_JSON` has exact `{schemaVersion:1,applications:{[application]:{scope,request}},tenants:[{scope,request}]}` shape. Process applications must use `_shared` and ordinary-secret descriptors. At most 16 application descriptors and 32 distinct tenants are accepted. Tenant descriptors must come from server-owned reviewed configuration. `loadTenant(tenant, bindingRevision)` requires its exact configured revision; it cannot create a new binding from a request header. Consumers must additionally check trusted current control revisions before admission so changed/new tenants require restart.

Calls use only the read-only snapshot route, a five-second request timeout, at most two retries for transport/503 failures (250/500ms backoff), a shared 30-second startup-read budget, bounded JSON responses and no redirects. Denied/missing/mismatched reads are not retried. Every response is checked for exact scope, revision/digest, mapping set, immutable versions and active attributes before publishing a deeply frozen snapshot. `snapshotMappings` extracts the current wrapping/index/control plus ordinary secrets and rejects duplicate/public/loader mappings. Application-specific format validation remains the consumer's responsibility.

Loaded snapshots are retained **until process restart**, with no 30-second TTL. A later vault outage/rotation/revocation does not erase already disclosed memory; restart/recycle consumers to pick up changes or revoke cached use. At next startup the pinned versions must still be authorized and active. `close()` cancels in-flight work and drops caches; JavaScript strings/already returned references cannot be remotely erased. This restart-based contract deliberately differs from the earlier `RuntimeVault` reconcile/refresh helper, which must not be used for normal APP-36 startup.

Pure contract verification without a database or development service:

```sh
npm test -- --config jest.runtime.config.cjs
npm run typecheck
npm run build
```

### Stored runtime manifests

Operators can publish metadata bindings once with `./publish-key-vault-bindings.sh --plan examples/explorer-api-bindings-plan.json`. Applications then bootstrap using `LOCAL_KEYVAULT` and stored manifests, without copying generated binding JSON into each consumer. See [manifest publication and revisions](docs/BINDINGS.md#publish-manifests-once-for-simpler-startup). The publisher uses the existing initialized vault database and does not provision secrets, keys or grants.
