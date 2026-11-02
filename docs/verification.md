# APP-35 verification record

## New tenant symmetric key creation

Added executable create-tenant-keys.sh with offline --help/-h. Metadata and token support prompts or --environment/--tenant/--name/--token options. Omitted tenant is always prompted, never inferred from the key-set name. Key env names are automatic WORKFLOW_REAL_<TENANT>_{WRAPPING_KEY_V1,INDEX_KEY,CONTROL_KEY}. Per latest user correction, raw key-value flags are rejected: three key values come only from an explicitly selected --env-file or hidden prompts. Missing/blank dotenv entries prompt individually; files are parsed without execution or modification and never discovered automatically. Relative source paths use caller cwd; vault bootstrap .env resolves from the vault project. Only --generate explicitly generates random values and cannot combine with --env-file. Suffix-only confirmation requires yes unless explicit --yes approves automation.

Supplied strings are preserved exactly and validated before confirmation. All writes use scoped read/write grant authorization and atomic create-only CAS checks; existing/deleted sets, races and unauthorized scopes cannot overwrite, rotate or reactivate keys. Full values are never printed or saved to files.

Build, typecheck and **81 tests across 12 suites** passed. Nine creation tests cover automatic mappings, tenant prompting with other metadata provided, hidden value collection, explicit readonly dotenv input with missing/blank entries, rejected raw-key flags, generation, exact-value preservation, validation/cancellation/isolation and concurrent create-only fencing. Existing PTY checks cover hidden input, scope/name prompts and suffix confirmation. Independent review of the corrected file/manual input flow found no important defects. Shell syntax/help/whitespace checks passed. No live keys were created or imported, and no real FCRWW .env was read for this change.


## Named tenant key sets and metadata tree

The importer now asks for the logical key-set name before key values, validates `<profile>:<exact-selected-tenant>:key`, and confirms the chosen reference, namespace, exact env-name mappings and three-character suffixes. The canonical tree is environment / tenant / key set / wrapping/v1, index, control. Explicit env names remain WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1, WORKFLOW_REAL_FCRWW_INDEX_KEY and WORKFLOW_REAL_FCRWW_CONTROL_KEY regardless of profile name. Physical names use tk-role plus the full SHA-256 hash of environment, tenant, reference and role path. Metadata retains the logical path and env mapping. Existing values with conflicting mappings abort rather than being silently relabelled.

Added list-protected GET /local/key-tree and namespace alias, with generated Swagger schema. It reads only the authorized namespace and projects logical groups, env names, physical/versioned secret IDs and attributes; no values, suffixes or key material. Invalid/unstructured tags are excluded; ordinary inventory remains available for legacy names. Disabled/expired current leaves remain visible; deleted leaves disappear. No automatic legacy rename, data migration or client-binding change occurs.

Build, typecheck and **72 tests across 11 suites** passed. New tests cover deterministic scoped names, namespace/profile separation, wrong-tenant/invalid names, name prompts, exact role/env mappings, tree metadata omissions, list-only access, empty isolated tenant trees and namespace mismatch denial. A synthetic PTY check verified visible name entry, three exact env-name prompts with hidden values, logical confirmation paths and yes confirmation. Shell help/syntax/whitespace checks passed. Independent review found no important defects. No real keys were imported.


## FCRWW symmetric key import

Added `import-fcrww-keys.sh [environment tenant]` with offline --help/-h. Per user correction it prompts locally for wrapping, index and control key values with hidden terminal input, never reading FCRWW files or key environment variables. The grant token is also prompted unless exported as VAULT_TOKEN. Only the vault bootstrap .env is read. Non-interactive input is rejected; Ctrl+C/EOF cancels before import. A supplied token must have exact scoped read/write permissions, rechecked on every CAS retry. All three distinct canonical Base64 32-byte strings are stored unchanged in one atomic transaction as encrypted secrets. Identical active targets are skipped; conflicting/inactive/deleted targets abort all writes. Before import, validated keys display only their exact last three characters (including Base64 padding), followed by the target namespace and a required explicit yes confirmation. All other answers cancel before invoking import. No key generation/rotation or runtime binding changes occur; final output contains names/scope/counts only.

Build, typecheck and **69 tests across 10 suites** passed. Independent review of the interactive revision found no important defects. Synthetic PTY checks verified all three interactive prompts, no echoed pasted values, and Ctrl+C cancellation. Shell syntax, offline help and whitespace checks passed. No real FCRWW keys were imported. Existing six import regressions cover original value preservation, metadata-only output, repeat/concurrent imports without new versions, validation before writes, least privilege and atomic conflict/disabled/deleted protection; a new test verifies three explicit prompt inputs independently of environment/file sources.

Two additional regressions verify suffix-only confirmation, empty/no/y rejection without writes, and validation before displaying suffixes. A synthetic PTY check verified three-character suffix display, explicit yes and continued hiding of full key values.

## Grant token rotation

Added executable `rotate.sh <grant-id>` and equivalent `grants.sh rotate <grant-id>`. Rotation atomically disables the original and persists a replacement token hash with a new ID, retaining the latest scope/permissions. The replacement token is printed once after commit. Revoked/unknown/invalid grants fail without changes or token output. Disabled originals are retained to prevent legacy import from resurrecting them. Concurrent rotations across MongoDB connections allow one replacement.

Build, typecheck and **59 tests across 9 suites** passed. Three new regressions cover live API old/new-token authorization and scope/permission preservation, re-import protection, invalid/revoked/unknown grants and concurrent rotations. Shell syntax/whitespace checks passed; independent review found no important defects. No existing local grant was rotated.

## MongoDB caller grants

Authorization now reads an encrypted `vault_grants` registry on each request, including handler permission checks. It persists SHA-256 token hashes, exact scopes, permissions, IDs and enabled status; it has no environment fallback or grant-management HTTP endpoint. Registry writes use the existing encrypted CAS implementation with a distinct authenticated ID, so concurrent connections preserve changes. CLI commands create/list/change permissions/revoke/import; only creation prints a bearer token.

Build, typecheck and **56 tests across 9 suites** passed. Added tests verify running-API grant creation, immediate permission changes and revocation across connections, tenant isolation, hash-only decrypted contents, encrypted storage, safe metadata listing, reconnection persistence, atomic/idempotent migration, duplicate legacy permission union, revoked-grant non-resurrection, two-connection concurrent management, invalid input, CLI output secrecy, empty-registry denial and database failure/corruption. Existing authorization, namespace, provisioning and Swagger suites remain green. Independent security review identified the duplicate-entry migration issue; a failing regression reproduced it, the fix unions incoming permissions before CAS, and follow-up review found no further important defects. Shell syntax and whitespace checks passed.

The existing local grant was explicitly imported without changing its token or permissions and verified against the MongoDB authorization service. Its assignment was removed from `.env` after verifying other bootstrap values remained identical. An ignored mode-0600 `.env.grants-backup` retains the original caller token for recovery; neither file is tracked. The running API process was not restarted. Swagger bearer documentation was updated to refer to saved creation/migration tokens and its suite was rerun.


Implementation uses NestJS 12 and TypeScript 6 on Node 24 on the local `codex/app-35-local-vault` branch. The repository had no commits or application code; an orphan feature branch was used in place because a worktree cannot be based on an unborn HEAD. Existing IDE files were left untouched and ignored.

## Metadata inventory and listing

Implemented Azure-compatible GET /keys and /secrets and the local GET /local/inventory, including namespace aliases, latest-only metadata, disabled/expired inventory, purpose/name/prefix/kind/tag/enabled/expiry filters and maxresults/nextLink pagination. A new explicit list permission permits metadata access without secret values, snapshots, writes or crypto. Existing grants are unchanged. New manifest objects receive purpose tags; reconciliation-created secret versions retain existing tags. Legacy metadata is not silently changed.

Continuation tokens are signed with a domain-separated master-key-derived HMAC key and bind namespace, endpoint, filters, page size, generation and a 15-minute expiry. Canonical signature encoding is required. Tampered or mismatched tokens fail with 400; a namespace mutation invalidates continuation with 409. No plaintext search index is stored.

Build, typecheck and **48 tests across 8 suites** passed. Inventory regressions cover metadata omissions/least privilege, tenant and endpoint cursor binding, tampering, changed filters/page limits, mutation invalidation, default 25 pagination, empty results, combined audit filters and purpose discovery without key rotation. An independent review found no important actionable defects and independently reran all 5 inventory tests. Production dependency audit remains zero advisories.

## Live Swagger documentation

NestJS generates OpenAPI at startup from controller annotations and explicit schemas. Swagger UI is served at `/docs`, with JSON at `/docs-json`; bundled local assets and raw JSON are accessible on loopback without a token. API requests retain namespace and handler permission guards. Browser requests must be same-origin, and token persistence/external validation are disabled. The documentation contains no live tokens, master keys or stored values.

Clean install, build, typecheck, all **43 tests across 7 suites**, and production dependency audit passed (zero production advisories). Swagger tests cover UI/assets, auth/header/query schemas, request/response refs, path alias parameter coverage, unique operation IDs, schema-required arrays, credential omission, authenticated same-origin requests and rejected unauthenticated/cross-origin requests. Independent review found no important issues. Live requests on port 4000 confirmed UI/spec availability and continued unauthenticated API rejection.

## Startup diagnostics

Startup errors now identify invalid environment variables, .env read errors, MongoDB initialization phases and listener failures, with safe nested error names/codes and actionable hints. Master-key mismatches specifically name VAULT_MASTER_KEY. HTTP error bodies retain the original code-only contract; credentials, arbitrary driver messages and stacks are not serialized. Current local bootstrap validation reports missing/invalid JSON in VAULT_GRANTS.

Build, typecheck and **35 tests across 6 suites** passed, including field-level diagnosis, nested-code extraction, master-key mismatch and secret omission. Independent review found no important issues and reran the 16 config/store tests successfully.

## URL-only MongoDB configuration

MongoDB now requires only `VAULT_MONGODB_URI`, with no separate database-name or password variable. The API requires an explicit database path in the URL. Missing/empty/whitespace database paths fail before connecting, including URLs with only authSource or SRV options. No default database is used. Real MongoDB tests inspect both collections for explicit paths and verify rejected bare URLs do not create fallback collections. `env.example` explicitly names the database with `mongodb://127.0.0.1:27017/key-vault`. The optional local Compose MongoDB requires no password and publishes only on loopback. Integration tests cover both bare URLs and isolated database paths.

## .env bootstrap loading

- `env.example` contains the port 4000 default, single MongoDB URL, blank required credentials and a quoted JSON grant example. `.env` remains ignored by Git.
- Startup uses Node 24's native dotenv parser and validates the merged configuration before connecting. Exported environment variables take precedence; an absent file is optional, while unreadable files and invalid required values fail with safe diagnostics. Parsing does not modify global process.env.
- Build, typecheck and **31 tests across 6 suites** passed, including file parsing/JSON, precedence, absent-file fallback and safe errors. Compiled server startup using only a temporary `.env` also passed HTTP authentication and secret write/read checks against an isolated MongoDB.

## Node 24 dependency update

- Runtime target is Node 24.x (`engines.node` and `.nvmrc`); verified with Node **24.22.0**. Node types remain 24.19.2.
- Upgraded to NestJS **12.3.2**, MongoDB driver **7.8.0**, TypeScript **6.0.3**, and Supertest types **7.2.1**, retaining the existing minor-version package updates. TypeScript 7 is outside ts-jest's declared peer range and was deliberately excluded.
- Native ESM/NodeNext imports and Jest ESM configuration replace the prior CommonJS setup. Removed ts-node and the multer override; Nest 12 includes patched multer directly. Development startup compiles then runs native Node.
- Build, typecheck, native compiled module imports, dependency consistency and all **27 real-MongoDB tests** passed. An independent compatibility review found no important defects.
- Both `npm start` and `npm run start:dev` passed authenticated-MongoDB smoke checks on Node 24.22.0: HTTP auth, secret persistence between starts and clean shutdown. Tests used a temporary database and credentials, then removed them.
- Test execution uses Node's experimental VM-modules flag; its warning is expected. Production startup uses standard native ESM without that flag. Production audit has zero advisories; the remaining low-severity deepmerge/Jest advisory is detailed below.

## Current MongoDB storage verification

- File persistence was replaced with one encrypted MongoDB document per namespace and an encrypted startup key verifier. MongoDB credentials and master keys remain external bootstrap configuration.
- The test suite launches isolated loopback `mongod` processes with temporary data directories. No configured/live database is accessed; no file-store migration is performed.
- **27 tests passed across 5 suites**, including all existing REST/runtime behavior, encrypted reconnection, wrong-key/corruption rejection, namespace/revision ciphertext binding, two concurrent store connections and two Nest servers, failed database read/write operations, namespace size bounds, and rotation/revocation visibility across writers.
- Independent review checked encryption, namespace isolation, CAS retry/failure handling, shutdown, async service changes and documentation; no important actionable defects found. The reviewer independently reran all 27 tests successfully.
- `npm run typecheck`, `npm run build`, and `npm audit --omit=dev` passed; production audit reports **0 vulnerabilities**. Compose configuration validates without launching a container.
- Compiled Nest entrypoint smoke passed against an authenticated temporary MongoDB using a database-scoped `readWrite` user: bootstrap, HTTP auth, secret write/read and clean shutdown. Temporary bootstrap and database were removed afterward.

The development Jest advisory caveat below remains applicable. Current storage is bounded at 8 MiB serialized plaintext per namespace, with MongoDB majority reads/writes and up to 20 revision-conflict attempts. There is no lifetime file lock or plaintext server cache. See README for configuration, ambiguous write outcomes and migration boundaries.

## Original file-backend verification (historical)

- Test-first suites exercise the real encrypted filesystem store and real Nest HTTP endpoints with temporary test-only credentials and keys.
- Store tests cover encrypted restart, wrong key/corruption, exclusive ownership, concurrent transactions, thrown-mutation rollback, failed-persistence rollback, detached read/results and symlink rejection.
- REST tests cover exact authorization grants, secret lifecycle and version metadata, disabled/expired values, tenant isolation, malformed body/version/fields, origin rejection, names resembling object prototype properties, public-only JWK responses, RSA-OAEP-256 and pre-rotation version decryption.
- Provisioning tests cover deterministic names, concurrent idempotent reconciliation, encrypted restart, supplied-secret rotation, rollback when required credentials are missing, stale/conflicting revision rejection, deleted/disabled key refusal, and unsafe/mismatched manifest scopes.
- Runtime tests cover concurrent tenant initialization without process.env writes, immutable mappings, not-ready startup, expiry, refresh outages, stale revision events, revocation, process mapping conflict atomicity and unsafe names.
- Independent code review found route permission inference bypasses (including case/trailing-slash variants), NUL truncation in process.env and refresh readiness gaps. Regression tests reproduced the failures before fixes. Permissions are now Nest handler metadata enforced by a guard, and metadata PATCH omits existing secret values for write-only callers. A failed newer event retains its revision watermark so an older event cannot restore stale readiness.
- Clean `npm ci` completed. Full `npm test`: **25 tests passed across 5 suites**. `npm run typecheck` (including the Nest consumer example) and `npm run build` passed. `npm audit --omit=dev`: **0 vulnerabilities**.
- Compiled `dist/main.js` smoke test passed with temporary test-only bootstrap: loopback startup, unauthenticated HTTP rejection and SIGTERM release of the store lock.
- Independent reviewer rechecked the final handler guards and runtime changes, ran the 25-test suite, and reported no remaining important defects in the reviewed scope.

## Limits and remaining external work

No live Azure service or existing application was available for conformance/migration testing. This is an explicitly limited REST subset with local authentication, namespace IDs, permanent deletion, unpaginated version lists and secret PATCH metadata-only responses. It is not complete Azure/HSM compatibility.

Consumers must wire the async startup provider and authenticated tenant-change events into their application, supply an actual purpose/mapping inventory and authorized external credentials, and recreate clients on rotation. The included manifest/provider are integration examples. APP-35's Freddie/Chris approvals are external review requirements, not implied by implementation.

The production dependency audit reports no advisories. Nest 12 includes patched multer directly, so the former override has been removed. Overrides pin minimatch 11.0.3, glob 14.0.3 and deepmerge 4.3.1. Glob/minimatch advisories are resolved. The full dependency audit now reports 6 low-severity findings, all from deepmerge and its Jest dependents; no moderate/high/critical findings remain. Deepmerge 4.3.1 is the latest published release, but [GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) lists no patched version. Its override pins the current version and does not fix that issue. No test server/tooling runs in the production start command.

No deployment, live credential/key provisioning, migration, external message, or Jira status transition was performed.

Database confirmation: the actual .env URI explicitly names key-vault; effective startup configuration selects the same database. A read-only connection/ping and collection listing succeeded: vault_metadata exists; vault_namespaces has not yet been created. No key or secret was generated for this check.

## UI connection authentication regression

Added read-only GET /local/session behind existing full-token and namespace authorization. Its controller requires no extra operation permission; scope checks still apply. Tests reject appended/truncated tokens with 401 and wrong scope/namespace aliases with 403, verify valid responses, and verify read-only, write-only, crypto-only and list-only callers can authenticate without resource access. Existing altered-token resource request also returns 401. Full API suite: 9 suites, 60 tests passed; typecheck and build passed. Fixtures use disposable MongoDB; no live grant or secret changes.

Runtime smoke check: restarted the local API from the verified build, confirmed /docs-json includes GET /local/session, and a fabricated invalid suffixed credential returns HTTP 401. No real credential was read or tested.

## APP-50 purpose labels/search — release 0.1.4 (2026-11-01)

Added optional local-inventory `search` for a case-insensitive literal name OR purpose substring. The existing metadata scan filters before slicing pages; signed cursor fingerprints include search automatically. Existing kind/namespace/permission behavior remains unchanged. No secret values, private material or new storage are involved.

Observed three new regressions fail before implementation. Then 70 tests across 10 pure/in-memory suites passed, including the three new search tests (name/purpose OR, case, punctuation, missing tags, pagination, changed-search cursors, scope, payload bounds and exclusion of secret values). Command:

```sh
node --experimental-vm-modules node_modules/jest/bin/jest.js --config jest.inventory-unit.config.cjs --testMatch '**/test/{inventory-search,config,audit,runtime-client,runtime-snapshot,runtime-manifest-client,runtime-manifest-plan,runtime-manifests,oauth-credentials,create-key-vault-grants}.spec.ts' --runInBand
```

`npm run typecheck` and `npm run build` passed. The MongoDB-backed full suite was not run because it launches disposable mongod processes; service starts were outside this task's authorization. No real vault, running services, credentials or stores were touched. Locked install reports the same 6 low-severity development-tooling advisories previously documented; no dependency updates made. Live HTTP/database integration and running UI remain unverified.

## Secret version counts — release 0.1.5 (2026-11-02)

Local inventory now includes versionCount from the already-loaded resource version array, including disabled/expired versions. No extra history requests, secret reads, permission changes or new storage. Azure-compatible /keys and /secrets list shapes are unchanged. Four inventory unit tests pass; all71 tests across10 pure/in-memory suites, typecheck and compilation pass. Full database-backed suite remains unrun under no-service-start constraint. Unrelated untracked APP-49 design file was left untouched.
