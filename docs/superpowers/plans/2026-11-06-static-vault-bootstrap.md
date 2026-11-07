# Static Vault and Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline. The user explicitly approved the design, requested this plan and authorized starting implementation; proceed without another plan-approval checkpoint. Steps use checkbox tracking.

**Goal:** Deliver normalized Vault storage and static-secret bootstrap for five consumers, with tenant-owned runtime tokens and consent-controlled administration.

**Architecture:** Build a versioned `src/v2/` service boundary on per-entity MongoDB documents; encrypt only immutable secret values. The shared SDK installs tenant-isolated memory snapshots. Introduce the v2 authority only through verified maintenance cutover, never by silently interpreting legacy documents as v2.

**Tech Stack:** Existing TypeScript, NestJS, Next.js, MongoDB, Node crypto, Jest; existing CommonJS SDK exports remain compatible during staging.

**Spec:** ../specs/2026-11-06-static-vault-bootstrap-design.md

## Global Constraints
- Database names: `key-vault-kick-playr`, `control-kick-playr`, `<tenant>-kick-playr`; derive tenant names from validated IDs only.
- Work directly on each repository's existing authorized branch; preserve unrelated edits. No feature branches/worktrees.
- Original offline phase prohibited live changes. On 2026-11-07 the user explicitly authorized migration/cutover and service restarts; execution evidence and preserved backups are recorded in 2026-11-07-static-vault-cutover.md and the private ledger. No unrelated deployment or cleanup is authorized.
- No namespace-wide grant arrays; one document per grant/resource/version/link. Plaintext metadata; encrypted values; hashed high-entropy grant passwords.
- Static credentials only in Vault. Runtime tokens only in encrypted tenant storage; optional encrypted Redis cache.
- Requests use memory; fetch interval >=60 seconds; no change means no adaptation; startup unready/retry with `Key Vault is not connected`.
- Tenant consent and indirect-access checks apply to human operations. Machine grants remain read-only and follow approved assignments/links.
- All running affected instances acknowledge new keys; no timeout-based retirement. Explicit administrator permanent-stop confirmation is required.
- Tests use synthetic fixtures or owned disposable MongoDB, never real ENV credentials or live tenant data.

## Review Focus
- Ciphertext or grant substitution across environment/owner/version must fail; metadata listing must never decrypt values.
- Consent revocation racing a reveal/save and indirect grant/link access must deny publication.
- An unreachable instance, revoked grant or concurrent enrollment must not disappear from a rotation barrier.
- A refresh result from before reconnect/static-client change must not overwrite the new runtime authority generation.
- Partial migration/uncertain acknowledgement must not enable mixed authorities or replay external OAuth calls.

## Implementation sequence and interfaces

### Task 1: Names, records and value encryption
**Files:** create `src/v2/database-names.ts`, `src/v2/records.ts`, `src/v2/value-cipher.ts`; tests `test/v2/foundation.spec.ts`; isolated `jest.v2.config.cjs`.
**Consumes:** existing `databaseFromMongoUri(uri)` for URI validation; Node crypto.
**Produces:** `databaseNames.vault`, `.control`, `.tenant(tenantId)`; `assertDatabaseName(uri,expected)`; `ResourceScope`, `ResourceRecord`, `ResourceVersion`, `GrantRecord`; `ValueCipher.seal(scope,resourceId,versionId,schemaIdentity,value): ValueEnvelope`, `.open(...): Buffer`, `.close():void`.
- [x] Write tests for exact names, hostile/reserved tenant IDs, URI mismatch, ciphertext-only values, plaintext metadata, wrong owner/version/schema, tampering and closed cipher.
- [x] Run `npm test -- --config jest.v2.config.cjs` and observe missing modules/behavior fail.
- [x] Implement typed identities and per-value authenticated envelope encryption, with owned key buffers wiped on close/failure.
- [x] Run v2 tests and `npm run typecheck`; commit only task files and ledger.

### Task 2: Normalized MongoDB persistence
**Files:** create `src/v2/mongo-store.ts`, `src/v2/indexes.ts`; `test/v2/mongo-store.spec.ts`, `jest.v2.mongo.config.cjs`.
**Consumes:** Task 1 record types/cipher.
**Produces:** `V2MongoStore.open({mongoUri,masterKey})`, `.databaseName`, `.resources`, `.versions`, `.grants`, `.links`, `.transaction(work)`, `.close()`; typed `V2Transaction` methods for CAS publications and audit/change heads.
- [x] Failing disposable-Mongo tests: two grants are two documents, revoke one without rewriting another; metadata lookup/list uses projection and no decryption; concurrent version publication has one CAS winner; failure rolls back all writes.
- [x] Implement collections/indexes and transactions; forbid legacy target URI and unknown owner references. Never create a global grant registry document.
- [x] Verify real replica-set transaction tests, typecheck and legacy storage regressions; commit.

### Task 3: Identity, consent and grant services
**Files:** create `src/v2/authorization.ts`, `src/v2/grants.ts`, `src/v2/consents.ts`; tests `test/v2/authorization.spec.ts`, `test/v2/grants.spec.ts`.
**Consumes:** `V2MongoStore`, trusted identity adapter to existing Explorer platform/club authority.
**Produces:** `Authorization.require(actor,action,scope)`, `GrantService.issue/authorize/revoke/rotate`, `ConsentService.approve/revoke` with policy-revision fences.
- [ ] Failing tests for own-tenant club rights, global metadata-only rights, consent-gated values/edits, consent racing commit, no self-approval, per-document token lookup and wrong application/environment.
- [ ] Implement separate machine/interactive/operator grant classes, hashed random credentials, approved delivery and anti-bypass issuance/link/owner checks.
- [ ] Verify global role cannot gain value access through direct API or provisioning credentials without the required identity/consent; commit.

### Task 4: Resource, integration schema and link management
**Files:** create `src/v2/resources.ts`, `src/v2/integration-schemas.ts`, `src/v2/links.ts`; corresponding `test/v2/*.spec.ts`.
**Consumes:** authorization and store transaction ports.
**Produces:** resource CRUD/version APIs, immutable schema versions and checked application/tenant links.
- [ ] Failing tests for named duplicate-type integrations, supported encoding without changing bytes, missing required fields, runtime-token fields rejected, custom schema limits/no remote references, duplicate access names and cross-owner links.
- [ ] Implement built-in provider schemas and bounded custom schema support, metadata-only listing, explicit value reveal, CAS saves and in-use delete blocking.
- [ ] Verify per-document metadata search/pagination never opens ciphertext and runtime token values cannot enter static schema paths; commit.

### Task 5: Coherent bootstrap API
**Files:** create `src/v2/bootstrap.ts`, `src/v2/controller.ts`, `src/v2/app.ts`; modify `src/main.ts` only for explicit verified v2 authority selection; tests `test/v2/bootstrap.spec.ts`, `test/v2/http.spec.ts`.
**Consumes:** read-only grant authorization, explicit links and immutable resource versions.
**Produces:** `BootstrapService.snapshot(grant,ifNoneMatch)` -> snapshot/304; `/v2/bootstrap` and authenticated instance endpoints; separately authorized admin endpoints.
- [ ] Failing tests: resources selected only by app/grant, tenant-local partial failure, coherent snapshot, unchanged view 304, revoked grant never 304, no sensitive data in management responses.
- [ ] Implement transactionally stable authorized views/revisions, default value-excluding projections and admin identity/consent enforcement.
- [ ] Verify HTTP scope spoofing and old/new authority gates; commit.

### Task 6: Shared in-memory bootstrap SDK
**Files:** create `runtime-client/bootstrap.cjs`, `runtime-client/bootstrap.d.cts`, `test/v2/bootstrap-client.spec.ts`; update package export/types.
**Consumes:** Task 5 wire contract with injectable fetch/time/scheduler.
**Produces:** `createBootstrapClient(options)` with `start()`, `status()`, `application()`, `tenant(id)`, `close()`; immutable snapshots and scoped change/cancellation hooks.
- [ ] Failing tests: unready startup retries, no business-triggered fetch, >=60,000ms interval including manual attempts, one in-flight fetch, tenant name collision isolation, 304 preserves identities/client hooks, outage retains memory, scoped explicit revocation removes material.
- [ ] Implement memory-only state machine, ENV compatibility for application values only, safe diagnostics and key installation ACKs.
- [ ] Verify CommonJS/types exports and non-secret public projection; commit.

### Task 7: Instance and key rotation coordination
**Files:** create `src/v2/instances.ts`, `src/v2/key-rotations.ts`; `test/v2/key-rotations.spec.ts`.
**Consumes:** instance/key-version/participant documents and bootstrap ACKs.
**Produces:** prepare/ack/activate/retire lifecycle with one durable membership revision.
- [ ] Failing tests: offline node blocks forever, join concurrent with activation blocks until loaded, revocation/unlink cannot shrink original barrier, explicit permanent-stop confirmation only, retired identity cannot rejoin.
- [ ] Implement versioned participant documents, atomic activation and decrypt-only retention; application migration evidence is required for index/control key changes.
- [ ] Verify retained historical decryption and interruption/idempotent status; commit.

### Task 8: Shared tenant runtime OAuth records
**Files:** create `runtime-client/integration-runtime.cjs`, `.d.cts`, `test/v2/integration-runtime.spec.ts` and a Mongo adapter.
**Consumes:** local static integration snapshot, local tenant key ring and tenant Mongo connection.
**Produces:** runtime read/CAS reservation/dispatch/result/reconnect methods bound to `authorityGeneration`, credential revision and static version.
- [ ] Failing tests for concurrent refresh winners, stale results after reconnect/config changes, proven pre-dispatch recovery, ambiguous dispatch blocking replay, lost commit reconciliation by operation ID and Redis fallback.
- [ ] Implement encrypted tenant-only records and actionable recovery state; no SDK Vault call from a runtime-token operation.
- [ ] Verify fresh account-bound reconnect bypasses broken provider role graph while preserving admin authorization; commit.

### Task 9: Vault APP and Explorer administration
**Files:** modify existing Vault APP `applications-panel.tsx`, `application-links-table.tsx`, `runtime-configuration-panel.tsx`, `azure-vault-panel.tsx`; add `src/components/tenant-consent-panel.tsx`, `integration-editor.tsx`, `key-rotation-panel.tsx`; update scoped API adapters and tests. Existing unrelated user edits in the Vault APP must be preserved. Explorer uses the equivalent existing club-admin settings routes/components.
**Consumes:** v2 metadata/admin APIs, trusted human identity and separate provisioning credentials.
**Produces:** application/tenant resource linking, typed integration forms, consent controls and rotation status/retirement UI.
- [ ] Failing UI tests: metadata without values, denied edit/reveal without consent, club admin scope, 20-row paging/name/ENV/link filtering, repeated integration types, explicit confirmed retirement.
- [ ] Implement the new views with purpose/name first, collapsed details, safe errors, no hidden value payloads and no browser provisioning credentials.
- [ ] Verify existing user layout behavior and authorization integration; commit scoped changes.

### Task 10: Five consumer bootstrap adapters
**Files:** update Club API `scripts/lib/api-secrets.cjs`, `src/tenancy/tenant-development-workflow-owner.ts`; Club APP server secret bootstrap; Explorer APP `src/lib/server-secrets*.ts`; Explorer API bootstrap/secrets adapter; Vault APP server loader/instrumentation.
**Consumes:** Tasks 6 and 8 APIs.
**Produces:** framework startup/readiness gates and memory-pinned local clients, replacing request-time/old generation loaders.
- [ ] Failing adapter tests: no ready application before required secrets, tenant-local degradation, hot client replacement, no hard-coded Clerk issuer, no Vault calls on business/refresh paths and safe Next.js public configuration.
- [ ] Implement each consumer separately, preserving current business routes and using the existing authorized repository branches.
- [ ] Run each repo's targeted tests/type checks; inspect built public artifacts for server secrets; commit per repository only after checks.

### Task 11: Read-only migration preview and explicit staged cutover
**Files:** create `src/v2/migration.ts`, `src/v2/migration-cli.ts`, `test/v2/migration.spec.ts`; add package command and operator documentation.
**Consumes:** legacy read-only decoder, normalized store and tenant runtime adapter; explicit source/target connection configuration.
**Produces:** `previewMigration`, `stageMigration`, `verifyMigration`, `activateMigration`, `resumeMigration`, `rollbackMigration` with durable job/item ledgers.
- [ ] Failing tests: exact target database names, unknown fields block classification, mixed bundles split correctly, token history transferred out of Vault, changed source aborts, partial stage never activates, old writers fenced and post-write rollback refused.
- [ ] Implement reviewed digests, exact-value/key-byte equivalence and cross-database resumable protocol; no external OAuth replay and no silent live ENV rewrite.
- [ ] Verify synthetic/disposable migration including interrupted phases. Produce a concrete live maintenance preview for separate execution approval; commit.

### Task 12: Final verification and reviewable release
**Files:** update operator docs and this plan/ledger.
- [ ] Run all affected unit, HTTP, disposable-Mongo, SDK and consumer tests, typechecks and builds; investigate failures, distinguishing existing failures from regressions.
- [ ] Benchmark bootstrap bytes/time, metadata queries without decrypt, unchanged polling and warm requests with zero Vault calls. Measure representative multi-tenant memory footprint.
- [ ] Obtain one fresh whole-change security/code review; fix important findings with reproducing tests.
- [ ] Present exact migration/environment/credential-delivery actions and backups for maintenance execution approval. Do not claim live cutover or endpoint performance from fixture tests.

## Execution ledger

- 2026-11-06: User approved the design and explicitly authorized plan creation and building. Database names incorporated.
- Ruling: execute inline on primary authorized checkouts, preserving unrelated edits, rather than introduce worktrees or another approval checkpoint — explicit user/repository instruction prevails over generic skill defaults.
- Ruling: v2 storage is staged separately from legacy authority. Existing live databases and stopped services remain unchanged until a reviewed maintenance action is approved — avoids mixed writers and accidental live migration.
- Plan coverage scan: Tasks 1–2 cover database/document/encryption requirements; 3–4 cover identity/consent/grants/resources/schema/links; 5–7 cover bootstrap/instances/rotation; 8 covers tenant runtime secrets; 9–10 cover UI and all five consumers; 11–12 cover migration/rollback/verification. Interfaces are versioned at the v2 boundary.

- Tasks 1–2: implemented and tested normalized MongoDB foundation. Foundation 3/3 and disposable replica-set persistence 4/4 passed; legacy/default suite 240/240 passed before the additional scoped-query hardening regression, whose targeted suite and typecheck also pass. Metadata is plaintext; only values encrypted. Live services/databases untouched.

- 2026-11-07: Tasks 3–4 library slice added: consent/grant authorization, typed integration schemas, resource version/update/reveal/delete and explicit link validation. Unit 17/17, disposable Mongo 7/7, default regression suite 257/257 and typecheck pass. Production identity/delivery wiring, persisted schemas and further link race coverage remain; these tasks are intentionally unchecked.

## Integrated cutover checkpoint — 2026-11-07

Tasks 3–6, 8–11 now have integrated implementations and live migration evidence; the historical per-task commit checkboxes above are retained rather than imply new commits were made. Task 7 implements the durable barrier, Club API wrapping-key proof and fail-closed migration-evidence gates. Captured Clerk/index/control keys remain maintenance-only, with no fabricated installation acknowledgements. Task 12 verification passed: 334 Vault tests, 93 focused Club API checks, consumer typechecks/builds, public-artifact scans and fresh review; see [cutover record](2026-11-07-static-vault-cutover.md). Bexio fresh authorization and signed-in business timing remain external execution prerequisites. No commits/pushes were included in this continuation.
