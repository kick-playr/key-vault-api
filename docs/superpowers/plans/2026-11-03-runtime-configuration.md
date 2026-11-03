# Runtime Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for core implementation. Independent consumer/UI work may use superpowers:dispatching-parallel-agents with the interfaces below.

**Goal:** Manage development's four apps, tenant assignments and bindings in the Vault UI, with compatible manifests and hot tenant enrollment.
**Architecture:** One encrypted environment configuration, metadata-only import/export, immutable per-namespace publication and revision checks. Stable app identities use a separate read-only transport and explicitly administered scope permissions. SDK discovery refreshes authoritative assignments; consumers initialize tenants independently before routing requests.
**Tech Stack:** Existing NestJS/TypeScript/MongoDB, runtime CJS SDK, Next.js UI and consumers.
**Spec:** `docs/superpowers/specs/2026-11-03-runtime-configuration-design.md`

## Global Constraints

- ID equals environment: development; display names Club API, Club APP, Explorer APP, Explorer API. Existing slugs club-api, app, explorer, explorer-api remain unchanged.
- Preserve values, grants, historical versions, canonical mappings and encryption migration guards. No real service restarts, deployment or live activation.
- New tenant adoption target five seconds under healthy conditions; unavailable new tenants do not interrupt existing ones.
- Use primary development branches and preserve unrelated edits. No credentials in logs, persisted configuration JSON or exports.

## Review Focus

- A stale cross-namespace save or partial publication must not invalidate previously published manifests.
- New scope cannot be authorized solely by being listed in configuration.
- Explicit pins and Latest must survive new-format export/import; legacy omitted versions remain singleton-only.
- Caller-controlled tenant IDs never discover or enroll a tenant; authoritative config and business registry both required.
- Old clients and immutable process encryption keys remain compatible; tenant changes never require process-wide env publication.

### Task 1: Configuration schema, resolver and publication

**Files:** Create `src/runtime-configuration.ts`, `test/runtime-configuration.spec.ts`; modify `src/types.ts`, `src/app.ts`, `src/applications.ts`, `src/runtime-manifests.ts`, `src/runtime-manifest-plan.ts`, `src/store.ts` as required.
**Interfaces:** `RuntimeConfigurationDocument` = `{kind:'runtime-configuration',schemaVersion:1,id:string,applications:Record<string,{displayName:string,description:string,secrets:SecretSelection[]}>,tenants:TenantSelection[]}`. `SecretSelection` = `{purpose,mapping,version}` with version latest or immutable pin. `TenantSelection` = `{tenant,applications:string[],secrets:SecretSelection[],keySets:KeyPlan[]}`; KeyPlan follows existing plan schema and permits latest selections for Vault versions. Server envelope `{revision,configuration}`.
Routes: GET/PUT `/local/runtime-configuration`, POST `/local/runtime-configuration/import` (validate/normalize draft only), GET `/local/runtime-configuration/tenants/:tenant` with that tenant's scope/credential returns its available binding plan. PUT body `{expectedRevision,configuration,expectedGenerations?:Record<string,number>}`; tenant credential map uses bounded `x-vault-tenant-tokens` JSON header, never stored. Shared token may authorize multiple scopes if already granted.
- [ ] Write failing schema/round-trip/pin/missing-key and publication concurrency/failure tests; run them RED.
- [ ] Implement strict parser, legacy import, current-model bootstrap projection, authorized snapshot reads, compatible request generation and idempotent immutable publication. Tenant revisions first, shared batch/config CAS last. Keep old histories.
- [ ] Preserve old catalog links and add missing Club API on accepted configuration save. Publish desired shared links/tenant links only for accepted resources. Validate actual crypto changes against current published material; block unsafe replacement.
- [ ] Run API focused/full checks/typecheck/build. Commit verified API changes.

### Task 2: Runtime identity and refreshable SDK transport

**Files:** Create `src/runtime-identity.ts`, `src/runtime-identity-cli.ts`, tests; modify `src/app.ts`, `src/types.ts`, `runtime-client/index.cjs`, `runtime-client/application-client.cjs`, declaration files and runtime client tests.
**Interfaces:** Stable app identity hashes stored in separate encrypted namespace metadata; identity bound to environment/application and explicit allowed tenants. Administrative CLI creates/revokes/updates allowed tenants using existing bootstrap ownership; do not issue live credentials during implementation. SDK env `LOCAL_KEYVAULT_APPLICATION_TOKEN` is optional; old AUTH_JSON behavior remains. Add `runtime.refreshBindings(application)` returning fresh compatible bindings without clearing valid process snapshots, and typed optional `runtime.loadRuntimeConfiguration(application)` if consumer discovery requires authoritative assignment metadata.
App identity requests use `/local/runtime-access/:application/...` scoped wrapper routes for existing runtime manifest/snapshot/application runtime operations. Reject generic secret access, cross-app/environment access, unauthorized/unassigned tenant scopes and requests outside published bindings. Existing grant routes stay unchanged.
- [ ] Add failing tests for identity isolation, revocation and new-scope denial, hot discovery replacing cached lists without process snapshot mutation, legacy transport compatibility.
- [ ] Implement transport/refresh and scoped server authorization, with finite manifest/snapshot paths only and bounded request bodies. Never place app token in exports or responses.
- [ ] Run relevant API/SDK tests and build; commit verified core and publish SDK commit for consumer pinning.

### Task 3: Vault Runtime configuration UI

**Files:** Create UI `src/components/runtime-configuration-panel.tsx`, `src/lib/runtime-configuration.ts`; modify `src/components/vault-console.tsx`, `src/lib/vault-proxy.ts`, styles and UI tests.
**Interfaces:** Consume Task1 routes/document exactly. Runtime configuration navigation for shared environment, with existing Applications panel retained inside/beside configuration. Show ID development and four display names. Tenant grant fields are ephemeral; load tenant template via its scoped GET, assign consumers, edit existing secret/keyset selections, preview/import/export and Save. Explicit conflict/error states; no false Ready on metadata save.
- [ ] Write failing UI/proxy tests for tenant add, assignment, cancellation, import/export, bounded credential headers and no token persistence.
- [ ] Implement using existing controls and accessibility patterns, dirty-state guards and runtime status observations.
- [ ] Run UI tests/typecheck/build preserving pre-existing next-env.d.ts edits; commit verified changes.

### Task 4: Consumer hot enrollment and final integration

**Files:** Club API runtime/tenant registry modules and tests; Explorer API `src/tenant-live.ts`, `src/secrets.ts`, configuration/routing caches and tests; affected frontend realm modules only where needed; consumer package manifests/locks for SDK pin.
**Interfaces:** Consumers use `refreshBindings(application)` on bounded polling, authoritative tenant registry entries and SDK app transport when configured. Initialize only newly authorized authoritative tenant views; atomically publish per-tenant clients and preserve old views/in-flight requests. User input never appends bindings. Report sanitized per-tenant pending/loading/ready/error states.
- [ ] Write failing same-process tests adding a second authorized, registry-owned tenant; preserve first tenant; reject third unassigned/unauthorized tenant. Test polling recovery and no process.env mutation.
- [ ] Implement bounded discovery/registry refresh and credential transport wiring. Frontend routing refreshes trusted realm metadata without shipping secrets to browser.
- [ ] Run appropriate consumer checks and integration tests using the actual SDK. Verify same PID/runtime instance and adoption under five seconds in healthy fixture transport; do not restart existing services.
- [ ] Fresh final security/correctness review; fix material issues with regression tests. Publish verified development commits and record remaining installation/configuration requirements truthfully.
