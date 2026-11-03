# Runtime inheritance implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Configure bindings once and combine applications and tenants in runtime.
**Architecture:** SchemaVersion2 reference-only persistence, canonical server resolution into existing schemaVersion1 preview and immutable SDK manifests. Existing auth and publication safeguards retained.
**Tech Stack:** NestJS/TypeScript, Next.js/React.
**Spec:** docs/superpowers/specs/2026-11-03-runtime-inheritance-design.md

## Global Constraints
Primary development checkouts; preserve unrelated edits. No service activation/restarts. Canonical definitions must never be overwritten from runtime/import. No credential output.

## Review Focus
- Stale rich drafts/imports cannot overwrite canonical links or metadata.
- Latest/pinned policies and complete tenant key histories survive resolution.
- Concurrent canonical edits reject publication rather than replacing metadata.
- Missing applications/tenant material fail explicitly; access stays separate.
- Published snapshots preserve current crypto/history safeguards and SDK format.

### Task 1: Canonical backend inheritance
- [x] Add failing tests for reference-only save, canonical reload after changes, stale rich imports and unchanged canonical associations.
- [x] Resolve references from catalog/tenant namespaces, store only refs and retain resolved response shape for consumers/UI compatibility.
- [x] Preserve atomic publication and crypto guards; test HTTP/Mongo flows.

### Task 2: Assignment-only UI
- [x] Replace duplicate secret/name/ENV editors with inherited read-only previews; apps/tenants selection only.
- [x] Save/export reference schema2; compatibility import uses assignments only. Preserve access controls and status semantics.
- [x] Run meaningful UI tests/typecheck/build.

### Task 3: Verification and publication
- [x] Review changed paths; run API tests/types/build and UI checks.
- [x] Convert existing unpublished metadata to reference storage without touching manifests/secrets/access.
- [x] Patch versions, commit/push owned development changes; report initial rollout boundary.

Validation: API229 tests/31suites, typecheck/build pass; UI119 tests/typecheck/build pass. Fresh bounded review fixed uncommitted-tenant projection and pinned-policy regressions, then returned no important findings. Live HTTP fixture uses schema2 assignments, actual installed v2 SDK starts a tenant with no duplicate app links, and refresh adopts canonical ordinary secret changes. Existing development revision0 migrated to references only; definitions/values/manifests/access verified unchanged, remains unpublished. UIad52462 pushed.
