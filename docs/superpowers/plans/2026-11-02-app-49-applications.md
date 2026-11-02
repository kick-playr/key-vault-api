# APP-49 Applications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Build the approved editable Applications model, canonical resource mappings and safe live activation contract.
**Architecture:** Resource membership and ENV names live once in encrypted namespaces; the environment application catalog lives in _shared. Metadata APIs enforce existing grants; consumers retain immutable snapshot validation. UI never equates a saved model with runtime adoption.
**Tech Stack:** NestJS/TypeScript, Mongo encrypted CAS, Next.js/React, Jest and node:test.
**Spec:** docs/superpowers/specs/2026-11-02-app-49-applications-design.md; Chris approval APP-49 comment 10150; user approval 10155 and current build request.

## Global Constraints
- Primary development checkouts only; preserve unrelated app next-env.d.ts edit. No worktrees/PRs/deploys/service restarts/live secrets or grants.
- Sharing uses one ENV name; membership follows logical resource across versions. Tags/app names never authorize.
- Runtime denial/expiry stops new affected work; transient refresh failure retains valid prior generation with warning.
- Five-second normal adoption target; grouped key migrations may take longer and must retain old decrypt capability.
- No unsupported consumer or unfinished rotation adapter may claim Applied.

## Review Focus
- Stale UI writes must conflict instead of losing another operator's links.
- Missing/deleted versions and public ENV names must not become active bindings.
- Shared resource canonical name must never be overridden by another app.
- Namespace grants must prevent cross-scope metadata leaks and mutations.
- Saving metadata must never falsely imply installed consumers have refreshed.

### Task 1: Encrypted application catalog and resource associations (metadata milestone complete)
Files: src/applications.ts, src/types.ts, src/app.ts, src/audit.ts; test/applications.spec.ts; jest.applications.config.cjs.
Interfaces: ApplicationsService(store).list(scope), create/update(scope,name,input), link(scope,application,input), unlink(scope,application,kind,name,input), remove(scope,application,input). Operations use expected metadata revision CAS; outputs contain metadata only. Catalog in _shared; tenant projections contain only local memberships. Canonical envName belongs to resource identity. Unknown applications cannot gain runtime support simply by creation.
- [x] Write fixture tests for create/edit/list, shared canonical ENV across apps, collisions, latest/pin, new version inheritance, stale revision, deleted resource, no values; run focused suite RED.
- [x] Implement strict bounded schemas, encrypted namespace fields and metadata CAS with no value changes. Disallow deletion while linked, canonical renaming while shared, and ambiguous legacy envName metadata.
- [x] Add guarded/audited HTTP routes and test list/write permissions, exact scope, sanitized errors and alias paths. Run focused suite GREEN and typecheck.

### Task 2: Applications UI and proxy boundary (metadata milestone complete)
Files: app src/components/applications-panel.tsx, src/lib/applications.ts, src/components/vault-console.tsx, src/lib/vault-proxy.ts; app test/applications.test.tsx and proxy tests.
Interfaces: metadata-only /local/applications collection/item and /local/applications/:app/resources/:kind/:name routes. Current connection scope stays explicit; catalog creation/edit is shared scope. Tenant views only expose links in current namespace.
- [x] Write UI tests for creating/editing an application, linking one existing secret to two apps with identical ENV name, unlinking, pinning, conflicts, forbidden/error/empty and dirty navigation; run RED.
- [x] Add Applications navigation, responsive model editor, metadata inventory picker with pagination and namespace context, resource/tag/membership inspection. Preserve existing sections, auth fencing and abort stale requests. Do not show secret values.
- [x] Allow only exact new proxy routes; test rejected path injection and response safety. Run full UI tests/typecheck/build.

### Task 3: Desired snapshot and refresh protocol
Files: API src/application-runtime.ts, src/runtime-snapshot.ts, runtime-client/index.cjs and declarations; test/application-runtime.spec.ts.
Interfaces: authorized current application desired descriptor per scope with exact resource names, canonical mappings and immutable versions; complete snapshot loader. Runtime refresh controller validates candidate, prepares adapter, swaps generation, reports status, retains previous valid generation on transient failure, observes revocation/known expiry. Bounded read-only registration/ack routes do not grant configuration writes.
- [x] Test explicit arbitrary resource names, Latest/pins, missing/disabled candidate, coherent generations and no values in status RED.
- [x] Implement versioned descriptor/resolver without changing legacy startup manifest semantics. Preserve encrypted key grouping and historical decrypt versions; unsupported migration has explicit blocked status.
- [x] Test serialized polling with fake time, out-of-order response rejection, successful adapter swap/drain, refresh failure, denial and local expiry; implement and run GREEN.

### Task 4: Consumer adapters and rotation integration
Files: actual reader/client inventory across club API, app, Explorer API and Explorer; APP-43 durable rotation interfaces.
- [ ] Inspect each reader/client and record supported swap/drain boundary before editing it. Write integration regression for actual client use of new values.
- [ ] Implement each verified adapter; group encryption-set transitions through durable migration. No pointer-only key changes, key generation during startup, or process.env tenant mutation.
- [ ] Measure normal end-to-end adoption within five seconds using synthetic data; verify partial rotation resume, retained historical decrypt, failed consumer/offline status and unrelated tenant availability.

### Task 5: Verification and independent review
- [ ] Run appropriate focused/full suites, API build/typecheck, app build/typecheck, whitespace checks. Record any unavailable infrastructure honestly.
- [ ] Fresh whole-change reviewer checks current files and real evidence; resolve important findings with regression tests.
- [ ] Update Jira with delivered scope and exact remaining blockers. No completion claim while required adapters/rotation are unfinished. No commit/push until verified; stage only task-owned files.
