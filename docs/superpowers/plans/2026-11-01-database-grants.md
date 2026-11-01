# Database grants implementation plan

**Goal:** Replace runtime VAULT_GRANTS with encrypted MongoDB grants and immediate revocation, preserving existing caller tokens during explicit migration.
**Architecture:** One encrypted registry document in vault_grants, with collection-specific ID, AES-GCM and CAS revisions using the existing MongoStore. Store only SHA-256 token hashes, exact scopes, permission arrays, enabled flag and stable IDs. Read the registry on every request; never fall back to environment grants. A local CLI sharing the database/master key creates, lists, updates permissions, revokes and imports grants. Existing user-approved local scripts are the administration boundary; no grant administration API or extra admin token.
**Stack:** Existing NestJS/Node24/MongoDB; no new dependencies.

- [x] Add failing integration tests for live create/revoke/permission changes across connections, restart persistence, encrypted and hash-only storage, scope isolation, safe/idempotent import, atomic concurrent writers and database failure.
- [x] Generalize encrypted CAS persistence to support the isolated grant registry; implement grant service with complete input validation and safe errors.
- [x] Remove environment authorization from bootstrap/controller; authorize asynchronously against persisted grants. Adapt test fixture seeding explicitly; no production automatic seed.
- [x] Add CLI and shell wrappers for create/list/permissions/revoke/import. Tokens printed only at creation; migration reads legacy env explicitly and reports counts only.
- [x] Update examples/docs, run build/typecheck/full tests, independent security review, then migrate existing local env grants and remove their env assignment after verification. Keep master key external; do not restart user processes or commit secrets.

Migration is atomic for a complete validated array. Existing IDs (including disabled grants) are skipped rather than overwritten, preventing stale configuration from undoing revocation or permission changes. Empty registry denies callers but allows startup for first-run CLI provisioning. No plaintext grant index or cache. In-flight requests already authorized can finish; subsequent requests see committed changes. Registry is bounded by the existing encrypted-document size limit. Migration never deletes namespace data or rotates caller tokens.

## Follow-up: token rotation

- [x] Add failing CLI/API rotation tests; implement atomic replacement preserving latest scope/permissions, retain disabled original against stale import, reject revoked grants/concurrent losers.
- [x] Add executable rotate.sh and CLI rotate command, update documentation and verify build/typecheck/59 tests plus independent review. No live grants rotated.
