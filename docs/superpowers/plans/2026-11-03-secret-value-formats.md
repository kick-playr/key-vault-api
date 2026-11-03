# Secret Value Formats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Record and display explicit secret formats, classify existing versions, and accept existing hex Clerk keys without altering their text.

**Architecture:** A server-side format module owns validation and inference. Format metadata travels through the existing encrypted version records and metadata APIs. An idempotent backfill uses the store's compare-and-swap machinery; frontend loaders validate both supported Clerk representations and publish the original strings.

**Tech Stack:** Existing TypeScript/NestJS/MongoDB API, Next.js/React UI, Node.js consumer loaders and current test runners. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-03-secret-value-format-design.md`

## Global Constraints

- `valueFormat`: `text`, `base64`, or `hex64`, per secret version.
- Explicit UI selection for new versions; omitted API format defaults to `text` for existing clients.
- Existing unclassified versions: hex64 first, then canonical nonempty standard Base64, otherwise text. Preserve explicit declarations.
- Never change the original string, version ID, pin, grant or activation mode during classification.
- Use primary development checkouts; preserve unrelated edits. Do not start/restart services or deploy.

## Review Focus

- A 64-character hex string also matching Base64 must classify as hex64.
- Metadata-only writers must not receive secret values in successes or validation errors.
- Empty, unpadded, whitespace-containing and noncanonical Base64 must not be guessed as Base64.
- Historical/disabled versions must be classified, and concurrent writes must survive retries.
- Changing a format declaration or loading a mixed-case hex key must never normalize its text.

### Task 1: API format contract and safe backfill

**Files:** Create `src/secret-value-format.ts`, `src/backfill-secret-value-formats.ts`, `test/secret-value-format.spec.ts`; modify `src/types.ts`, `src/vault.ts`, `src/inventory.ts`, `src/applications.ts`, `src/store.ts`, `src/provisioning.ts`, `src/oauth-credentials.ts`, `src/swagger-schemas.ts`, `package.json`, `test/api.spec.ts`, and relevant store tests.

**Interfaces:** Export `SecretValueFormat = 'text' | 'base64' | 'hex64'`, `validateSecretValueFormat(value: string, format: unknown): SecretValueFormat`, and `inferSecretValueFormat(value: string): SecretValueFormat`. Add optional `Version.valueFormat`; new versions store a validated format. Migration results expose counts only.

- [x] Write failing tests for all formats and invalid declarations; assert exact preservation of mixed-case hex and canonical Base64. Test hex-first inference, historical versions, idempotence, and preservation of existing declarations.
- [x] Run `npm test -- --runTestsByPath test/secret-value-format.spec.ts test/api.spec.ts`; confirm new assertions fail for missing behavior.
- [x] Implement the format helpers, create/metadata-patch validation, metadata projection, Swagger contract and declaration preservation in internal provisioning/rotation writers. Do not include representation metadata in consumer runtime descriptors unless required; existing runtime strings stay opaque.
- [x] Add a dry-run/apply backfill command. Enumerate encrypted namespace documents, classify only missing declarations, and persist through the existing document CAS transaction helper. Do not rewrite opaque/non-namespace collections. Abort safely on decode errors; print no values or hashes. Count scanned/updated versions and namespaces. Add migration audit entries and generation updates only for changed namespaces.
- [x] Run focused tests, API typecheck/build, then the full applicable API suites. Verify metadata-only responses never disclose a value. Commit the independently verified API changes on development.

### Task 2: Vault format controls and display

**Files:** Modify `/Users/Lolo/git/key-vault-app/src/lib/azure-vault.ts`, `src/lib/inventory.ts`, `src/lib/applications.ts`, `src/lib/operations.ts`, `src/components/azure-vault-form.tsx`, `src/components/azure-vault-panel.tsx`, `src/components/inventory-panel.tsx`, `src/components/application-links-table.tsx`, and their corresponding tests under `test/` (all relative paths in this task belong to the Vault UI repository).

**Interfaces:** Consume optional `valueFormat` in secret metadata; expose the three exact server enum values with labels Plain text, Base64, Hex (64 characters). RSA keys have no secret format control.

- [x] Write failing operation/parser/component tests for create, metadata edit, historical-version display and linked-application display. Assert unknown format values fail safely and value-free UI state stays value-free.
- [x] Run the focused test files and verify missing controls/projection cause failures.
- [x] Implement the select, request serialization, metadata parsers and visible format labels. New-version forms require explicit selection; editing retains the selected version's declaration. Format-only edits never fetch a value into client state.
- [x] Run UI tests, typecheck, lint and build appropriate to the repository. Review the edited React components and commit only verified changes on development.

### Task 3: Existing Clerk key compatibility and live verification

**Files:** Modify `/Users/Lolo/git/fcrww-app-kick-playr-ch/src/server/secrets-bootstrap.mjs`, `scripts/test-secrets-bootstrap.mjs`; modify `/Users/Lolo/git/kick-playr-tenant-explorer/src/lib/server-secrets-core.ts`, `test/server-secrets.test.ts`, `test/server-secrets-live.test.ts`. Add v2 assertions to the existing APP live-secret test script where applicable.

**Interfaces:** Existing bootstrap/v2 loader signatures remain unchanged. Clerk encryption keys accept canonical Base64 representing exactly 32 bytes OR exactly 64 ASCII hex characters. Return the input string unchanged.

- [x] Add failing loader tests accepting mixed-case hex and canonical 32-byte Base64, rejecting malformed hex, incorrect decoded lengths and noncanonical Base64. Assert all-or-nothing publication and exact original text.
- [x] Run the APP and Explorer focused secret tests; confirm hex acceptance fails before implementation.
- [x] Change only Clerk encryption-key validation, retaining existing environment, mapping and fail-closed guards. Run focused tests and consumer typechecks/checks required by each repository; commit verified changes on their existing development branches.
- [x] After all checks pass, run the migration dry-run and then apply the user-authorized backfill against the existing Vault. Verify all retained secret versions now have valid formats; compare values/version IDs/pins against an in-memory pre-migration snapshot. Repeat apply and verify zero further changes.
- [x] Run read-only live grant/snapshot and actual APP/Explorer loader validation against the stored strings. Report loader results separately from startup-manifest readiness. Do not activate, restart, re-encrypt or deploy anything.
- [x] Publish verified development commits following each repository's applicable version/release instructions, without PRs or merges unless explicitly requested. Report the evidence and any remaining startup-manifest blocker.

## Delivery evidence

API: 26 suites / 213 tests passed, plus the subsequently added deterministic CAS race and metadata-write-only tests passed; typecheck/build passed. UI: 98 tests, typecheck/build passed. Explorer: 131 tests and typecheck passed. APP: 11 bootstrap, 11 live-secret and 14 version checks passed; typecheck passed. Fresh reviewer found no blocking issues.

Live backfill: 32 versions across four namespaces classified (17 text, 12 Base64, 3 Hex64). All original values/version IDs/links and activation modes verified unchanged; repeat apply updated zero versions. APP legacy/v2 and Explorer v2 secret-loader validation passed with live grants. Explorer legacy startup still needs a manifest; no restart, activation or deployment was performed.
