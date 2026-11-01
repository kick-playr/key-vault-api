# APP-35 verification record

Implementation uses NestJS 11 and TypeScript on the local `codex/app-35-local-vault` branch. The repository had no commits or application code; an orphan feature branch was used in place because a worktree cannot be based on an unborn HEAD. Existing IDE files were left untouched and ignored.

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

The production dependency audit reports no advisories after overriding Nest 11's transitive multer to a patched 2.5 release. The full development dependency audit currently reports 20 low/moderate advisories in the Jest tooling graph (deepmerge, glob and minimatch and their dependents). No test server/tooling runs in the production start command. Avoided the audit's suggested major downgrade of Jest; these development dependency upgrades require separate compatibility review.

No deployment, live credential/key provisioning, migration, external message, or Jira status transition was performed.
