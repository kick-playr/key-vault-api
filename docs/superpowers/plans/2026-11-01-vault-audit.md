# Vault audit implementation plan

Goal: implement the user's collection/console routing with ENV overrides.
Execution: native in the existing isolated vault worktree; no service starts.

1. Add failing HTTP/config tests with an in-memory store and no MongoDB process.
   Cover routing, snapshots, aliases, denied requests, secret exclusion and strict
   configuration. Run RED before implementing.
2. Add focused audit classifier/configuration and delivery service in src/audit.ts;
   configure through src/config.ts, persist separate events through src/store.ts,
   expose authenticated grant metadata through src/grants.ts, and attach a single
   request completion listener before auth/body parsing in src/app.ts. Drain audit
   delivery before store shutdown. Preserve namespace behavior and permissions.
3. Run tests GREEN, add error/abort/shutdown coverage, typecheck/build and document
   ENV syntax/defaults, collection fields, security boundaries and failure policy.

Review focus: POST snapshot classified read, versions classified list, operation
aliases/casing, denied grants never logged as authenticated, no request body/URL
or error message leaks, duplicate finish/close events, delivery failure handling.

Verification: initial HTTP/config tests witnessed RED (audit absent), then GREEN.
Review found unhandled automatic HEAD routes; its real HTTP regression witnessed
RED before normalizing HEAD to GET. Final `npm run test:audit`: 37 passed across
4 suites; full TypeScript check and build passed. Tests use fake HTTP/Mongo driver
boundaries, never start mongod. Full live-Mongo suite not run. No service activation,
secret import, package version bump, commit or publication performed.

2026-11-01: User explicitly requested merge back into development. Fresh audit37-test suite, TypeScript and build pass. Commit all current vault API changes, update existing vault PR1 and merge to development; other application PRs remain open. Existing0.1.1 patch bump is retained for this same unreleased feature branch. No services restarted or live environment changed.
