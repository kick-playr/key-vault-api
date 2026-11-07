# Static Vault cutover — development

The user authorized migration, service restarts and cutover on 2026-11-07, then explicitly approved FCRWW machine assignments for Club APP, Club API, Explorer APP and Explorer API. The user also selected Explorer's Clerk realm and existing global-admin list for Vault APP. Tenant-value consent remains a separate, unchanged authorization decision.

## Data and authority

- Normalized Vault: `key-vault-kick-playr`; control: `control-kick-playr`; FCRWW business/runtime storage: `fcrww-kick-playr`.
- Static migration verified 25 resources / 32 immutable static versions. One separately reviewed nonsecret Explorer API origin was added. Three obsolete source records remain solely in the encrypted legacy backup.
- Six OAuth history versions moved into encrypted native tenant runtime storage. Bexio remains `reauthorization-required` because its original refresh was unfinished. Migration never replays that refresh.
- Control data copied with original BSON types, collection options and ordered indexes. Its runtime envelope was re-encrypted under the new database AAD using the same wrapping key. Workflow key bindings now select the canonical control database; tenant Mongo references resolve the canonical tenant database.
- Tenant business documents, encrypted metadata, key bytes and key labels were preserved. Legacy `tokens`, `integration_sessions` and `integration_token_locks` were excluded from the target. Source databases were not modified. Empty target `test` collections were inspected, metadata-backed up and removed before verification.
- Activation used verified staging, stopped consumers, fresh private grant delivery and explicit machine enrollment approvals. Legacy HTTP paths are absent from the active v2 API. Original source databases remain operator-only rollback material, not an application fallback.

## Bootstrap and configuration

Ordinary consumers use `VAULT_URL`, `VAULT_APPLICATION_ID`, `VAULT_ENVIRONMENT`, `VAULT_GRANT`. `NODE_ENV`, API port/logging and existing Club APP compile-time feature flags remain operational configuration. Clerk keys, Mongo URIs, Redis credentials, control/wrapping/index keys and integration client credentials are absent from active consumer ENV files.

Vault API retains its external infrastructure root key and Mongo connection. Vault APP and Explorer APP have a separate server-only interactive provisioning grant; it does not replace signed human identity or tenant consent. Operator credentials are kept outside consumer ENV files.

Each changed ENV file has a private backup ending `.pre-static-v2-20261107.old`, excluded through the repository's local Git exclusion file. Deployment credentials, source mappings, HMAC review key, maintenance scripts and metadata evidence reside in the private, ignored plan workspace. They are never application/public artifacts. Original source filename provenance is retained when environment migration sources read their backup files.

## Runtime behavior and limitations

Startup waits for required static material. Requests use pinned memory; background refresh runs no more frequently than once per minute. An unchanged response preserves existing instances. Transport outages retain the last good snapshot. A validated authoritative update that cannot be installed clears the previous snapshot and invalidates the application graph, preventing revoked values from surviving a failed rebuild.

Tenant wrapping keys have a real Club API crypto probe before acknowledgement. Captured Clerk/application keys and Explorer's metadata-only tenant-key adapter do not automatically acknowledge prepared keys. Rotation remains blocked until the supported operator maintenance/migration procedure and explicit permanently-stopped instance confirmations satisfy the barrier. No fake key acknowledgements or timeout retirements were introduced during this cutover. This cutover preserved key bytes and did not rotate keys.

Post-activation rollback is deliberately refused by the automatic migration engine. Restoring ENV alone is not a safe authority rollback; a new coordinated migration is required once target authority is active.

## Evidence

Synthetic 200-tenant SDK benchmark: 47,730-byte snapshot; 100,000 memory reads with zero business-request Vault calls. This excludes network, MongoDB, Clerk and Bexio latency and is not a signed-in `/contacts/me` performance claim.

Release test counts and final endpoint checks are recorded in the execution ledger. Authenticated business verification requiring Bexio must follow a fresh account-bound reconnect; migration does not manufacture provider authorization.

Final checks: Vault 334/334 tests; Club API 93 focused checks; Explorer API 215 tests; Vault APP 128 tests; Explorer APP 24 targeted checks; consumer typechecks and production builds pass. Final public scans found zero secret matches in Club APP 65 files, Explorer APP 19 files and Vault APP 14 files. A fresh reviewer found and rechecked the SDK revocation fix and found no remaining Critical/Important cutover issues. Existing unrelated broad Club APP chat/manager/voucher script failures were not represented as passing.

All services are running. Club API Swagger is `http://127.0.0.1:4312/swagger-api`. Final unauthenticated `/api/contacts/me` returns 401 in about 1 ms; signed-in provider latency remains unmeasured until Bexio reconnect.
