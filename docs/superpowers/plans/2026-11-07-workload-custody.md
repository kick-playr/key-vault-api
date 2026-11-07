# Workload-only custody amendment

User decision, 2026-11-07: application database credentials and control keys are workload-only. Applications can load them; administrators can see metadata; values and changes use the deployment/operator path. Tenant consent does not override this policy.

## Enforcement

- Resource custody is plaintext metadata, `workload-only` or `admin-managed`. Human resource update requests cannot change it.
- Missing classification on an application resource defaults to workload-only. Application encryption keys are always workload-only, even if mislabeled. Tenant resources retain their existing club-admin/consent policy.
- Interactive administration cannot reveal, replace, delete, revoke, prepare or activate a protected value. Rotation status, resource/version metadata and link metadata remain visible with ordinary metadata authorization.
- Known application database, Clerk secret and control-key ENV mappings reject admin-managed resources both when linking and when delivering a bootstrap snapshot. Renaming a resource or changing its ENV mapping never changes its custody.
- Ordinary read-only application grants can bootstrap explicitly linked protected resources. Custody never causes request-time Vault calls or introduces another bootstrap secret.
- New resources supplied through interactive administration are admin-managed, except application encryption keys, which cannot be created there. New resources provisioned through the operator service are workload-only. A reviewed migration can explicitly classify ordinary application secrets as admin-managed; unclassified imports remain workload-only.

## Deployment/operator entry point

`src/v2/workload-operator.ts:createWorkloadOperator(store, "Bearer <operator-password>", applicationScope)` is an in-process deployment entry point, not an HTTP route. It requires a separately provisioned, enabled `operator` grant and an explicit matching `vault_grant_scopes` document. Application grants and interactive provisioning grants cannot use it.

The returned opaque actor and authorization adapter can be supplied to `ResourceService` and `KeyRotationService`. They retain the ordinary resource CAS, value encryption, audit, key ACK and migration-evidence requirements. Each operation rechecks the grant and scope; transaction fences conflict with concurrent revocation. There is no automatic operator grant issuance or password reveal in the admin UI. Initial operator grant custody belongs to the deployment platform, separately from application and interactive credentials.

This entry point requires trusted Vault infrastructure access (including its value-encryption root), and must run only in the operator environment. It does not broaden the browser/API administrator boundary. No operator credentials were generated, exported or installed during implementation.

## Verified behavior

Native Mongo tests cover global metadata without plaintext; denied reveal/update/revoke/delete; operator create/reveal; ordinary workload bootstrap; rejection of a human-managed database mapping; operator revocation; and admin rotation-status visibility with denied protected activation. Unit tests cover safe defaults, forged operator identity rejection and migration custody review. Vault APP renders a workload-only explanation and disables human mutation/value controls.

## Remaining release work

This amendment resolves the pending custody decision. It does not complete the broader plan: the native runtime-token repository consumer integration, control-plane/catalog/identity migration, deployment credential delivery and consumer-specific key migration remain tracked in the original execution ledger. Live authority remains unchanged.

## Local operator command

The implementation includes `npm run workload:resource -- create <private-input.json>`, `update <resource-id> <expected-revision> <private-input.json>`, and `reveal <resource-id> <version-id> <new-private-output-file>`. Run these only in the trusted Vault operator environment. Configuration comes from explicitly supplied process/deployment variables, never an automatically loaded application `.env`: `VAULT_MONGODB_URI`, `VAULT_MASTER_KEY`, `VAULT_OPERATOR_GRANT`, `VAULT_APPLICATION_ID`, `VAULT_ENVIRONMENT`.

Input JSON contains the ordinary resource input fields (`name`, `kind`, `value`, `valueFormat`, `schemaIdentity` as appropriate). Input must be a regular private file with no group/other permissions; symlinks are rejected. Reveal writes only to a newly created mode-0600 file and never overwrites an existing file or prints a value. Value buffers are wiped after export; operator command failures are sanitized. Failed operations may leave an empty output placeholder, which the operator must inspect/remove before retrying. Control key rotation uses `KeyRotationService` through the same operator context; this generic resource update command deliberately cannot replace a key outside its ACK/migration barrier.

No command was executed against live infrastructure as part of implementation.
