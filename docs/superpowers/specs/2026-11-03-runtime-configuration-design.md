# Runtime configuration: applications and tenants

Status: approved by user on 2026-11-03. ID: development. Display names: Club API, Club APP, Explorer APP, Explorer API. Tenants and bindings included, with hot tenant enrollment. Product name: Runtime configuration.

## Intent

Replace manual editing and enrollment of a metadata-only bindings plan such as `club-api-app.plan.json` with a complete UI. A runtime configuration groups the application bindings and tenant bindings for one environment. An application is an individual consumer; a tenant is an organization/data boundary; a binding chooses an existing secret/key version and its ENV mapping.

The initial editor manages the configuration for the connected environment. Do not introduce another application record for the configuration itself, or an unrelated projects/workspaces hierarchy.

## Approaches

- **Environment runtime configuration — recommended:** extend the existing application model with an environment-level overview, tenant assignments, plan import/export and validated runtime publication. Existing application records, resources and grants remain authoritative.
- **Standalone named bundles with duplicate app/tenant models — not recommended:** introduces conflicting copies of the same bindings and additional ownership rules before there is a requirement for multiple independent configurations in one environment.

## Existing evidence and migration boundary

- `club-api-app.plan.json` contains `club-api`, `app`, `explorer-api`, and tenant `fcrww`.
- The current new catalog contains `app`, `explorer`, `explorer-api`; `club-api` is absent. Explorer frontend is an additional separately approved application, not a replacement for Club API.
- fcrww's tenant secrets and wrapping/index/control key material already exist. Its application-link models are absent; legacy manifests still preserve its runtime bindings.
- Import must preserve the original three applications and tenant bindings, while retaining the separately configured Explorer frontend. Preview any conflicts with existing links and Latest policies. The Explorer API MongoDB URI currently differs from the old plan; do not silently overwrite it while importing.
- Preserve immutable version pins and historical wrapping labels from the old plan. Do not infer Latest for pinned resources. No secret values, credentials or private key material belong in import/export documents.

## UI

An environment's Runtime configuration page has:

1. **Applications:** the existing catalog, including name, slug, description and shared bindings. Create/edit applications using the existing controls.
2. **Tenants:** add an existing tenant slug such as fcrww, then choose its consuming applications and existing tenant resources. Tenant rows show name, assigned applications, binding counts and whether required key roles are complete. Use explicit tenant selection rather than exposing an unrestricted namespace directory.
3. **Tenant bindings:** select secrets and the existing wrapping/index/control key set. Show purpose, logical key role, ENV mapping, exact version/Latest choice and retained wrapping history. Shared resources remain shared; tenant resources remain in their tenant namespace.
4. **Review and save:** show metadata changes, affected consumers, missing resources, incompatible mappings and version conflicts. One Save action validates and records the reviewed configuration and publishes compatible startup manifests. Incomplete edits cannot be saved. Existing live activation controls remain separate.

Provide metadata-only **Import configuration** and **Export configuration**. Import accepts both the old bindings-plan JSON and the new configuration format. Old plans are resolved through the current plan parser and resource validation; their global tenant list initially assigns every listed tenant to every listed application, faithfully preserving the old publisher's semantics. An omitted old-plan version retains the old rule: resolve it only when there is exactly one stored version.

The new export is a distinct, versioned runtime-configuration document, with an explicit document kind, environment, application-to-tenant assignments, shared/tenant bindings and explicit Latest-or-pinned policies. Do not claim that it can be passed to the unchanged legacy plan CLI. Export must preserve selective tenant assignment and Latest policies without loss; a new-format import/export round trip retains both. Resolve Latest to exact immutable pins when generating existing schemaVersion-1 runtime manifests. Keep generated startup manifests compatible with the existing schemaVersion-1 format; dynamic discovery/credential transport may require a backward-compatible SDK update. This serialization choice is the implementer's recommendation, not a previously stated user preference.

Imports stage a reviewable draft before writing. Invalid or inaccessible resources fail without partially replacing the configuration. Import cannot grant a new consumer access by changing grant permissions.

## Binding semantics

- Application identities are environment-wide. Tenant assignment does not clone an application or a secret.
- Use existing canonical ENV mappings and mapping-conflict rules.
- Validate application contracts for live application-link models. Preserve legacy manifest tenant references faithfully even where a consumer currently reads only its process snapshot; do not silently drop an APP tenant reference from an imported plan.
- A tenant key set retains its profile, three role mappings, current wrapping label, retained wrapping versions and index/control pins. Selecting a wrapping key alone is insufficient.
- A saved configuration is metadata. Generating/publishing a manifest does not activate live mode, rotate keys, restart a service or migrate encrypted data.
- Apply existing encryption-key migration protections to actual key changes; configuration publication must not bypass them by updating a startup manifest. Metadata-only representation edits are not key rotation.
- Missing consumer startup configuration, including Explorer frontend, must be visible and can be generated after its complete bindings have passed validation.

## Live tenant enrollment without container restart

User requirement: adding a tenant through Runtime configuration must be adopted automatically by the already-running assigned applications. Adding a tenant must not require restarting the main container or editing its startup environment. This is required behavior after the updated runtime/consumer implementation has been installed, not a claim about the current implementation.

- Save publishes the new desired application-to-tenant assignment and complete tenant bindings. Assigned consumers refresh discovery and stage the new tenant within the existing five-second adoption target under healthy Vault/network/database conditions.
- Consumer discovery must not permanently cache the initial tenant list, and the legacy restart-only sealed-list checks must not remain the path used by dynamic enrollment. Requests must never discover or register arbitrary tenant IDs supplied by a caller; only an authoritative configuration revision can enroll a tenant.
- Dynamic enrollment requires refreshable credentials as well as refreshable manifests. A process-start-only AUTH_JSON map is insufficient for a new tenant scope. Use a stable application identity and a runtime credential supplier or application-scoped Vault transport. Bind the identity to its environment/application and enforce separately administered tenant access on the server for every request. A configuration link by itself never grants access. No copying tenant values into global process.env or changing startup env for each enrollment.
- Build the new tenant's immutable configuration, secret snapshot, key-ring view, database/provider clients and routing entry before exposing it to requests. Publish the ready tenant view atomically. Existing tenants and in-flight requests retain their valid views; never rebuild or restart the whole process just to add one tenant.
- The Vault binding is not the entire business tenant. Resolve the existing authoritative tenant definition, host/domain routing and registry metadata. If an organization has not been provisioned through the existing tenant-management flow, show that prerequisite instead of fabricating a usable tenant from a Vault namespace alone.
- UI runtime status is per application and tenant: Pending, Loading, Ready, or Error, with sanitized reasons. Missing permissions/resources or provider failures keep only the new tenant unavailable. Do not mark it Ready merely because the metadata save succeeded. A slow or failed external connection may exceed five seconds; show its actual progress/error and retry safely.
- Isolate tenant credentials, authentication state, connections and caches. Apply existing encryption-key migration safeguards to key changes; enrolling a new tenant must not rotate existing tenants' keys.
- Verify additions to Club API and Explorer API, and any tenant-dependent frontend routing/realm cache used by Club APP or Explorer. A frontend that delegates tenancy entirely to its API must continue through that API without exposing tenant secrets in the browser.

## Permissions and consistency

Reuse the existing scoped grant checks. Require appropriate read/list permissions to inspect each namespace and write permission for every namespace changed. Ask for the existing tenant grant when the current connection cannot access that tenant; tokens remain in memory and are excluded from saved metadata, exports, logs and errors. Never infer permission from a shared catalog entry.

Validate all referenced resources and expected revisions before publication. Publish immutable tenant manifest revisions first, retaining old history, then publish the shared application manifest batch that references those exact tenant revisions/digests. A failed partial attempt leaves the previous shared manifests usable and is safely retryable. Detect concurrent edits rather than silently replacing them. No claim of a cross-namespace atomic MongoDB transaction on a standalone server.

## Scope

Vault API, Vault UI, runtime SDK and the affected consumer adapters/registries, using compatible startup manifest formats. The dynamic-enrollment path requires consumer changes. No automatic grant expansion from links, secret import/regeneration, key re-encryption, process restart, live activation or deployment during implementation. Work in the existing primary development checkouts.

## Verification

- Round-trip the old metadata-only plan, including all three original application bindings and fcrww's key history and tenant secrets.
- Ensure Explorer frontend remains a separate fourth application.
- Test unauthorized/cross-environment references, missing resources/roles, duplicate mappings, explicit pins versus Latest and canonical ENV conflicts.
- Test per-tenant grants without token persistence or response leakage.
- Test concurrent modifications and failure between tenant/shared publication; old manifests must remain usable.
- Test UI tenant assignment, import preview, cancellation, save/export and manifest generation and dirty-state handling.
- Start a consumer with one enrolled tenant, save a second through Runtime configuration, and prove the same process/container identity adopts it within five seconds in healthy conditions. Check routed requests against both tenants and prove no process.env edits or cross-tenant leakage. Test a third unauthorized/invalid tenant failing independently, retried enrollment, duplicate saves and concurrent configuration revisions.
- Compare actual stored bindings and manifests read-only after publishing the user-reviewed configuration. Preserve all original secret strings and immutable resource versions.

## Builder check

A fresh builder identified one material gap: the legacy plan cannot express selective tenant assignments or true Latest policies. The new versioned export format and legacy-import rules above resolve it. All other implementation decisions can be settled in the plan.
