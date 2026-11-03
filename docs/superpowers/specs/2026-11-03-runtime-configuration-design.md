# Runtime configuration: applications and tenants

Status: proposed implementation design, based on the user's approved four-step UI flow. Product name: Runtime configuration.

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

The new export is a distinct, versioned runtime-configuration document, with an explicit document kind, environment, application-to-tenant assignments, shared/tenant bindings and explicit Latest-or-pinned policies. Do not claim that it can be passed to the unchanged legacy plan CLI. Export must preserve selective tenant assignment and Latest policies without loss; a new-format import/export round trip retains both. Resolve Latest to exact immutable pins when generating existing schemaVersion-1 runtime manifests. No consumer SDK manifest-format change is required. This serialization choice is the implementer's recommendation, not a previously stated user preference.

Imports stage a reviewable draft before writing. Invalid or inaccessible resources fail without partially replacing the configuration. Import cannot grant a new consumer access by changing grant permissions.

## Binding semantics

- Application identities are environment-wide. Tenant assignment does not clone an application or a secret.
- Use existing canonical ENV mappings and mapping-conflict rules.
- Validate application contracts for live application-link models. Preserve legacy manifest tenant references faithfully even where a consumer currently reads only its process snapshot; do not silently drop an APP tenant reference from an imported plan.
- A tenant key set retains its profile, three role mappings, current wrapping label, retained wrapping versions and index/control pins. Selecting a wrapping key alone is insufficient.
- A saved configuration is metadata. Generating/publishing a manifest does not activate live mode, rotate keys, restart a service or migrate encrypted data.
- Apply existing encryption-key migration protections to actual key changes; configuration publication must not bypass them by updating a startup manifest. Metadata-only representation edits are not key rotation.
- Missing consumer startup configuration, including Explorer frontend, must be visible and can be generated after its complete bindings have passed validation.

## Permissions and consistency

Reuse the existing scoped grant checks. Require appropriate read/list permissions to inspect each namespace and write permission for every namespace changed. Ask for the existing tenant grant when the current connection cannot access that tenant; tokens remain in memory and are excluded from saved metadata, exports, logs and errors. Never infer permission from a shared catalog entry.

Validate all referenced resources and expected revisions before publication. Publish immutable tenant manifest revisions first, retaining old history, then publish the shared application manifest batch that references those exact tenant revisions/digests. A failed partial attempt leaves the previous shared manifests usable and is safely retryable. Detect concurrent edits rather than silently replacing them. No claim of a cross-namespace atomic MongoDB transaction on a standalone server.

## Scope

Vault API and Vault UI, using existing SDK manifest formats. No consumer source changes unless a verified compatibility issue requires them; no grant expansion, secret import/regeneration, key re-encryption, process restart, live activation or deployment. Work in the existing primary development checkouts.

## Verification

- Round-trip the old metadata-only plan, including all three original application bindings and fcrww's key history and tenant secrets.
- Ensure Explorer frontend remains a separate fourth application.
- Test unauthorized/cross-environment references, missing resources/roles, duplicate mappings, explicit pins versus Latest and canonical ENV conflicts.
- Test per-tenant grants without token persistence or response leakage.
- Test concurrent modifications and failure between tenant/shared publication; old manifests must remain usable.
- Test UI tenant assignment, import preview, cancellation, save/export and manifest generation and dirty-state handling.
- Compare actual stored bindings and manifests read-only after publishing the user-reviewed configuration. Preserve all original secret strings and immutable resource versions.

## Builder check

A fresh builder identified one material gap: the legacy plan cannot express selective tenant assignments or true Latest policies. The new versioned export format and legacy-import rules above resolve it. All other implementation decisions can be settled in the plan.
