# APP-49 — Application-managed vault configuration

Status: user-approved product design; Chris architecture/security approval is
recorded in APP-49 comment 10150. Engineering authorized by subsequent user approval.
The metadata/UI milestone is implemented; live runtime activation remains pending.
Prepared by Codex in delivery chat `01a19bed-7679-7bc3-9e6a-130bf59b6de1`.
This document includes source analysis and the Freddie-stage UX proposal; it does
not claim an independent Freddie review. Chris-role approval is attributed to
comment 10150, not to this document. APP-9 is excluded.

## Agreed product behavior

User decisions in APP-49 comments 10139, 10143 and 10144:

- Create Applications in the UI and link existing secrets/keys through managed
  application membership and ENV-name metadata. Inspect every linked resource
  and its tags from its Application page.
- The user explicitly approved the design and reaffirmed that applications and
  their secret relationships must be modelled in the UI. Users can create/edit
  application records, add/remove secret links, and inspect relationships from
  both application and secret details. This must be an editable model, not just
  a read-only view of code-defined applications or generated plans. An application
  record may exist before a compatible runtime consumer is connected.
- Bootstrap requires application name and grants, using existing/default vault
  connection configuration. No command-line plan creation or manual revisions.
- Sharing secrets across applications must work. Each logical secret has one
  canonical ENV variable name, identical in every consuming application.
- Latest is the normal default; optional exact-version pinning remains advanced.
- Both secret and encryption-key changes propagate automatically. The user
  accepted up to five seconds for normal adoption without a restart.
- A failed refresh retains the last working configuration and shows a warning.

The user explicitly confirmed on 2026-11-02: allow safe migration time. Ordinary
secret updates target adoption within five seconds. Encryption-key migration
starts automatically and shows progress within five seconds; it may take longer
and temporarily pause the affected tenant. Activate new keys only after safe
migration verification. This confirms timing/availability behavior, not approval
of every proposed implementation choice in this document.

## Source baseline and boundaries

Vault API development at `e585422`; both vault primaries matched fetched
origin/development during analysis. The app's existing `next-env.d.ts` edit was
left untouched. There were no open PRs in either vault repository.

- `docs/STARTUP-MANIFESTS.md`, `runtime-client/index.cjs`: application startup
  discovery already removes consumer `LOCAL_KEYVAULT_BINDINGS_JSON`. Manifests,
  values and dependent clients remain cached until restart.
- `src/runtime-manifest-plan.ts`: the administrator still supplies a plan and
  positive revisions. Multiple versions without a pin produce AmbiguousVersion.
  Current secret lookup derives names from purpose rather than arbitrary IDs.
- `src/runtime-manifests.ts`, `src/runtime-snapshot.ts`: immutable manifest history,
  digest validation and coherent reads within one namespace already exist.
  Tenant-first publication followed by the shared parent preserves prior graphs;
  there is no atomic transaction spanning namespaces.
- `src/types.ts`, `src/validation.ts`: resource tags are version metadata, limited
  to 15 string pairs of at most 512 characters each. `envName` is currently scalar.
- `src/inventory.ts`: current-version metadata supports exact tag filtering.
- `src/grants.ts`: grants authorize environment/tenant namespaces and permissions.
  Application name is a selector, not a resource-level authorization boundary.
- Consumer `fcrww-api/scripts/lib/api-secrets.cjs` and
  `src/secrets/api-discovery-contract.spec.ts`: finite mapping allowlist,
  startup-loaded process values and sealed tenant revisions require restart.
- APP-48 is To Do; its original problem statement predates startup discovery.
  Reuse its discovery/refresh scope instead of creating a competing system.
- APP-43 is To Do and requires durable `in-rotation` tenant unavailability,
  migration with all three tenant keys, verification and retained recovery keys.
- APP-50's existing resource forms should be reused for resource editing.

Initial delivery remains LOCAL_KEYVAULT in local development. ENV_VARIABLES
compatibility stays intact. Cloud activation remains gated by APP-47.

## Approaches and recommendation

1. Put an application list and envName directly on every secret version. This
   looks small, but membership can disappear on a new version and a growing list
   hits flat-tag limits. Historical version edits become configuration changes.
2. Recommended: first-class Applications and resource-level managed metadata
   inside the existing encrypted namespace store. Keep one canonical envName per
   logical resource and many application memberships; expose these as managed
   tags in the UI. Derive existing runtime manifests automatically. Ordinary
   version tags remain metadata, with no second editable membership truth.
3. Store independent application-specific mappings. This can express different
   names for the same secret but conflicts with the user's canonical ENV-name
   rule and adds unnecessary reconciliation; reject it.

Approach 2 is Codex's recommendation, not an approach explicitly chosen by the
user. Physical storage/route naming is for Chris to review. No new infrastructure
service, broker, operator file or manual counter is proposed.

## Identity, metadata and validation

An Application is identified by `(environment, applicationName)`. Resource
identity is `(environment, tenant, kind, logicalName)`; a version is separate.
Store the Application record in that environment's shared control namespace.
Keep authoritative canonical mapping/membership alongside the resource in its
own namespace. Application detail is a projection over authorized scopes, not a
second independently editable list. Reconcile derived indexes automatically.

Managed metadata: canonical `envName`, application memberships, and per-membership
version policy (`latest` or exact immutable pin). The UI labels these fields
Applications, ENV variable and Version. Ordinary tags remain visible below them.
Membership attaches to resource identity and survives a new version. Pins do not
move; changing an ENV name previews all affected applications and validates them
as one configuration change. Do not rewrite historical version tags to change
current membership. Reserved managed fields cannot be edited as free-text tags.

Applications may link only names in their supported finite consumer contract.
Initial supported runtime contracts are the four existing identities: club-api,
app, explorer-api and explorer. The UI may create another Application record, but
shows No compatible consumer registered and does not activate it until a reviewed
code-shipped contract exists. Free-form schema/ENV injection or a new contract
registration service is not part of initial delivery. This is a proposed scope
choice for review, not a user restriction already agreed.
Do not inject arbitrary ENV variables or browser/public values. Reject duplicate
ENV names pointing to different resources in one application/environment/tenant
target. Reject accidental shared-to-tenant shadowing; a contract must explicitly
distinguish process values from tenant-scoped fields. Tenant values never enter
shared process.env. Matching ENV names across distinct tenants are expected.

Shared secrets have one canonical ENV name across all applications. Linking adds
membership without copying secret bytes. Unlinking removes membership without
deleting the secret. Updating a shared Latest secret affects every linked Latest
consumer; exact pins remain unchanged. No requirement for cross-application key
sharing is inferred from the user's secret-sharing correction.

Proposed shared-edit rule: changing the canonical ENV name or removing a shared
membership requires authority to validate every affected application and scope.
Refuse the change if that authority or complete validation is unavailable; show
no unauthorized application details. Updating an authorized resource's value
uses existing resource write authority, and automatic publication/adoption
validates each linked consumer without expanding the operator's read access.
Chris must approve this distinction and the derived-publication authority.

Bootstrap retains the existing strategy selector for compatibility, built-in
application identity where already known, scoped grants and default URL and
development environment. An explicit existing environment selector is required
when grants cover multiple environments; never infer an arbitrary environment.
New tenant access still requires an authorized grant. Tags cannot issue grants.
Dynamic grant issuance/brokering is outside this design; APP-48 must use the same
control plane if that capability is added later.

## Concrete operator experience

Navigation adds Applications alongside existing Keys, Secrets and Advanced.
No existing resource editor or fallback section is replaced.

Example application detail:

| ENV variable | Resource | Scope | Version | Runtime state |
| --- | --- | --- | --- | --- |
| TENANT_CONTROL_MONGODB_URI | Existing control DB secret | development / shared | Latest | Applied |
| WORKFLOW_SHARED_WRAPPING_KEY_V1 | Existing shared encryption secret | development / shared | Latest | Applied |
| Existing wrapping/index/control names | Existing tenant key set | development / fcrww | Latest | Applied |

Actual inventory names and existing canonical mappings are displayed, never
invented names or live values. Non-exportable `/keys` show supported handles and
operations; tenant symmetric key sets stored as `/secrets` retain their role model.

Flow:

1. Create Application: name and explicit environment context. Explain that
   creation itself grants no resource access.
2. Link existing resource: choose an authorized scope, resource and supported ENV
   slot. Reuse its canonical ENV name if already set; an incompatible name is a
   clear validation error. Choose Latest by default, Pin in Advanced.
3. Review affected applications and validation. Save records desired metadata and
   automatically generates the required internal manifest graph. No JSON editor,
   plan command, revision copying or secret re-entry in this flow.
4. Show Saved, Updating, Applied, Using previous configuration — warning, or
   Rotation in progress. Saved does not mean consumers have adopted it.
5. Resource detail lists consuming applications, canonical ENV name, all ordinary
   tags, version history and status. Link/unlink is available from either entry
   point and edits the same metadata. Unlinking the last required resource fails
   validation unless the application is explicitly being deconfigured.

Desktop uses a resource table with filters and a detail drawer. Mobile uses cards
and a full-screen editor, with application/environment/tenant context persistent.
Provide keyboard navigation, labelled controls, inline errors, focus restoration,
and text status alongside color. Loading/empty/forbidden/not-found states must be
distinct. Warnings identify the affected scope and safe next action. No secret
values or runtime bearer tokens appear in adoption status payloads.

## Publication and live refresh

Use existing immutable descriptors and snapshots as the execution contract.
Automatic internal IDs/revisions must be distinct from the authoritative tenant
configuration revision: a secret refresh must not invent a tenant control revision.
Extend the descriptor contract to carry both where needed. Runtime checks tenant
control revision plus vault binding generation/digest, without manual coordination.
Preserve existing descriptors for legacy consumers during explicit migration.

The current purpose-based resolver cannot link arbitrary resource names. Extend
the finite descriptor with explicit validated logical resource references; retain
legacy purpose resolution. Snapshot reads still authorize exact namespaces and
validate kind, role, mapping, version and complete formats. No arbitrary URL fetch.

Writes use compare-and-set and idempotent operation IDs. Generate exact immutable
version references server-side. Publish complete tenant descriptors first, then
the parent application graph. Readers select only complete published graphs;
failed partial publication leaves old graphs usable and new history unreferenced.
Retry and reconciliation are automatic. Concurrent metadata/version changes must
retry against current generations, never silently overwrite a newer graph.

Proposed transport: authenticated bounded polling of desired application state,
using a one-second interval and conditional revisions. The healthy-operation goal
is end-to-end consumer adoption within five seconds of save for updates that can
validate and rebuild dependencies in that time. This is a measured target, not a
guarantee during network failure, long initialization or data migration.

Per application/tenant, serialize refresh; discard stale/out-of-order results.
Load a complete candidate snapshot, validate it, construct replacement clients,
then atomically publish the candidate generation for new operations. Existing
operations hold their original generation until drain/deadline and cleanup.
Never mutate tenant process.env or partially replace a multi-resource key set.
Process-only secrets need explicit adapters at their actual readers; changing
process.env after imports is not hot refresh. Inventory adapters for club API,
app, Explorer API and Explorer server before engineering scope is declared done.
Unknown or restart-only readers are explicit delivery blockers, not an Applied
status. Existing specialized OAuth renewal/CAS protocols remain authoritative.

Authenticated per-instance acknowledgements contain instance identity, applied
generation/digest and timestamps, never values. Applications show expected active
instances, last-seen state and per-instance pending/failed acknowledgements. No
registered instances means No consumers connected, never Applied. Instance
registration/expiry is automatic; an offline instance is shown as offline rather
than counted as successfully updated. Registration cannot create authorization.
Chris must review how acknowledgements are authenticated with existing grants
without granting runtime callers general metadata write access.

## Failure and key lifecycle

Initial startup without a complete validated snapshot fails readiness. After
successful startup, transient fetch, validation or client reconstruction failure
keeps the last working generation, disposes incomplete candidates, warns and
retries automatically with bounded backoff. Readiness reports degraded state
separately from whether the last working generation can serve traffic.

Proposed security distinction for Chris review: confirmed revoked/denied access,
tenant removal, or explicitly disabled/expired key material blocks new affected
work once observed. An unreachable vault is a refresh failure, not proof of
revocation. Do not promise immediate offline revocation. This distinction is not
an explicit user choice and must be surfaced in the approved security policy.
Latest selects the newest stored version; an invalid/disabled newest version
produces a failed update warning rather than silently skipping versions.
A disabled candidate retains the healthy prior generation. Disabling material
already in use follows the separately reviewed revocation/admission policy.

Saving a valid new encryption-key version automatically starts its supported
rotation workflow; no separate routine rebinding/restart step. Startup/discovery
never generates keys. Preserve immutable historical decrypt versions and labels.
Do not convert non-exportable keys to raw ENV values.

For APP-43's three-key tenant set, the update is one complete rotation operation,
not an independent edit of a single active member. Proposed UI behavior: Save on
the key-set rotation action authorizes exactly one replacement three-key set;
the system generates it once and runs migration/activation automatically. Managed
set members cannot bypass this operation through an individual version edit.
Pre-existing imported replacement sets must be complete and validated before
activation. Do not generate missing companion keys as a side effect of reading,
linking, or saving an ordinary secret. Chris must confirm this grouping against
the complete consumer key inventory before engineering.

Wrapping-key adoption may use version-labelled old/new decrypt capability where
the consumer supports it. Index/control/shared encryption changes require their
specific migration protocol; never simply switch Latest. Reuse APP-43's durable
operation IDs, tenant locking, checkpoints, migration, verification and active
reference switch. Prevent overlapping rotation and lifecycle writes. Do not
generate another set merely because a refresh retries.

Once APP-43 migration starts, its in-rotation admission fence controls availability;
failure retains recovery keys and checkpoints, but does not reopen traffic over
mixed migrated data. The ordinary keep-working-on-refresh-failure rule applies
before migration admission and to ordinary refresh, not an unsafe rollback after
data migration. Show real stage/count progress and resume safely. Old-key deletion
and retention require an explicit approved policy, including retained backups.

## Delivery, migration and verification criteria

This is a multi-repository change: vault API/client and UI plus all supported
server consumers. APP-49 owns Applications/canonical mappings/latest UX and the
user-facing activation outcome. APP-48 discovery/lifecycle and APP-43 rotation
must use this contract; do not claim either unfinished dependency already exists.
An implementation plan must allocate work explicitly and identify every reader.

Import existing manifest membership/mappings as a metadata-only, reviewed UI
operation. Detect contradictory envName tags, invalid references and missing
grants before activation; do not rewrite secret bytes or mint grants. Existing
consumers stay on their current valid startup descriptors until migrated to the
refresh-capable contract. No forced legacy fallback on malformed configuration.

Acceptance verification must cover shared membership/canonical names, conflicting
ENV mappings, namespace authorization, new-version inheritance, Latest/pins,
complete graph publication with CAS races, initial readiness, five-second normal
adoption, multiple instances and offline status, failed refresh retaining values,
revocation policy, tenant removal, actual dependency replacement/drain, historical
decrypt capability, interrupted/resumed rotation and tenant isolation. UI tests
cover desktop/mobile flows, keyboard/error states and honest adoption indicators.
Use synthetic fixtures; live grant/secret rotation is not required for testing.

No product code, live tags/grants/secrets, service start/restart, deployment or
merge is part of this design stage. Do not commit/push this draft before review.

## Remaining approval points

A fresh builder check identified key-set grouping, unknown application contracts
and authority for shared mapping edits. The explicit proposals above resolve
those planning gaps for Chris review; none is represented as a user decision.

1. Chris: review the proposed storage/descriptor generation, metadata write
   authority, runtime acknowledgement authority, tenancy/control revision split,
   failure/revocation policy, consumer adapter completeness and key retention.
   Record a SABB plus explicit approval covering this scope before engineering.
2. User product approval is recorded, with UI modelling of applications and
   secret links mandatory. Material product changes resulting from security review
   must be brought back to the user; do not request the same approval again.
   Chosen physical encoding, route names, polling jitter and routine implementation
   details are delegated to the builder within Chris's approved constraints.
