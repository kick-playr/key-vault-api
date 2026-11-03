# Application models and resource links

APP-49 implementation status: the editable application model, scoped v2 runtime
contract, server-only refresh controller and consumer-report UI are implemented.
The four existing application consumers still need their real reader/client
adapters and the APP-43 durable key-migration integration. Saving links does not
update legacy startup consumers. Do not activate this as a completed
end-to-end automatic-refresh release.

In the vault UI choose **Applications**. Connect to the desired environment and
`_shared` namespace using an operator grant with `list` and `write` permissions.
Create an application name and display label; edit its label/description; choose
an existing resource and its ENV variable name. Names remain immutable identities.
The same secret can belong to several applications with one canonical ENV name.
New versions preserve memberships. Version policy defaults to Latest; an optional
exact immutable pin stays fixed. Removing a link never deletes resource bytes.

Resource cards show canonical ENV name, kind, selected version, tags, and the
other linked applications in that resource's namespace. These are metadata-only
views: no secret values or private key material are loaded by this flow. Existing
Keys, Secrets, Advanced and Azure-style sections remain available.

Application records are environment-wide and stored in encrypted `_shared`
namespace metadata. Tenant views show only associations in the selected tenant.
To link a tenant resource, enter the existing application name and the separate
`_shared` catalog list token when needed; the current connection token must still
have tenant `list` and `write`. The catalog token is held only in the masked input
and cleared after a write. It cannot authorize reads or writes in the tenant.
Neither an application name nor a membership tag grants access.

## Metadata API

All paths support existing `/namespaces/:environment/:tenant` aliases. Exact
namespace headers, bearer authentication and no-store responses remain required.
The browser proxy supports only the exact paths below, not runtime value reads.

- `GET /local/applications`: list permission; returns the current metadata revision,
  namespace generation, scope and application/resource metadata.
- `PUT /local/applications/:application`: shared namespace only, list+write;
  body `{expectedRevision, displayName, description}` creates/edits the record.
- `PUT /local/applications/:application/resources/:kind/:name`: list+write;
  body `{expectedRevision, envName, version}` links/updates membership. `kind` is
  `keys` or `secrets`; version is `latest` or an exact 32-character hexadecimal ID.
  Tenant linking also checks shared catalog list authority, using
  `x-vault-catalog-token` for a separate scoped credential if supplied.
- `DELETE /local/applications/:application/resources/:kind/:name`: list+write;
  JSON body `{expectedRevision}` removes just the association.

The UI manages expectedRevision automatically. Stale edits return 409 rather than
silently overwriting concurrent work. Mapping changes conflicting with canonical
metadata or another resource in the application also return 409. Missing/inactive
versions, public ENV names and runtime bootstrap variables cannot be linked.
Canonical names cannot be changed through another app's link. Canonical metadata
is retained after unlinking the final application, so reusing the resource does
not silently rename it. Catalog/resource counts and request sizes are bounded.

The store uses its existing encrypted namespace CAS; no new collection or root
credential is exposed to a consumer or browser. Application operations use safe
metadata audit actions without request bodies, tokens or secret values.

## Scoped runtime contract

Runtime callers with an exact namespace `read` grant can use:

- `GET /local/application-runtime/:application/desired`: schemaVersion: 2 metadata
  resolves current UI membership and Latest/pins to exact resource names/versions.
- `POST .../snapshot`: `{generation,digest}` reads the complete matching values
  from one committed namespace. A changed generation/digest returns 409; no mixed
  or partial result is returned. Browser proxy access is forbidden.
- `POST .../in-use`: validates retained resource versions still exist, are linked,
  enabled, active and unexpired. A rejected new candidate is distinct from
  disabling the material already in use.
- `POST .../register`: `{}` creates a bounded 30-second reporting instance with a
  server-issued proof, stored only as a hash. Runtime identities never gain
  configuration-write permission.
- `POST .../acknowledge`: reports the issued instance/proof, generation/digest and
  state. Applied must match current desired metadata; warning/blocked reports may
  identify a retained earlier generation. Reports do not change data generation.

Operators with `list` can inspect `GET /local/applications/:application/status`.
Only this metadata report is available through the browser proxy; it contains no
proofs or values. The UI shows updating, reported applied, warning, blocked or
offline. No registered consumers means adoption is unconfirmed, not successful.
Reports are authenticated self-reports, not independent security attestations.

The new runtime-client export `createApplicationRuntime` accepts the built-in
application identity, exact scope, existing connection/grants and code-owned
mapping policy. A consumer adapter's `prepare` validates all values and builds a
replacement value/client before publication. Callers access it through
`withValue`, which holds a generation lease and an abort/deadline signal.
Default polling is 1 second; failure backoff is bounded to 5 seconds. Failed ordinary
refresh keeps the prior valid generation with a warning. Observed denial, removal
or disable of in-use material, and locally known expiry block admission.

Changed encryption or managed-credential material requires `prepareMigration`.
The controller fences local traffic, aborts/drains retained operations and keeps
failed migrations fenced until verified recovery. The adapter must still enforce
APP-43's durable tenant-wide fence, locking, resumable migration and historical-key
retention across every process. A pointer rollback cannot clear the local recovery
fence. Denial disposes active clients but retains a metadata-only encryption
baseline, so restoring access cannot bypass migration. Retained client generations
and concurrent leases are bounded. Callbacks must honor abort signals.

A desired descriptor is revalidated after preparation so a superseded candidate
is not published. Digests include scope, application, canonical mappings, selected
versions/classification and validity attributes; unrelated namespace changes and
instance acknowledgements do not force client reconstruction. Exact pins stay
fixed. Non-exportable key handles have no reviewed ENV adapter yet and remain
explicitly unsupported by this value transport. Tenant key roles must match the
existing deterministic key-set layout and be linked as a complete three-key set.
No old vault versions are deleted and no keys are generated by discovery/refresh.

## Remaining delivery

Follow the approved design and plan in `docs/superpowers/`. Legacy consumers are
still startup-only: club API seals tenant snapshots, app bootstrap caches one
load, and Explorer server/SDK configuration is captured at startup/import time.
Task 4 must compose application/shared/tenant scopes with control revisions and
replace actual readers/clients through verified adapters. It must also update
published/pinned package contracts. Merely changing process.env is insufficient.
APP-43's global durable migration and recovery remain unfinished. The scoped
runtime unit/integration tests are evidence for the protocol/controller, not proof
that these existing applications already refresh automatically.

## Explicit consumer migration

Creating/editing the model does not activate it. In the shared Application page,
**Use live configuration → Activate live configuration** validates the shared
links and sets a sticky server-side live-mode flag. The operator needs the same
shared namespace list/write authority and a current metadata revision. Editing
labels cannot reset activation. There is no ordinary downgrade button: returning
to old startup pointers could bypass completed key migrations.

Updated consumers read `GET /local/application-runtime/:application/mode` with
shared read authority. This adds no bootstrap environment variable. Before UI
activation they retain their legacy startup policy; afterwards they use the v2
controller. The client exposes `mode()` and supports seeding an already validated
process snapshot/prepared value, so invalid candidates retain working values and
key changes still require migration during this handover. The conversion helper
`applicationSnapshotFromLegacy` accepts process snapshots only, validates pins and
derives the existing deterministic resource names; tenant key sets need their own
explicit adapter. Dynamic realm mappings use a code-owned finite predicate, never
an operator-provided executable expression or arbitrary ENV injection.

A consumer that has already been activated must retain the encryption baseline
across cold starts. `applicationDescriptorFromLegacy` converts authenticated v1
immutable pins into metadata for the controller's `baseline` option, without
fetching obsolete values. This descriptor cannot serve data. Missing baseline
metadata fails closed; a changed encryption-key pin requires migration even on a
new process. Durable migration completion must advance the trusted baseline as
part of APP-43. An expired retained startup snapshot may preserve this comparison
baseline, but its values remain unavailable. Activation handover retries after a
failed first start so recovery does not depend on another browser request.
