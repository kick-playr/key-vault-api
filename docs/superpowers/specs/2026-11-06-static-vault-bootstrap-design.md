# Static Vault, tenant integrations, and application bootstrap

Date: 2026-11-06
Status: **Draft for approval — implementation is not authorized by this document alone.**

## 1. Intent and scope

Vault owns static secrets and exportable encryption keys. Applications load their authorized material before becoming ready, serve business requests from memory, and check for changes in the background. Integration access tokens, refresh tokens, OAuth state and other persisted runtime credentials belong in encrypted application/tenant databases, never in Vault.

This redesign covers Key Vault API, Key Vault APP, their MongoDB storage, the shared bootstrap SDK, and adapters for Club APP, Club API, Explorer APP, Explorer API and Vault APP. Vault API's own infrastructure bootstrap is described separately below. It also covers migration of the existing mixed static/runtime OAuth bundles.

It does not redesign ordinary Club configuration, business authorization rules, or the previously agreed one-hour Bexio contact-input cache. Those continue to follow their own contracts. Integration recovery must work independently of a functioning Bexio connection.

## 2. Decisions agreed with the user

| Area | Agreed behavior |
| --- | --- |
| Persistence | Explicit MongoDB collections, replacing large encrypted namespace aggregates as the authoritative model. Secret payloads remain encrypted. |
| Document granularity | One document per grant, resource, resource version and relationship; no document containing all grants or all of a tenant's secrets. Names, tenant/application names, versions, types and other non-secret metadata remain plaintext and directly queryable. Encrypt only secret/key value payloads; grant passwords are stored as hashes. |
| Applications | Each application has an entry, static secrets, tenant assignments and explicit resource links. |
| Tenants | Assigning a tenant does not expose all its secrets. Only explicitly linked secrets and integrations are loaded. |
| Application memory | Application-wide secrets may populate `process.env`. Tenant secrets remain in isolated server-only memory contexts. |
| Bootstrap credentials | Only the Vault URL, application ID, environment and bootstrap grant remain in application ENV/deployment secrets. Vault API also needs its infrastructure database connection and master encryption key externally. |
| Startup | Wait and retry while Vault is unreachable; readiness is unavailable and application requests are blocked until required secrets are loaded. Report “Key Vault is not connected”. |
| Refresh | Load at startup and refresh in the background, no more frequently than once every minute. Business requests never fetch secrets from Vault. |
| No changes | An unchanged authorized configuration does not replace the snapshot, overwrite ENV or recreate clients. |
| Vault outage | After successful bootstrap, keep using the last loaded secrets until connectivity returns. No age-based eviction solely because Vault is unreachable. |
| Revocation | Explicit grant revocation, resource revocation or unassignment removes affected access at the next successful background check. Stop only the affected tenant/functionality. |
| Integration instances | Multiple named instances of the same integration type are supported per tenant. |
| Integration schema | Enforce built-in type schemas and support custom integrations with a user-defined JSON schema. |
| Runtime tokens | One encrypted runtime-token record per tenant integration, shared by consuming applications, with only one refresh operation at a time. Redis is optional. |
| Cryptography | Applications download authorized keys and perform cryptography locally. No request-time Vault crypto service. |
| Key activation | All affected running application instances must acknowledge loading the new key before activation, including temporarily disconnected instances. |
| Instance retirement | No timeout removes an instance from the rotation barrier. An admin must explicitly confirm it is permanently stopped. |
| Machine grants | One read-only application grant per application/environment, automatically following approved tenant assignments and resource links. |
| Writes | Separate administration/provisioning grants; interactive writes are authorized against the signed-in human's permissions. |
| Human roles | Global admins manage the platform; club admins manage their own tenant's secrets/integrations, not application-wide secrets, grants or other tenants. |
| Tenant consent | Global admins can see names, types, links and status. Reading tenant values or editing requires that tenant's club-admin approval for the global-admin role. |
| Consent lifetime | Approval remains active until a club admin revokes it. Approved application access remains independent of this human-administration consent. |
| Migration | A coordinated maintenance window is acceptable. |

The remaining detailed choices in this document are design proposals, not additional user decisions. They are identified where security or operation depends on them.

## 3. Approaches considered

1. **Evolve the existing encrypted namespaces.** Preserve namespace-level encryption/CAS and adapt their contents. This reduces migration work but retains large mixed aggregates and makes independent ownership, revisions and consent harder to express.
2. **Explicit collections with encrypted payloads.** Separate identity, ownership, links, immutable versions, access policy and operational state. This gives a clearer authoritative model and permits small change manifests without reading all secret payloads.

The user selected **approach 2**. Keep MongoDB and the existing TypeScript/NestJS/Next.js applications. Introduce one shared SDK rather than implementing different bootstrap/security rules in each consumer.

## 4. Domain model and ownership

### Applications and environments

Canonical application IDs are `club-app`, `club-api`, `explorer-app`, `explorer-api` and `vault-app`. Migration maps legacy IDs such as `app` and `explorer` explicitly; it must not create duplicate applications. Names and descriptions remain editable metadata. Tenant names such as `fcrww` are not embedded in application IDs.

An application catalog entry is environment-independent. An application deployment is `(applicationId, environment)` and owns its bootstrap policy, application-wide links and instance registrations. No development grant can access a different environment.

A tenant has a stable ID and display name. An environment-specific tenant record owns its static resources and access policy. Assignments connect application deployments to tenants in the same environment.

### Resource kinds

All values are versioned resources with one owner: an application deployment or a tenant environment.

| Kind | Examples | Representation |
| --- | --- | --- |
| Static secret | MongoDB URI, Clerk secret, SMTP password | Encrypted value with explicit format metadata. |
| Encryption key | Tenant wrapping key, blind-index key, application encryption key | Encrypted key material with algorithm, encoding, version and lifecycle metadata. |
| Integration | `bexio-accounting`, `dropbox-documents`, `email-membership` | Encrypted JSON validated against an immutable integration-schema version. |

Tenant resources are stored once and can be linked to multiple applications. A link references a resource/version policy; it never copies a value. Preserve the same canonical ENV/access name when sharing the same resource, consistent with the earlier approved sharing rule. Duplicate names within an effective application or tenant context are rejected, not silently overridden.

Application and tenant scopes do not implicitly override each other. A consumer asks explicitly for application material or a particular tenant context.

### Static integration JSON

Each integration has a stable ID, tenant, environment, unique tenant-local name, type and schema version. Link by stable ID; use the name for display and application lookup.

Examples of static fields:

- Bexio: client ID, client secret, expected account reference and approved callback settings.
- Dropbox: application key/secret and static connection settings.
- Pingen: its administratively configured API credential and organization/settings required by that integration's authentication mode.
- Email: protocol, host, port, TLS mode, username, password and allowed sender information.

An administratively configured API credential is not classified by whether its field contains the word “token”. Classification follows the provider schema and credential lifecycle. OAuth access/refresh/ID tokens and session JWTs are runtime material. Do not classify arbitrary values by their appearance alone.

`contentType` is `application/json`; JSON structure and value encoding are separate concepts. Existing plain-text, Base64 and 64-character hexadecimal key formats remain supported explicitly. Do not silently convert existing key bytes.

Named integrations remain structured objects in the tenant registry. Do not flatten two email accounts into colliding ENV names. An application-owned integration can also be a resource, but tenant integration runtime data always stays in its tenant database.

## 5. Vault MongoDB collections

Collection names below are proposed concrete names. Every scoped collection uses compound indexes containing the environment and owner identity. Schema validators reject unknown security-critical fields and cross-environment references. No value is embedded in link, grant, consent, instance or audit documents.

### MongoDB document principles

Use collections as collections of individually addressable entities, not as containers for one global registry document. In particular, `vault_grants` contains **one document for each grant**. Grant creation inserts a document; revocation updates that grant by ID and expected revision. Do not load, rewrite or CAS an object/array containing every grant to change one credential.

The same rule applies to resources, versions, applications, tenants, assignments and links. Histories and potentially growing relationships are separate documents with indexes, not unbounded nested arrays. Small bounded fields such as a grant's capability-name array can remain embedded in its own document.

Names, descriptions, tenant/application IDs and names, resource type, content type, version IDs/numbers, encoding, schema identity, enabled state, timestamps, links, permissions and consent/rotation status are plaintext metadata. A metadata query, search, filter, sort or pagination operation requires **no payload decryption**. A secret-version listing obtains the display name/type/owner through indexed resource/tenant/application references and returns version metadata without the encrypted value field.

Encrypt only fields that actually contain secret values: scalar credentials, encryption/private key material and integration JSON payloads. For integration JSON, the whole JSON value is one encrypted payload; its instance name, integration type and schema/version remain ordinary metadata. Grant passwords are the exception to reversible value storage: persist only their cryptographic hashes, never an encrypted or plaintext recoverable password.

| Collection | Important fields / responsibility |
| --- | --- |
| `vault_applications` | `_id: applicationId`, display name, description, metadata revision, deletion state. |
| `vault_application_environments` | Unique `(applicationId, environment)`, configuration revision, required-capability declarations, policy revision, status. |
| `vault_tenants` | `_id: tenantId`, display name and non-secret catalog metadata. |
| `vault_tenant_environments` | Unique `(tenantId, environment)`, status and resource/policy revisions. |
| `vault_resources` | Resource ID, owner type/ID, environment, kind, unique owner-local name, content type, format, schema ID/version or key algorithm, selected/current version, enabled state and revision. |
| `vault_resource_versions` | One document per immutable version: version ID/number, resource ID, scope, kind, content type/encoding, schema reference, encrypted **value field** with its envelope, creation actor/time and lifecycle metadata. All fields except value material are queryable metadata. |
| `vault_integration_schemas` | One document per built-in or tenant-owned custom schema definition, with name/type/owner and current version reference. |
| `vault_integration_schema_versions` | One document per immutable schema version: schema identity, JSON schema, display-field definitions, static/public/private field annotations and validation limits. No actual integration credentials are present. |
| `vault_application_tenants` | Unique `(applicationId, environment, tenantId)`, enabled state and revision. No secret values or duplicate ENV mappings. |
| `vault_resource_links` | Application deployment, optional tenant ID, resource ID, access/ENV name, version policy and optional capability association. Explicitly selected resources only. |
| `vault_grants` | **One document per grant:** ID, token hash, grant class, application/environment, bounded capabilities, enabled state, policy revision and issuance/rotation audit references. Never a single document containing every grant; never plaintext grant passwords. |
| `vault_grant_scopes` | One document per explicit provisioning grant/owner-scope relationship when a grant covers multiple owners. Application grants derive effective access from their application links instead of copying all resource IDs into a grant document. |
| `vault_tenant_admin_consents` | Unique `(tenantId, environment)`, global-admin-role approval, approval/revocation actor and times, monotonically increasing policy revision. No expiry by default. |
| `vault_principal_bindings` | Authoritative references to the existing platform/tenant identity policy, including issuer/audience and policy revisions. Not a duplicate independently editable club-admin membership list. No application grant can modify these. |
| `vault_application_instances` | One document per boot instance: application/environment, random boot-instance ID, public process metadata, observed status, loaded view revision and explicit retirement record. |
| `vault_instance_key_versions` | One document per instance/key/version observation or acknowledgement, rather than an ever-growing key history array in the instance document. |
| `vault_key_rotations` | One document per job: owner/key, old/new versions, state, participant membership revision and migration/activation status. |
| `vault_key_rotation_participants` | One document per rotation/instance: required key version, ACK state and any explicitly authorized permanent-stop retirement. |
| `vault_change_heads` | Effective-view/source revisions used to cheaply determine whether an authorized bootstrap view changed. Excludes audit reads and ordinary heartbeat timestamps. |
| `vault_audit_events` | Append-only actor, scope, action, target IDs, result, policy/consent revision and correlation ID. No secret values, tokens or grant passwords. |
| `vault_migration_jobs` | One document per job: reviewed inventory digest, phase, summary counts, verification and rollback/cutover markers. No plaintext credential payloads or embedded full-source inventories. |
| `vault_migration_items` | One document per job/source entity or version: source digest/revision, staged target reference, verification and progress state. No secret values. |
| `vault_platform_settings` | Versioned platform identity configuration and internal bootstrap references. Infrastructure root keys/URI remain external. |

Required unique indexes include owner-local resource names, resource/version IDs, assignments, link access names per effective context, schema versions, consent scopes and instance boot IDs. Foreign-reference ownership is checked inside the same transaction as publication. No TTL index deletes cryptographic versions, runtime instance registrations or rotation participants.

Index grant token hashes uniquely for direct credential lookup, grant application/environment/status for management, resource owner/name/type for inventory, resource ID/version for history, and relationship IDs for scope/usage checks. Reads use field projections that exclude encrypted values by default. Examples are `vault_grants.findOne({_id: grantId})`, resource inventory queries by tenant/environment/type, and version metadata queries by resource ID; none decrypts an aggregate registry.

### Encryption and transactions

Proposed payload format: AES-256-GCM with a random data key per immutable resource version; wrap that key using Vault's externally supplied master key. Authenticate a canonical AAD containing format version, environment, owner, resource ID, resource version and schema identity. Use distinct AAD purposes for payload encryption and data-key wrapping. Swapping ciphertext or wrapped keys between owners/versions must fail authentication.

Names/types/relationships are deliberately plaintext, indexed metadata; encrypt the value field, not the enclosing document or namespace. Wrapped data keys and payload ciphertext/authentication fields belong to that value's encryption envelope. Raw secret fingerprints are not exposed through metadata APIs. Root master-key rotation is an infrastructure operation, separate from application key rotation; retain the old root key until wrapped data keys have been migrated and verified.

Publish resource pointers, affected link/view revisions and audit records in MongoDB transactions with majority writes and CAS on the expected revision. Serve one coherent authorized bootstrap view using a database snapshot. If payloads require pagination, bind all pages to a fixed view/version set and publish nothing in the SDK until all pages validate. Do not independently read changing “latest” pointers page by page.

Deletion is blocked while a resource/application is in use, and requires a confirmation showing the actual usage. Disabling/revoking is explicit and distinguishable from deleting metadata. Historical encryption keys needed by tenant data cannot be deleted through an ordinary secret-delete action.

## 6. Roles, consent and grants

### Human administration

| Operation | Club admin | Global admin without tenant consent | Global admin with tenant consent |
| --- | --- | --- | --- |
| Tenant resource metadata | Own tenant | All tenants | All tenants |
| Read/reveal tenant values | Own tenant | Denied | Approved tenant |
| Create/edit/revoke tenant secrets, keys and integrations | Own tenant | Denied | Approved tenant |
| Manage tenant-local links to existing applications | Own tenant, within approved platform policy | Denied if it changes tenant access | Approved tenant |
| Manage application-wide resources/catalog | Denied | Allowed | Allowed |
| Manage grants | Denied | Platform management subject to the anti-bypass rules below | Same rules, with relevant consent satisfied |
| Approve/revoke global-admin access | Own tenant | Denied | Denied |

The row for tenant encryption keys treats them as tenant server-side secrets; high-impact retirement/rotation still uses its dedicated workflow. Club admins do not edit global integration schema definitions. They may manage custom schema definitions owned by their tenant.

Consent is checked server-side on every sensitive administrative operation, including direct API requests and values revealed through the UI. Check policy again at write commit/reveal publication so revocation racing an operation is respected. Cached application secrets are not a source of human-administration authorization.

Reuse the existing Explorer authority model: verified platform issuer plus its administrator-subject policy for global admins, and the active tenant authority's issuer/subject membership with the required club settings permissions for club admins. Vault API independently verifies the identity/delegation and consults that authoritative policy through a trusted server adapter; a proxy header or frontend role is not proof. Do not introduce a second role registry that can disagree with Explorer. Once tenant ownership is established, platform-initiated replacement/addition of its consent approvers cannot be used as an unapproved ownership takeover. Initial onboarding and exceptional ownership recovery require a separately audited provisioning procedure, not a global-admin self-approval button.

Approved machine access is independent of global-admin-role consent. Human consent revocation invalidates human access immediately at the policy boundary; it does not revoke the tenant's legitimate application bootstrap grant. An application background loader continues to check its own machine authorization once per minute.

**Anti-bypass proposal:** global admins cannot expose unapproved tenant values by adding/changing links, exporting snapshots, issuing or rotating a usable application password, changing a tenant resource's owner, or modifying the tenant's consent approvers. Grant issuance/reissue that exposes an existing tenant requires the relevant tenant consent or a club-admin-approved deployment provisioning action. Raw machine passwords are delivered only through that authorized provisioning action, are never retrievable from the grant list, and are not available to a global admin merely because they can edit grant metadata. Changing a tenant's authorized club-admin membership must not let a global-admin-role holder appoint themselves and self-approve access.

This is an application-role boundary. Infrastructure operators holding the Vault master key/database root or control of deployed application code are outside that boundary. Revocation cannot make a person forget previously disclosed values or credentials; credential compromise requires rotation. The design must not claim cryptographic protection from those operators.

### Grant classes

- **Application bootstrap:** one active credential policy per application/environment; read-only access to that application's effective linked resources and exportable keys. Scope follows assignments/links; permission does not broaden by the application submitting a different ID or tenant. Every resource export is authorized against the current policy, including conditional requests.
- **Interactive provisioning:** held server-side by the authorized administration backend, restricted to its permitted environment/owner scopes. A write additionally requires independently verified human identity, role and tenant consent. A browser cannot supply a trusted `isAdmin` flag or bypass consent by presenting the service credential alone.
- **Operator provisioning/migration:** separately issued, explicit scopes and audited use; never the normal consumer credential. Does not create an unlogged global-admin consent bypass.

Use explicit capability names for metadata listing, static-value reading, key export, resource/version writing, assignments, grant administration and rotation administration. Legacy `crypto` is migrated to authorized local-key export where applicable, not remote request-time crypto. Normal application grants never gain generic write capability.

Store only a cryptographic hash of a random, high-entropy grant password; show/deliver a newly generated password only through the authorized issuance workflow. Rotation creates a new credential and revokes the previous one. No bearer credential, user JWT or secret is logged or embedded in a browser URL.

## 7. Bootstrap contract and shared SDK

### Bootstrap inputs

Proposed common inputs are `VAULT_URL`, `VAULT_APPLICATION_ID`, `VAULT_ENVIRONMENT` and `VAULT_BOOTSTRAP_GRANT`. Application ID/environment may be fixed by trusted deployment code rather than manually repeated. The URL is not a secret; the grant is.

Administration services may additionally receive their separate provisioning bootstrap credential through deployment secrets. It is not returned to the browser, mixed into ordinary tenant material, or treated as a user authorization decision. Existing host/port and other non-secret infrastructure process settings are not credentials; the migration inventory must distinguish them rather than blindly deleting necessary launch settings.

Vault API loads `VAULT_MONGODB_URI` and `VAULT_MASTER_KEY` externally, opens its store, then resolves its own platform/static configuration internally. It never calls its own HTTP bootstrap endpoint as a startup dependency. Any additional infrastructure bootstrap inputs must be explicitly documented, not hidden in fallback ENV defaults.

### Proposed API surface

| Endpoint | Purpose |
| --- | --- |
| `GET /v2/bootstrap` | Grant-bound application/environment view. Returns coherent initial or changed snapshot, or `304` when unchanged. Optional fixed-view pagination for large payloads. |
| `POST /v2/bootstrap/instances` | Register a new boot instance with application identity bound to the grant. Returns current required key preparation/activation state. |
| `POST /v2/bootstrap/instances/{id}/ack` | Acknowledge successfully validated and installed revisions/key versions for that instance. Does not authorize general resource writes. |
| `POST /v2/bootstrap/instances/{id}/status` | Report readiness/degraded state or graceful shutdown. Missing reports do not automatically retire the instance. |
| `/v2/admin/applications`, `/tenants`, `/resources`, `/schemas`, `/links`, `/grants`, `/consents`, `/rotations`, `/audit` | Separately authorized metadata and management operations. Value reveal/export is explicit, not part of metadata listing. |

Administrative editing legitimately calls Vault as a management operation. The prohibition on request-time Vault calls applies to serving application business/authentication/integration requests using loaded secrets.

A bootstrap view contains: application identity/environment, opaque effective view revision, authorized application resources, assigned tenant contexts with only explicitly linked resources, resolved immutable resource/schema versions, enabled/revocation/capability state, and active/prepared/decrypt-only key versions. It contains no runtime access/refresh/session tokens. A tenant failure can be represented explicitly while unaffected tenant contexts remain usable; the SDK must never interpret an incomplete response as permission to reuse revoked material.

The effective revision changes for relevant resource versions, links, assignments, grant policy and key lifecycle. Heartbeats, unrelated edits and audit reads do not force reinstallation. A `304` response is sent only after grant authorization/revocation checks; it cannot accidentally keep a revoked grant alive.

### Startup sequence

1. Read minimal bootstrap inputs. Validate local configuration; never fall back to old application/tenant ENV secrets.
2. Start the bootstrap state machine with readiness unavailable. Health/status may be exposed, but business requests cannot proceed. Liveness is not the same as readiness.
3. Register a fresh boot-instance identity and fetch a coherent authorized view. No durable local secret cache is used as a substitute for fresh startup authorization.
4. Validate application/tenant ownership, links, required capabilities, JSON schemas, formats, key lengths and version relationships. Decode the existing supported key formats without changing their bytes.
5. Construct application and tenant service clients from the validated view, then publish an immutable in-memory snapshot. Populate only explicitly mapped application-wide ENV compatibility entries.
6. Acknowledge required prepared key versions only after the actual cryptographic adapter can use them. A concurrent rotation must include/block the joining instance as appropriate.
7. Mark the application ready when its required application capabilities are available. Mark individual tenant/functions available independently. Missing required tenant login material blocks that tenant; missing an optional integration blocks its dependent functionality, not all tenants.
8. Start background checks at a default interval of 60 seconds. Different instances may add positive jitter; jitter must never shorten the minimum interval.

On transient startup connectivity failure, retry no faster than the configured minimum and report `Key Vault is not connected` with sanitized code/time/retry status. Do not exit solely for a transient Vault outage. Invalid bootstrap settings and explicit authorization denial must be reported distinctly from a network outage; denied access remains unready until an authorized operator fixes it. Manual “retry” cannot bypass the minimum fetch interval.

### Requests and snapshots

Requests receive one immutable snapshot/context from memory. They cannot trigger Vault refreshes. Tenant context selection follows trusted hostname/realm resolution and authenticated authorization; an arbitrary request parameter does not select another tenant's secrets.

The SDK exposes an application context and tenant-scoped accessors, including named integration configurations and versioned key rings. It does not provide a “merge all tenant ENV” helper. Private data is unavailable to browser bundles, React client components, URLs, logs and general metadata endpoints.

`process.env` is a compatibility output, not the authoritative live-secret store. Consumers must not independently reread ENV between asynchronous request steps and combine generations. Rotation-sensitive clients use the pinned registry snapshot. Replacing ENV values alone is insufficient for libraries that captured secrets during initialization: adapters must construct a new client and atomically replace the client pointer.

Next.js public configuration is passed through an explicit safe projection, such as a tenant's Clerk publishable key and approved public API origin. Do not expose an entire integration JSON or depend on build-time `NEXT_PUBLIC_*` replacement for hot tenant configuration.

### Background refresh and failure behavior

One scheduled secret-refresh operation at a time per process. Use conditional views and immutable version references. The minimum interval applies to secret fetching; management operations and key ACK/status messages are not extra secret fetches.

- **Unchanged:** leave ENV, snapshots, client pools and callbacks untouched.
- **Changed and valid:** stage the complete affected contexts/clients, validate, then swap the registry pointer. Drain superseded clients safely.
- **Network outage/timeout:** retain the existing loaded snapshot, mark connection health degraded and retry on the next scheduled interval. Never synchronously fetch on a business request's cache miss.
- **Explicit revocation/unassignment:** remove affected references, deny new dependent work and cancel/fence in-flight work where possible. A whole-grant revocation affects that deployment; a tenant/resource revocation is scoped. An external side effect already dispatched cannot be recalled.
- **Invalid candidate:** do not publish partial material. Retain unrelated working contexts; block the affected capability if the prior material has been explicitly revoked. A bad replacement must not resurrect revoked values.
- **Configured validity:** enforce explicit not-before/expiry locally. An outage alone does not age out secrets, but it does not override an explicitly configured expiry. Normal historical decryption-key retention is a separate lifecycle state.

Drop active references to revoked values and wipe owned mutable key buffers where feasible. Do not promise physical erasure of every string/library copy in a managed JavaScript process. Logs record IDs/revisions and fixed error categories, not values or raw provider errors.

## 8. Consumer-specific behavior

| Consumer | Bootstrap / local use |
| --- | --- |
| Club API | Load application/control-plane secrets and its assigned tenant contexts before business readiness. Use tenant memory for database credentials, integration static JSON and local crypto. Shared integration runtime state is read/written in tenant MongoDB. |
| Club APP | Initialize server authentication and BFF clients from application/tenant memory. Serve an explicit public configuration projection. Do not request database or integration secrets it has not been linked to. |
| Explorer API | Read-only bootstrap for ordinary service operation. Interactive tenant administration additionally uses its separately scoped provisioning credential plus verified human role/consent. Reconnect administration must not require successful Bexio role lookup. |
| Explorer APP | Server-side bootstrap and safe public projections. Secret-entry forms send values only to the authorized administration backend; provisioning credentials never reach the browser. |
| Vault APP | Load its own server-side authentication/configuration through read-only bootstrap from Vault API. Administrative UI requests use the separate human/provisioning authorization path. Vault API must be usable without Vault APP running. |

Each server worker process using secrets is an instance for key-rotation participation. A parent launcher loading secrets and spawning workers does not prove the workers loaded the key ring. Shared SDK code must handle framework instrumentation and development reloads without accumulating pollers or phantom instance registrations. Graceful shutdown unregisters the instance when possible; failure to report shutdown requires explicit retirement, never an automatic timeout.

## 9. Runtime credentials in tenant databases

These collections belong to the consuming tenant database, not the Vault database. Static clients/secrets and encryption keys are referenced by IDs/versions, not copied into these records.

| Collection | Content |
| --- | --- |
| `integration_runtime_credentials` | Unique `(tenantId, environment, integrationId)`; encrypted runtime token payload, expiry metadata, provider account binding, credential revision, source static configuration version and refresh state. |
| `integration_refresh_operations` | Durable operation/fencing identity, reservation owner/phase, dispatch/result/commit state and bounded sanitized diagnostics. Any persisted credential response is encrypted with the tenant key ring. |
| `integration_oauth_states` | One-use, expiring OAuth state/PKCE and reconnect state, tenant/account/integration binding and consumed status; encrypt sensitive fields. |

Runtime credential payloads include only the needed access/refresh/ID tokens and related runtime state. Incoming session JWTs need not be persisted at all; if persisted, they follow the same encrypted application/tenant storage rule. Public JWKS caching is not secret storage.

Use tenant-database accounts with the required scoped permissions. A Vault read grant does not grant MongoDB write permissions. All applications consuming a shared integration agree on the same integration ID, database and runtime-record schema; they must not create per-process or per-application copies.

### Coordinated refresh and recovery

1. Load valid runtime data from the tenant database or optional encrypted Redis cache. Use its expiry; do not contact Vault.
2. Acquire a MongoDB CAS reservation with a monotonically increasing fencing generation. Only the winner may refresh. Other callers use a still-valid token or wait for the recorded result within a bounded request budget.
3. Validate the current static client configuration from memory. If a runtime record requires a static version not yet loaded locally, wait for the scheduled background update or return a typed temporary-unavailable response; do not fetch Vault on the request path.
4. Persist the dispatch marker before the one external OAuth refresh. A lease timeout may recover a reservation only when CAS/fencing proves dispatch never began. A timeout after possible dispatch does not authorize another refresh-token use.
5. Persist the encrypted replacement/result with the operation ID before publishing its active pointer/revision. On uncertain database acknowledgement, reconcile by reading that operation ID, not by replaying the provider call.
6. Update/invalidate the optional Redis cache by committed revision. Redis is not the lock or source of truth; its failure falls back to MongoDB. The prior absolute expiry is not extended by cache reads.
7. If dispatch outcome is unknown and no committed replacement exists, surface `reauthorization-required`/`reconciliation-required` with an actionable admin status. Do not leave an unexplained generic request failure or automatically clear the durable safety state.

Fresh reconnect uses a new one-use authorization code, verifies the expected provider account and current static configuration, stores new runtime credentials only in the tenant database, and retains sanitized history of the unresolved operation. It must not depend on the expired provider token to authorize the administrator. No OAuth code, token response, refresh ledger or runtime credential is written to Vault.

Refresh, reconnect, revocation and static client/account changes share a single authoritative integration `authorityGeneration`. Every reservation captures that generation, the runtime credential revision and required static version. A reconnect/revocation/configuration transition advances it under CAS; an old worker cannot subsequently publish a result or reactivate the prior account/client. Commit/result publication compares all three observations. Stale operations keep a sanitized superseded/reconciliation status; they do not overwrite the new record. Runtime worker fencing is not limited to competing refresh calls.

## 10. Encryption-key distribution and activation

Model key material as immutable versions with `prepared`, `active-for-encryption`, `decrypt-only` and `revoked` lifecycle states. Retain a version until migration/retention evidence proves no permitted data needs it. Ciphertexts record the key version; applications keep authorized historical keys in memory for decryption.

Rotation sequence:

1. An authorized administrator creates a new version and a durable rotation job. Existing encryption remains active.
2. Publish the new version as **prepared**, together with the current/historical ring. Identify all affected non-retired instances and the participant membership revision.
3. Instances fetch on their normal background schedule, validate/install the ring and acknowledge actual key availability. Their ordinary requests continue using the old active encryption key during preparation.
4. Activation is a transaction that proves every currently required running/joining instance acknowledged. A joining instance cannot become ready with an insufficient ring. New registrations during the check invalidate/recompute the activation barrier.
5. For ordinary versioned data-encryption/wrapping keys, activate new writes only after this barrier. An instance that disconnects after ACK can still decrypt new data because it already holds the prepared key; it may temporarily continue writing the retained old version until it learns activation.
6. Perform any necessary application-side data migration. Retain old decryption versions until verification completes. Vault owns key/distribution metadata; it does not directly edit business ciphertexts in tenant databases.
7. Blind-index/control-key changes require their own coordinated application-side migration and, where necessary, tenant-scoped quiescence or dual-index support. Distribution ACKs alone do not make reindexing safe. Other tenants continue running.
8. Mark complete only with the required migration/verification evidence. Once new-version ciphertext exists, rollback cannot simply delete the new key.

Disconnected instances remain participants indefinitely. `lastSeen` is informational, not proof of termination. An authorized administrator must confirm a process is permanently stopped to retire it from a barrier. Preserve the confirmation actor/reason/time. A retired boot identity cannot ACK/rejoin; a genuinely new boot must register and load current material before readiness. This explicit trust in the administrator's stop confirmation is part of the model.

Membership edits cannot shrink an in-progress barrier as a side effect. Newly linked applications and their instances are added before becoming ready. Unlinking a key/application or revoking a grant removes its resource authorization but does not silently remove an unacknowledged original participant from the rotation. If that participant can no longer fetch the prepared key, rotation remains blocked until its permanently stopped state is explicitly confirmed; a timeout is not a substitute. The UI explains this dependency before revoking/editing membership during a pending rotation. All membership and activation CAS operations use the same durable barrier revision.

## 11. Vault APP and Tenant Explorer UX

### Applications

- A structured list shows display name, slug, description, environment, tenant count and bootstrap health. A **New application** button reveals creation fields.
- Details default collapsed, with an expand/collapse icon on the right. Application selection checkboxes appear to the left of names.
- Resource tables use human-readable purpose/name first; IDs are secondary. Columns include link checkbox, kind/type, name, ID, version policy, ENV/access name and dependent capability.
- Preserve 20-row pagination, name/ENV search and linked/unlinked filters. Save publishes link changes together; no second editable copy in a runtime configuration form.
- Tenant assignment adds an association, not all tenant secrets. Tenant-level resource/integration links are configured explicitly and consent-checked.

### Tenants

- Tenant details show static secrets, encryption keys, named integrations, assigned applications and global-admin access consent.
- Club admins see only their tenant. Global admins without consent see metadata and a locked value/edit state with an approval-required explanation.
- Club admins control a persistent **Allow global admins to view and edit this tenant's secrets** setting. Show approval/revocation history. Global admins cannot enable this setting themselves.
- Named integrations have schema-generated forms, masked private fields, version history, consuming applications and validation errors that do not echo secrets.

### Keys, grants and operational views

- Key pages show version/algorithm, prepared/active/decrypt-only status, rotation progress and missing instance ACKs. Explicit instance retirement requires a confirmation naming the instance and stating it is permanently stopped.
- Grant pages show application/environment, effective metadata scope and capabilities, status and issuance/rotation controls. Normal application grants are visibly read-only; no grant value is retrievable from the list.
- An **Application status** view shows ready/degraded/waiting, loaded revision, last successful check and pending rotations. It stores operational metadata, not runtime secrets or OAuth tokens.
- Vault has no runtime-token editor or OAuth token-renewal broker. Tenant Explorer can show integration runtime health through the owning tenant service and offer authorized reconnect, without storing those values/status records as Vault secrets.

Value reveal is a separate audited operation. Secret values never accompany ordinary list/search/status responses. The frontend must not render hidden raw payloads and merely mask them with CSS.

## 12. Migration and coordinated cutover

### Inventory and preview

Build a read-only inventory of namespaces, applications, assignments, links, grants, key versions, integration bundles and consumer references. Identify static versus runtime fields using reviewed provider schemas. Do not use guessed regexes to silently discard unknown fields; unresolved classifications block that item.

For each mixed integration bundle, identify its stable tenant integration ID/name, static client fields, runtime token versions, current credential pointer, unresolved refresh operations and expected provider account. Existing expired/uncertain Bexio state is migrated as such; copying it is not a successful reconnect.

Generate a reviewable plan with source revisions/digests, target IDs, application alias mapping and counts. Values never appear in the preview. Inventory `.env`, `.env.local` and legacy `.old`/JSON credential backups; distinguish bootstrap values, static secret values, public settings and runtime tokens.

### Staging and validation

- Stage normalized Vault metadata and encrypted static versions in the new collections.
- Stage encrypted runtime-token/history records in the correct tenant databases. Historical token-bearing Vault versions must not remain readable as historical Vault secrets after cutover; retain required recovery history encrypted in the tenant database/approved migration archive instead.
- Preserve supported key bytes and historical versions exactly. Validate static JSON against the selected schema, source/target logical equivalence, ownership, links and all cross-references.
- Prepare all five consumers on the new SDK/tenant runtime record contract. They must not fall back to legacy ENV credentials or the old Vault OAuth broker.
- Prepare the minimal bootstrap grants and provisioning authorization through the approved consent/issuance process. Inventory pre-existing machine credentials and prevent duplicate live grants from becoming a consent bypass.

### Maintenance window

1. Drain affected writers/refresh operations. Unresolved provider dispatches remain explicitly reconciliation-required; do not clear them to make a preview green.
2. Acquire durable migration gates and verify the reviewed source revisions/digests. Listener/process checks are supplemental, not the authoritative distributed writer fence.
3. Commit staged targets and change the authoritative schema marker/pointers. Cross-database steps use an explicit resumable migration ledger with readback verification; do not pretend they form one transaction across unrelated databases.
4. Fence legacy writers and disable the old token-bearing Vault/OAuth paths before allowing new traffic.
5. Bootstrap consumers, verify readiness/tenant isolation and exercise actual authorized requests. Check that business traffic generates no Vault secret reads/writes.
6. Remove migrated runtime values from active Vault records and token-bearing secret-version history only after tenant storage verification. Keep audit metadata. External database backups follow the explicitly reviewed retention policy; do not claim that updating live records instantly erases old backups.
7. Replace active application ENV files with bootstrap-only configuration. Report and explicitly handle legacy plaintext backup files; destructive cleanup requires a concrete reviewed inventory and authorization at execution time.

### Rollback

Before new-format writes, rollback can restore the reviewed old state under maintenance from its encrypted migration archive. After runtime refresh or new-version encryption writes, blind rollback is forbidden: reconcile/copy current authoritative runtime data and retain every key needed by new ciphertext. Source identities/revisions, including runtime authority revisions changed by key rotation, must still match the proposed rollback.

Partial staging is not activation. Resume by migration job/phase and digests, never by replaying OAuth refreshes or blindly rerunning external writes. Maintenance interruption must leave a clearly gated, recoverable state.

## 13. Verification and acceptance criteria

### Security and isolation

- Cross-application, cross-tenant and cross-environment grant tests, including submitting another application ID with a valid grant.
- Create multiple grants/resources/versions and prove each is independently stored and addressed. Updating one grant must not replace an aggregate grant registry. Metadata list/search/version operations must succeed without invoking payload decryption and must not return value fields.
- Human metadata-only access without consent; value reads and edits require consent. Revocation races a pending reveal/save and prevents publication/commit.
- Test indirect value exposure through grant issuance/rotation, link changes, owner changes, self-appointment as club admin and exports.
- Browser bundles, HTML, logs, audit records and error responses contain no private payloads or provisioning grants.
- Payload/DEK tampering and substitution across owners/versions fail authentication; tenant runtime records never contain copied static client secrets or raw encryption keys.
- Custom schema validation rejects forbidden runtime fields, unsafe/remote references and resource-exhaustion cases; schema versions are immutable and migrations explicit.

### Bootstrap and performance

- All five consumers remain unready on fresh Vault outage and display/log the required message; business requests cannot initialize with missing secrets.
- Instrument actual Vault endpoints: zero business-request secret reads, writes or crypto calls after bootstrap. A runtime-token refresh uses the provider and tenant database, not Vault.
- Minimum 60-second background fetch spacing, one in-flight operation, bounded retries, no request-triggered refresh, and no snapshot/client/ENV changes on an unchanged view.
- Successful bootstrap followed by outage continues from memory; explicit scoped revocation disables only affected work on the next successful check.
- Test two tenants using identical secret names with different values. Test a partial tenant failure while others remain available.
- Measure startup separately from warm request latency. Record fetch count, payload bytes, memory footprint and refresh application latency under representative tenant counts. Do not substitute an in-memory fixture time for live endpoint timing.

### Runtime token coordination

- Concurrent consumers produce one provider refresh, not one per application; fencing rejects stale reservation owners.
- Crash before dispatch can recover only with proof of no dispatch. Ambiguous dispatch does not automatically retry a refresh token.
- Lost MongoDB commit acknowledgements reconcile by operation ID; Redis outage does not create extra refresh winners or extend token expiry.
- Reconnect works using tenant-admin identity even when Bexio is expired/suspended, verifies the expected account and never writes OAuth token material into Vault.

### Keys and migration

- Disconnected instances block key activation without timeout. A newly joining instance participates in the readiness/activation barrier.
- Reject forged/stale ACKs and rejoining retired boot identities. Test disconnect after ACK, retaining old/new decryption ability.
- Explicit retirement and key migration evidence are audited. Old data decrypts after activation and restart; index-key migration is tested separately.
- Migration preview performs no writes, exact classification/equivalence is verified, source changes abort cutover, old writers are fenced and interrupted jobs resume safely.
- After cutover, live Vault collections and exposed version history contain no migrated runtime token payloads. No consumer still references the old OAuth broker.

## 14. Proposals and builder discretion

The proposed collection/endpoint names, envelope layout, SDK API shape, required-capability declarations, public configuration projections, default 60-second-plus-positive-jitter schedule and the detailed anti-bypass/credential-delivery workflow require design review. They are not claims that the user chose those exact implementations.

### Builder check and remaining approval question

The independent builder review identified shared authority-generation fencing and rotation-membership races; the explicit rules above settle them within the user's agreed behavior. One security decision remains for the user: bearer-password custody at cutover and future enrollment. Proposed policy is to replace existing application grants at migration, deliver the replacements only through the trusted deployment provisioning path, never reveal them through global-admin UI, and require tenant club-admin approval for initial machine enrollment or credential delivery changes that expose that tenant. Existing credentials of uncertain custody would not be grandfathered. This closes the role-only UI bypass within the stated infrastructure-operator trust boundary; it does not make a stolen bearer password safe. Record the user's answer before treating this policy as approved.

The builder may choose the bounded schema-validation library, index naming, internal module organization and framework-specific initialization hooks, provided the agreed behavior and acceptance criteria hold. Do not change the ownership/consent boundary, introduce request-time Vault reads, add automatic rotation-barrier timeouts, or keep runtime tokens in Vault as an implementation shortcut.

After approval of this design, create a separate implementation plan covering Vault persistence/API, Vault APP/Explorer administration, shared SDK, each consumer adapter, migration tooling and verification. No service start, live migration, secret replacement, token refresh or deployment is part of writing this design.
