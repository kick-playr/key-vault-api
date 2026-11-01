# Generate LOCAL_KEYVAULT_BINDINGS_JSON

```sh
./create-key-vault-bindings.sh --plan examples/explorer-api-bindings-plan.json
```

First copy/edit the illustrative plan: its purposes, tenant selection and revision
are examples, not a discovered configuration. The command prints exactly one
shell-ready `export LOCAL_KEYVAULT_BINDINGS_JSON='...'` after all reads succeed.
Copy/source that export in the consumer's server configuration. It never edits
`.env`. It uses the vault project's bootstrap `.env` to inspect the existing
encrypted database; neither the running vault API nor new grants are needed.
This is an operator tool with bootstrap database/master-key access, not a runtime
consumer API. Encrypted namespace documents are opened in memory; only metadata
fields are consulted by the generator and returned. No secret values, private
keys, plaintext/ciphertext payloads or grant tokens are exported or printed.

## What the plan means

* `environment`: exact namespace, `development`, `dev` or `test`.
* `applications`: process entries keyed by the actual consumer name, e.g.
  `explorer-api`, `club-api`, `explorer`, `app`. Each uses `_shared` implicitly.
* Application `secrets`: explicit `mapping` and the existing manifest `purpose`.
  Purposes resolve the existing deterministic `kv-...` name, not arbitrary secret
  names. Look up the actual purpose/version in vault inventory metadata; sample
  purpose names are not automatically created. Include every mapping required by
  the consumer and its enabled capabilities. The example covers the five mandatory
  Explorer API mappings; configured invitation secrets require additional entries.
* `tenants`: exact required tenant IDs; `_shared` does not belong in this array.
* Each entry's `bindingRevision` is a required positive integer. Tenant revisions
  must match the authoritative control database's current configuration revision.
  The vault does not know or verify that separate database revision. Do not reset
  it to 1 or assume the example's 2 is right for every club. A process entry's
  revision identifies that process binding generation.
* `keySets`: exact existing `<profile>:<tenant>:key` reference and explicit
  `currentWrappingVersion`, the application's generation label (e.g. `v1` or
  `rotation-2026`). This is not the vault's 32-character immutable version ID.
  Role mappings are derived from validated `envName` metadata; optional explicit
  `mappings` must agree with every selected historical/current version.

With exactly one stored version of a resource, the script can pin it
automatically if active. If it has multiple versions, it stops with
`AmbiguousVersion`; it never silently chooses newest or skips an inactive version.
For ordinary secrets, add `"version":"<actual-32-character-vault-version>"`.
For rotated key sets, supply explicit metadata like:

```json
{
  "reference": "workflow-local:fcrww:key",
  "currentWrappingVersion": "rotation-2026",
  "wrappingVersions": [
    { "keyVersion": "v1", "vaultVersion": "<actual-old-vault-version>" },
    { "keyVersion": "rotation-2026", "vaultVersion": "<actual-current-vault-version>" }
  ],
  "indexVersion": "<actual-index-vault-version>",
  "controlVersion": "<actual-control-vault-version>"
}
```

Replace every version placeholder with its actual immutable ID. Include every
historical application version still needed for old ciphertext; do not relabel
old bytes or regenerate keys. The script cannot infer application labels from
opaque vault version IDs. Disabled/expired/not-yet-active pins fail completely.

## Validation and limits

The script validates the entire plan structure before opening MongoDB and reads
each namespace once. It verifies deterministic resource names, matching role tags,
active versions and mapping agreement, then computes canonical binding digests
with the same runtime client and re-parses every completed snapshot request.
It never reconciles, initializes, creates, imports, rotates or deletes resources.
A missing master-key verifier is an error rather than a reason to initialize one.
Missing resources must be provisioned separately using existing reviewed values.

Output is references/metadata, with no `latest` pins. It does not check secret
value formats or key-role independence by reading values, authenticate consumer
grants, validate application-specific required mappings, or validate control-plane
revisions. Consumers perform those checks on startup. Cross-namespace reads are
not atomic; later disable/rotation still requires consumer validation and restart.
No partial export is emitted on failure. Existing process/grant configuration is
left unchanged. Limits match the runtime contract: 16 applications, 32 tenants and
100 resolved values per request. Unknown/value-bearing fields are rejected.
Both the input file and generated bindings must fit within 1 MiB; the latter
matches the runtime client's configuration parser limit.

`--help` needs no Node.js or database. Run `npm run test:bindings` for pure metadata
and fake-driver contracts without starting MongoDB. These tests do not claim a
live vault/control-database integration pass.

## Publish manifests once for simpler startup

Run the operator command after provisioning the required entries and creating the metadata plan:

```sh
./publish-key-vault-bindings.sh --plan examples/explorer-api-bindings-plan.json
```

This resolves immutable version pins from existing metadata, validates every derived manifest before writing, and saves manifests inside encrypted vault namespaces. Tenant manifests are published first. All application manifests in the process `_shared` namespace are then published in one atomic operation. Publication creates no keys, secrets, grants or runtime values; stdout contains only a count summary. No secret values are read by metadata callbacks.

Each consumer keeps its existing `LOCAL_KEYVAULT` connection configuration and reads its current application manifest from `GET /local/runtime-manifests/:application`. The process manifest pins tenant manifest revisions and digests; tenant reads use `GET /local/runtime-manifests/:application/:revision`. Consumers no longer need a generated `LOCAL_KEYVAULT_BINDINGS_JSON` variable.

Keep explicit `bindingRevision` values in the plan. Increase the affected tenant revision when its bindings change and increase each application revision when its process bindings or tenant references change. Repeating identical published revisions is safe. Reusing a revision for different metadata or publishing an unknown older revision returns a conflict. History is retained: a partial publication cannot break a previously published process manifest. A failed publication may leave new tenant history; retry after resolving the conflict. Cross-namespace publication is deliberately ordered, while each namespace change is atomic.

HTTP publication uses `PUT /local/runtime-manifests/:application` with write permission; reads require read permission. Bodies are limited to 64 KiB and contain only validated manifest metadata. Namespace headers and application path must match the body. These `/local/` routes require no Azure `api-version` query.
