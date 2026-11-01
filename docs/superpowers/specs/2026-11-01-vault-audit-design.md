# Vault request audit

User-selected design: write and crypto request outcomes go to a separate MongoDB
collection, read and list outcomes to console. The alternative of routing all
operations into MongoDB was rejected by the user. Existing bounded namespace
mutation history remains internal and unchanged.

`VAULT_AUDIT_DESTINATIONS` is a JSON object overriding those defaults per category:
`read`, `list`, `write`, `crypto`. Values: `console`, `collection`, `both`, `off`.
Unknown keys/values and malformed JSON fail bootstrap. Configuration applies after
restart; no live configuration or service restart is performed by this change.

One metadata-only event per recognized HTTP operation includes a server-generated
request ID, time, elapsed milliseconds, action/category, validated resource name
and requested version, validated namespace, authenticated grant IDs, HTTP status
and success/denied/failure/aborted outcome. Namespace aliases, case variants,
runtime snapshots, provisioning and failed authorization are covered. Version
enumeration counts as list even though its existing permission is read.
Never copy raw URLs/query strings, credentials, bodies, values, keys, ciphertext,
plaintext, tags or arbitrary error messages into either sink. Unauthenticated
requests have no authenticated grant ID. Documentation/unknown routes are excluded.

Audit delivery is best effort after response completion. Collection inserts are
separate from namespace reads/CAS mutations and never change their generation.
Pending inserts drain before the store closes. Sink failure emits a sanitized
console delivery-failure event and never retries a vault mutation or exposes an
error payload. This is application audit visibility, not atomic transactional or
tamper-proof evidence. Metadata is queryable in `vault_audit`; no automatic expiry
or deletion endpoint. Database access and retention remain operator-controlled.

Scope: vault API HTTP operations only, not CLI provisioning/grant administration,
browser audit UI, service activation, package bump or publication.
