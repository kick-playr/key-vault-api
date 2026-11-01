# Metadata inventory and Azure list endpoints

Implement the approved proposal: Azure-compatible GET /keys and /secrets (2025-07-01), and local GET /local/inventory. All routes include namespace aliases and require a new explicit list permission; it grants neither secret reads nor crypto/write access. Existing read/write/crypto grants retain their permissions, and operators must explicitly add list where wanted.

List latest non-deleted object metadata, including disabled/expired objects, without reading values into responses or exposing private/public key material. Azure list IDs are versionless. Local inventory adds name/kind/latest version/version ID/purpose, plus kind, exact name, prefix, purpose, tagName/tagValue, enabled and expiresBefore (Unix seconds) filters. Apply filters only inside the authorized namespace.

Both APIs paginate with maxresults 1–25, default 25, and nextLink/$skiptoken. Cursors are HMAC-signed using a domain-separated key derived from the bootstrap master key, expire after 15 minutes, and bind namespace, endpoint, normalized filters, page size, namespace generation and last ordered item. Reject tampering/reuse for other scopes or filters; reject continuation after a mutation with 409 so pages cannot silently mix snapshots. Do not maintain a plaintext MongoDB search index.

New manifest-provisioned keys/secrets receive a purpose tag; reconciliation-created secret versions retain it. Existing versions are not rotated or silently migrated. Existing objects can be tagged through metadata PATCH.

Write HTTP regressions first for least privilege, metadata omission, aliases, Azure shape/page limit, cursor security/staleness, combined filters and purpose discovery. Then implement, update Swagger/README/grant generator, run build/typecheck/full suite and independent review. No live grants, data or credentials are changed by implementation.
