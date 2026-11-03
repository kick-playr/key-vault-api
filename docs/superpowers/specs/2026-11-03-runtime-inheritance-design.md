# Runtime configuration inherits canonical definitions

Approved by the user after the design explanation: runtime combines existing apps and tenants; no duplicate secret, version, ENV, name or description editors.

Applications own shared resource links, policies and ENV mappings. Tenant namespaces own their existing secret/key definitions. Runtime stores only environment/application IDs and app-to-tenant assignments, and publishes immutable resolved snapshots using existing authorization, concurrency and migration guards. Generated snapshots are internal history, never another editable definition.

Approach: resolve canonical application links and tenant definitions on every preview/publication. Keep old rich configuration import compatible only as an assignment import; do not let imported copies overwrite canonical definitions. Missing/deleted applications fail explicitly. Existing legacy rich stored documents are interpreted as assignments, with catalog names and links authoritative. No new permissions, identities, activation or restarts. UI displays inherited bindings read-only and sends schemaVersion2 references only. Preview changes require explicit publication; no unsafe automatic crypto migration.
