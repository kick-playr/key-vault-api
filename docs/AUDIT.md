# API audit events

By default, write and crypto HTTP operations append metadata events to
`vault_audit` in the vault's configured MongoDB database. Reads and lists print
one JSON event per request to the server console only. The previous encrypted
namespace mutation history remains unchanged and is not this request audit log.

Configure routing before startup (shell or `.env`):

```sh
VAULT_AUDIT_DESTINATIONS='{"write":"collection","crypto":"collection","read":"console","list":"console"}'
```

Each category supports `collection`, `console`, `both` or `off`. Partial overrides
inherit defaults, e.g. `{"crypto":"both"}`. Unknown keys, unsupported values,
empty values, malformed JSON, arrays and null fail startup. Changes require
restart. This setting configures logging only and never grants permissions.

Events include `schemaVersion`, `event`, `requestId`, UTC `time`, `durationMs`,
`category`, `action`, validated resource `name` and requested `version` when
applicable, validated requested `environment`/`tenant`, authenticated `grantIds`,
HTTP `status` and `outcome` (`success`, `denied`, `failure`, `aborted`). Before
authentication, grant IDs are empty; requested scope is not proof of access.
The server generates the `X-Vault-Request-Id` response header. Latest-version
reads omit version rather than claiming a concrete resolved version. Snapshot
events identify the snapshot operation and namespace, not its secret payload.

Both route forms and case/trailing-slash aliases are covered. Automatic HEAD
handling uses the same audit policy as the equivalent GET. Version enumeration
and tree/inventory routes are list operations. POST snapshot/runtime-snapshot
are read operations; reconcile is write. Errors and denied known operations use
the same destination policy. Documentation and unknown routes are excluded.
Authentication/session checks count as reads. Grant CLI commands and other
direct service/CLI use are outside the HTTP audit boundary.

No secret values, authorization headers, tokens/hashes, master/private keys,
request/response bodies, plaintext, ciphertext, tags, query strings or arbitrary
error messages are recorded. Resource and namespace identifiers are metadata;
protect access to logs and to the audit collection accordingly. The collection
is queryable metadata, not an encrypted namespace document. Its `_id` equals
the generated request ID. No audit endpoint, TTL or deletion job is added.

Delivery runs after response completion and does not change API results. A
failed insert emits a safe `vault.audit.delivery-failed` console event containing
request ID/category/destination, without the database error text. There is no
retry of the vault operation and no fallback that silently persists read/list
events. Pending inserts drain on graceful shutdown before the Mongo store closes.
An aborted event describes a closed HTTP connection, not rollback of any operation
already in progress.
Abrupt process termination or storage failure can lose events: this is best-effort
application auditing, not atomic, tamper-proof or compliance-grade evidence.

No service was restarted and no existing `.env` or running vault was modified
when implementing this feature.

Run `npm run test:audit` for the audit HTTP/in-memory, configuration, runtime-client
and snapshot contract suites without launching MongoDB. It verifies a Mongo
driver insert contract with an isolated fake; it does not claim a live MongoDB
integration pass. `npm run typecheck` and `npm run build` check the full source.
