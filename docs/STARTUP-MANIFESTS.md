# Simple vault-backed startup

Consumers now need `SECRETS_KEYS_STRATEGY=LOCAL_KEYVAULT`,
`NODE_ENV=development`, and their private `LOCAL_KEYVAULT_AUTH_JSON`.
`LOCAL_KEYVAULT_URL` defaults to `http://127.0.0.1:4000` and
`LOCAL_KEYVAULT_ENVIRONMENT` defaults to `development`. Each consumer already knows
its application name: `club-api`, `app`, `explorer-api`, or `explorer`.
No consumer-side `LOCAL_KEYVAULT_BINDINGS_JSON` is required.

An operator provisions existing secret bytes separately, creates scoped read
grants, and publishes one reviewed metadata plan with:

```sh
./publish-key-vault-bindings.sh --plan examples/explorer-api-bindings-plan.json
```

The plan is an administrative input in the vault repository, not an application
environment variable. It still must use actual provisioned purposes, current
control revisions, and explicit historical version labels where applicable. The
publisher never imports or generates secrets. See BINDINGS.md for those choices.

Startup reads the named application's current process manifest from `_shared`
using its read grant. It validates the descriptor/digest and then reads the pinned
secret snapshot. Process-only frontend servers need only their `_shared` grant;
merely listing a tenant in metadata does not fetch that tenant's manifest/values.
Backend tenant access additionally reads the exact tenant manifest revision from
that tenant's namespace and checks its digest against the cached parent manifest.
The club API discovers and seals its complete configured tenant set before ready.
All tenant namespaces must have the corresponding read grants.

Manifests are metadata only, strict-size bounded, and immutable within a revision.
The publisher writes tenant history first, then the complete shared application
batch atomically. Old process manifests continue to reference retained exact
tenant history if a publication fails partway. There is no cross-namespace atomic
commit; concurrent publishers may leave additional unreferenced tenant history.
Every changed manifest needs a new revision; tenant revisions must agree with the
authoritative control configuration. Metadata alone does not prove secret-value
formats, key-role independence or actual current tenant revision. Consumers keep
their existing validation and deny mismatches.

Discovery and secret values are cached until process restart. There is no runtime
write, key generation, hot refresh, secret migration or environment fallback.
Explicit legacy `LOCAL_KEYVAULT_BINDINGS_JSON` remains supported as an intentional
operator choice; remove it to use discovery. A malformed explicit legacy value
or a missing/denied manifest fails closed rather than switching sources.
Application names are manifest selectors, not an additional authorization boundary:
grant permissions still apply to the complete namespace.

Cloud/serverless use stays blocked pending APP-47. No live manifest publication,
secret provisioning, service restart or deployment is performed by implementation
tests. Pure fixture checks cover client/HTTP/store integration and bad scopes,
versions, digests, permissions, partial publication and secret-free audit output.
