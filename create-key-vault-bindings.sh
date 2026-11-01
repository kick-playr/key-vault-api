#!/bin/sh
case "${1-}" in
  --help|-h)
    cat <<'HELP'
Usage: ./create-key-vault-bindings.sh --plan <metadata-plan.json>

Print one export LOCAL_KEYVAULT_BINDINGS_JSON='...' from existing vault metadata.
See examples/explorer-api-bindings-plan.json and docs/BINDINGS.md.

The plan chooses applications, secret purposes/mappings, exact tenant revisions
and application wrapping-key labels. A resource with just one version can be
pinned automatically. Multiple versions require explicit pins; historical
wrapping-key labels cannot be inferred. No secret material is read by the
generator callback or printed. All digests use the shared runtime client.

Examples:
  ./create-key-vault-bindings.sh --plan examples/explorer-api-bindings-plan.json
  ./create-key-vault-bindings.sh --help

Requires the vault project's bootstrap .env, Node.js 24, installed dependencies
and an existing initialized vault database. Compilation/errors go to stderr;
stdout contains only the generated export, after all reads succeed. Does not
create or rotate secrets, create grants, edit .env or start a service. The plan
is metadata only: do not put credentials, values or tokens into it. Paths to
plans are resolved from your current directory. Help needs no Node.js or MongoDB.
HELP
    exit 0
    ;;
esac
set -eu
bindings_script_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
npm --prefix "$bindings_script_root" run build --silent >&2
exec node "$bindings_script_root/dist/create-key-vault-bindings-cli.js" "$@"
