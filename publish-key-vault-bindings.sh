#!/bin/sh
case "${1-}" in
  --help|-h)
    cat <<'HELP'
Usage: ./publish-key-vault-bindings.sh --plan <metadata-plan.json>

Resolve existing resource metadata and publish immutable runtime manifests.
Requires Node.js 24, installed dependencies and the vault bootstrap .env.
Publishes tenant manifests first, then all process applications atomically.
Does not create grants, secrets, keys or runtime snapshots. Never prints tokens
or secret material. Consumers only need their LOCAL_KEYVAULT connection config.
Plans require explicit application and tenant bindingRevision values. Increase
an application's revision when changing tenant references. See docs/BINDINGS.md.
HELP
    exit 0 ;;
esac
set -eu
publish_script_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
npm --prefix "$publish_script_root" run build --silent >&2
exec node "$publish_script_root/dist/publish-key-vault-bindings-cli.js" "$@"
