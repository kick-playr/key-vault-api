#!/bin/sh
case "${1-}" in
  --help|-h)
    cat <<'HELP'
Usage: ./create-key-vault-grants.sh [--clubs "fcrww,fcuster"] [--shared] [--environment development|dev|test]

Create NEW read-only grants for one consumer and print exactly one shell export:
  export LOCAL_KEYVAULT_AUTH_JSON='<complete generated JSON>'

Options:
  --clubs         Comma-separated club IDs; whitespace is trimmed, duplicates removed.
                  Up to 32 distinct clubs. Use --shared for the _shared namespace.
  --shared        Include the _shared process-secret namespace.
  --environment   Exact namespace environment; defaults to development.
  --help, -h      Show help without compiling or connecting to MongoDB.

Examples:
  ./create-key-vault-grants.sh --clubs "fcrww,fcuster" --shared
  ./create-key-vault-grants.sh --shared
  ./create-key-vault-grants.sh --clubs "fcrww" --environment dev

Reads the vault project .env; exported variables take precedence. Requires
VAULT_MONGODB_URI, VAULT_MASTER_KEY, Node.js 24 and installed dependencies.
Creates all requested grants atomically in one MongoDB registry update.
Every invocation issues new tokens; existing grants remain valid until revoked.
Run separately for each consuming service. Tokens are printed only once.
Does not change .env, create secrets/bindings, start services or set variables
in your parent shell. Source the printed export to set it in your shell.
Compilation and errors go to stderr; stdout contains only the credential export.
HELP
    exit 0
    ;;
esac
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
npm run build --silent >&2
exec node dist/create-key-vault-grants-cli.js "$@"
