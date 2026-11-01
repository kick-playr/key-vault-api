#!/bin/sh
case "${1-}" in
  --help|-h)
    printf '%s\n' 'Usage: ./grants.sh <command> [arguments]
       ./grants.sh --help|-h

Manage caller grants in the encrypted MongoDB registry.

Commands:
  create [environment tenant [permissions]]
      Create a grant; defaults: dev, tenant-123, read,write,crypto,list.
      Supply environment and tenant together, or omit both.
      Prints metadata and a fresh bearer token once; save it securely.
  list
      List metadata for active/revoked grants; never reveals tokens or hashes.
  permissions <grant-id> <permissions>
      Replace permissions with a comma-separated selection of
      read,write,crypto,list. Does not reactivate revoked grants.
  revoke <grant-id>
      Disable a grant immediately; subsequent requests reject its token.
  rotate <grant-id>
      Atomically disable an active grant and create a replacement ID/token,
      retaining its scope and permissions. Prints the replacement token once.
  import
      Import legacy VAULT_GRANTS from .env or exported variables.
      Existing grants, including revoked grants, are skipped.

Examples:
  ./grants.sh create dev tenant-123 read,list
  ./grants.sh list
  ./grants.sh permissions <grant-id> read,list
  ./grants.sh revoke <grant-id>
  ./grants.sh rotate <grant-id>
  ./grants.sh import

Use IDs returned by create/list; replace <grant-id> with the actual ID.
Reads project-root .env; exported variables take precedence.
Requires Node.js 24, installed npm dependencies, reachable MongoDB,
VAULT_MONGODB_URI with an explicit database and VAULT_MASTER_KEY.
Commands compile current sources before running. Grant changes apply to
subsequent requests without an API restart. Help needs no Node.js or MongoDB.'
    exit 0
    ;;
esac
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
npm run build --silent >&2
exec node dist/grants-cli.js "$@"
