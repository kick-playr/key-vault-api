#!/bin/sh
case "${1-}" in
  --help|-h)
    printf '%s\n' 'Usage: ./migrate-grants.sh [--help|-h]

Import legacy VAULT_GRANTS JSON from project-root .env or exported variables
into the encrypted MongoDB grant registry, preserving tokens and permissions.
Prints imported/skipped counts without revealing tokens.

Example:
  ./migrate-grants.sh

The complete array is validated before one atomic update. Duplicate incoming
entries for one token/namespace have their permissions combined. Existing
grants, including revoked grants, are skipped on repeated imports.
After success, save caller tokens securely before removing VAULT_GRANTS from
.env. The script does not remove it automatically. Restart an older API once
to load database-backed authorization; later grant changes need no restart.

Requires Node.js 24, installed npm dependencies, reachable MongoDB,
VAULT_MONGODB_URI with an explicit database and VAULT_MASTER_KEY.
Exported variables take precedence over project-root .env.'
    exit 0
    ;;
esac
# Imports legacy VAULT_GRANTS atomically without restoring existing/revoked grants.
exec "$(dirname -- "$0")/grants.sh" import "$@"
