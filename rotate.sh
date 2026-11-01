#!/bin/sh
case "${1-}" in
  --help|-h)
    printf '%s\n' 'Usage: ./rotate.sh <grant-id>
       ./rotate.sh --help|-h

Atomically disable an active grant and create a replacement with a new ID
and bearer token, preserving its environment, tenant and current permissions.
The old token stops working at commit. Save the new token printed once and
update callers; there is no overlap period and no API restart is needed.

Examples:
  ./grants.sh list
  ./rotate.sh <grant-id>

Use the ID from grants.sh list. Revoked grants cannot be rotated.
Reads project-root .env; exported variables take precedence.
Requires Node.js 24, installed npm dependencies, reachable MongoDB,
VAULT_MONGODB_URI with an explicit database and VAULT_MASTER_KEY.'
    exit 0
    ;;
esac
# Atomically replace an active grant's bearer token. Usage: ./rotate.sh <grant-id>
exec "$(dirname -- "$0")/grants.sh" rotate "$@"
