#!/bin/sh
case "${1-}" in
  --help|-h)
    printf '%s\n' 'Usage: ./create-grants.sh [environment tenant [permissions]]
       ./create-grants.sh --help|-h

Create a caller grant in MongoDB and print its metadata and bearer token.
The token is shown only once; save it securely and supply it to the caller.

Arguments:
  environment   Exact environment identifier (default: dev).
  tenant        Exact tenant identifier (default: tenant-123).
  permissions   Comma-separated read,write,crypto,list (default: all four).
  Supply environment and tenant together, or omit both for defaults.

Examples:
  ./create-grants.sh
  ./create-grants.sh dev tenant-123 read,write,crypto,list
  ./create-grants.sh dev tenant-123 list

Reads project-root .env; exported variables take precedence.
Requires Node.js 24, installed npm dependencies, VAULT_MONGODB_URI with
an explicit database, VAULT_MASTER_KEY, and reachable MongoDB.
New grants apply immediately; no API restart is needed.'
    exit 0
    ;;
esac
# Creates a persisted grant; the bearer token is printed only once.
exec "$(dirname -- "$0")/grants.sh" create "$@"
