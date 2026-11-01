#!/bin/sh
case "${1-}" in
  --help|-h)
    printf '%s\n' 'Usage: ./import-fcrww-keys.sh [environment tenant]

Prompts for a key-set name, for example workflow-local:fcrww:key, then
three existing FCRWW symmetric keys with hidden input:
  wrapping/v1 -> WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1
  index       -> WORKFLOW_REAL_FCRWW_INDEX_KEY
  control     -> WORKFLOW_REAL_FCRWW_CONTROL_KEY

Naming: <profile>:<selected-tenant>:key. Profile is lowercase kebab-case,
at most 48 characters; tenant must exactly match the selected grant scope.
Each set has a logical tree: wrapping/v1, index, control. These mappings
are explicit; WORKFLOW_REAL_ is not inferred from the profile name.
Azure-compatible physical secret names are deterministic tk-<role>-<hash>.
GET /local/key-tree exposes the metadata-only hierarchy with list permission.

Defaults: environment development, tenant fcrww. Supply both or neither.
Prompts for the grant bearer token too, unless VAULT_TOKEN is exported.
The grant must have read and write for the selected environment/tenant.

Example:
  ./import-fcrww-keys.sh development fcrww

Requires an interactive terminal. Pasted keys and token are not echoed.
Enter only each value, without quotes or variable assignments, then Enter.
Before import, displays only the last 3 characters of each key (including
Base64 padding) and the chosen key-set name/namespace. Type yes to confirm; any other
answer, Ctrl+C or EOF cancels without writing keys. No FCRWW .env file is read.
Keys must be distinct canonical Base64-encoded 32-byte values. Original
strings are preserved; no keys are generated or rotated.

All three writes commit atomically; identical existing active values are
skipped. Conflicting/inactive/deleted targets cause the whole import to fail.
Confirmation displays only key suffixes; final output contains scope/names/
counts. Full key values and bearer tokens are never printed.

Connects directly to MongoDB using VAULT_MONGODB_URI and VAULT_MASTER_KEY
from the vault project .env (exported variables take precedence). Requires
Node.js 24, installed dependencies and MongoDB; the API can be stopped.
Compiles current sources first. Help requires no credentials or connection.

This imports storage only. Keep your original keys until Kick-Playr is
updated and verified to load these secrets instead of env: references.'
    exit 0
    ;;
esac
set -eu
if [ "$#" -ne 0 ] && [ "$#" -ne 2 ]; then
  printf '%s\n' 'Usage: ./import-fcrww-keys.sh [environment tenant]' >&2
  exit 1
fi
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
npm run build --silent >&2
exec node dist/import-fcrww-keys.js "$@"
