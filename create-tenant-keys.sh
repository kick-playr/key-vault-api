#!/bin/sh
case "${1-}" in
  --help|-h)
    printf '%s\n' 'Usage: ./create-tenant-keys.sh [options]

Create a new named tenant key set from a selected .env file or hidden input.
Missing metadata and tenant are always prompted; key/token input is hidden. Env-variable names are automatic:
  WORKFLOW_REAL_<TENANT>_WRAPPING_KEY_V1
  WORKFLOW_REAL_<TENANT>_INDEX_KEY
  WORKFLOW_REAL_<TENANT>_CONTROL_KEY
Tenant is uppercased and hyphens become underscores.

Options (both --option value and --option=value work for value options):
  --environment <name>   Namespace environment (prompt default development).
  --tenant <id>          Namespace tenant, e.g. fcrww.
  --name <reference>     <profile>:<tenant>:key, e.g. workflow-local:fcrww:key.
  --token <token>        Grant bearer token; otherwise VAULT_TOKEN or hidden prompt.
  --env-file <path>     Read the three named keys from this selected dotenv.
                        Missing/blank entries are prompted with hidden input.
                        Without this option all three keys are prompted.
  --generate            Generate three fresh random 256-bit keys instead.
                        Cannot be combined with --env-file.
  --yes                 Approve writing without the final yes prompt.
  --help, -h            Show this help without compiling or connecting.

Supplied values must be distinct canonical Base64-encoded 32-byte keys;
they are preserved exactly. Only an explicitly selected key dotenv is read;
no FCRWW file is discovered automatically, and key env vars are not read.
Before writing, displays only each final 3 characters and exact mappings/
reference/namespace. Default confirmation requires explicit yes. Other
answers, Ctrl+C or EOF cancel without writing keys. All writes are atomic.
Existing/deleted key sets are refused; this never rotates existing keys.
Full values are never printed or written to plaintext files.
Raw encryption key values are not accepted as command-line parameters.

Examples:
  ./create-tenant-keys.sh
  ./create-tenant-keys.sh --environment development --tenant fcrww --name workflow-local:fcrww:key
  ./create-tenant-keys.sh --env-file /path/to/source.env
  # Tenant, environment and name are prompted; missing file keys are prompted.
  ./create-tenant-keys.sh --generate

The grant needs scoped read/write. Uses VAULT_MONGODB_URI and VAULT_MASTER_KEY
from the vault project .env (exported variables take precedence). Requires
Node.js 24, installed dependencies and MongoDB; the API can be stopped.
Compiles current sources first. Fully non-interactive use requires all scope,
name and token, a complete --env-file (or --generate), and --yes.
GET /local/key-tree browses the resulting metadata with list permission.'
    exit 0
    ;;
esac
set -eu
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
npm --prefix "$script_dir" run build --silent >&2
exec node "$script_dir/dist/create-tenant-keys.js" "$@"
