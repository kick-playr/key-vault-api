#!/bin/sh
case "${1-}" in
  --help|-h)
    printf '%s\n' 'Usage: ./create-key.sh [--help|-h]

Generate one random 256-bit master encryption key as a Base64 string.
Prints the key to stdout; does not change .env or connect to MongoDB.

Example:
  ./create-key.sh
  # Save the output as VAULT_MASTER_KEY in .env for a NEW database.

Keep the key private and retain it across restarts. Generating a new key
will not re-encrypt an existing database; keep its original master key.'
    exit 0
    ;;
esac
exec node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64") + "\n")'
