# MongoDB storage implementation plan

User requested MongoDB instead of the file backend; preserve the existing REST/runtime contract and encryption. Continue inline implementation under the user's prior instruction to proceed.

Design: use the official MongoDB driver and one AES-256-GCM-encrypted document per namespace. Bind ciphertext to namespace ID and storage revision with authenticated additional data. Use conditional atomic replacement on the current revision (and unique `_id` on insert) to retry concurrent mutations without losing versions. No in-process plaintext cache or lifetime file lock. Reads go to the primary with majority read concern; writes use majority acknowledgement. Standalone local MongoDB is supported without multi-document transactions. Limit encrypted namespace payload below MongoDB's 16 MiB document maximum and fail safely when full. This keeps a complete tenant reconcile atomic; splitting versions into multiple documents would require replica-set transactions and is outside this storage change.

Bootstrap: require `VAULT_MONGODB_URI`, default database `local_key_vault`, retain external master key and exact caller grants. Never log connection strings or driver errors. Store only ciphertext, nonce/tag and revision metadata in the namespace collection; a small encrypted verifier document catches wrong keys at startup without scanning all namespaces. Existing encrypted file stores are untouched; no automatic migration or production database modification.

- [x] Replace file tests with real temporary MongoDB integration tests: encrypted restart, wrong key/corruption, concurrent connections/CAS retries, detached results, atomic callback rollback, database outages and BSON size bound.
- [x] Implement `MongoStore.open`, async namespace `read`, namespace `transaction`, and close; update Nest services/config to await database-backed operations.
- [x] Run all existing API/runtime tests against isolated MongoDB databases; add concurrent provisioning across two Nest server instances.
- [x] Update bootstrap/Compose/docs, run build/typecheck/full tests/audit and independent review.

Tests spawn a separate loopback mongod with a temporary data directory, never connect to the user's configured database. No live credential generation or migration is performed.
