# FCRWW key import

Goal: provide an explicit local script to import existing FCRWW symmetric wrapping/index/control key strings into encrypted vault storage for a caller grant, preserving compatibility with existing ciphertext.

Architecture: prompt locally for the three key values without reading FCRWW files or key environment variables, validate canonical 32-byte Base64 and distinctness, verify the supplied bearer grant for read/write on the exact target scope, and use the existing encrypted namespace CAS transaction. No source file is accessed and Kick-Playr bindings remain unchanged. No plaintext values in output; no auto-import or API process startup. Existing identical active values skip; conflicts or inactive/deleted values abort all three writes. Vault master-key bootstrap stays external. CLI token comes from a hidden prompt or exported VAULT_TOKEN, never argv. All key prompts hide input; cancellation aborts import. Defaults development/fcrww; explicit environment/tenant overrides accepted together.

- [x] Add import regressions and observe initial missing-feature failure.
- [x] Implement atomic, grant-authorized import and executable wrapper with offline help.
- [x] Document invocation, field mapping and the separate consumer-binding cutover.
- [x] Verify build/typecheck/67 tests, offline shell help and independent security review. No live source-key migration performed.

User follow-up: validate all entered keys, show only each exact final three characters (including Base64 padding), name the target namespace, and require explicit yes before invoking the atomic import. Empty/no/y answers and cancellation do not write keys. Added suffix-only/decline/invalid-input regressions.

## Named tenant key sets

User provided workflow-local:fcrww:key and explicit three WORKFLOW_REAL_FCRWW env names. Implement environment/tenant/reference/role hierarchy; profiles do not infer or rename env mappings. Prompt for the name before values. Use deterministic full-hash physical names compatible with Azure naming and metadata tags for the original logical reference, role path and exact envName. Validate reference tenant against grant scope. No automatic migration or relabel of existing objects.

- [x] Add failing layout/tree tests, then implement scoped naming and metadata tree service.
- [x] Wire list-protected GET /local/key-tree, namespace alias and recursive Swagger schemas.
- [x] Integrate name prompt/confirmation and atomic importer metadata conflict checks.
- [x] Document structure and verify build/typecheck/72 tests, interactive PTY and independent review. No live imports performed.
