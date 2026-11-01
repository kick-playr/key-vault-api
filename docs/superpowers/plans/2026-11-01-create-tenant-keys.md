# Create tenant key set

Goal: interactive local creation of a fresh wrapping/index/control symmetric key set with explicit tenant naming and environment-variable mappings.

Use the existing logical tree, encrypted namespace CAS, scoped read/write grant authorization and hidden token input. Ask for environment, tenant, logical reference and all three env names (suggest tenant-derived defaults but validate user choices). Generate three distinct random 32-byte Base64 keys, preview only 3-character suffixes plus exact namespace/reference/mappings, then require explicit yes. Commit all three atomically with create-only semantics: no replacement, reactivation or rotation of existing/deleted keys. Never print full generated keys or write them to files. Read them later via authorized secret API. Help must work offline. No real key creation during implementation.

- [x] Add generation/prompt/refusal/grant/atomicity regressions.
- [x] Share validated mapping and atomic writer with existing importer; add create-only behavior.
- [x] Add create-tenant-keys.sh with offline help and interactive CLI.
- [x] Verify full suite, PTY prompts, independent review and documentation.

User correction: create-tenant-keys.sh knows the three key names automatically. Only ask environment, tenant and reference; derive WORKFLOW_REAL_<UPPERCASE_TENANT>_{WRAPPING_KEY_V1,INDEX_KEY,CONTROL_KEY}, normalizing tenant hyphens to underscores. Display all mappings at suffix confirmation. Keep existing hidden token, random generation and atomic create-only protection. Regression verifies exactly three metadata prompts and exact FCRWW mapping names.

User follow-up: CLI defaults to real key values via hidden prompts, with --wrapping-key/--index-key/--control-key parameters accepted individually. Scope/name/token also accept options. Only --generate requests fresh random values; incompatible supplied-key flags are refused. --yes supports explicit non-interactive approval. Preserve supplied strings, suffix-only previews, metadata mappings and atomic create-only authorization. Added argument, missing-value prompt, exact-value persistence and invalid-value regressions.

Latest correction: remove raw key-value parameters entirely. Keep non-secret scope/name parameters and always prompt for an omitted tenant. Read key values only from an explicitly selected --env-file, or hidden prompts; missing/blank source entries are prompted. Never discover/read FCRWW source files automatically. Preserve caller cwd for relative source paths while resolving vault bootstrap .env from the vault project. --generate is incompatible with file mode. Tests cover tenant prompting with metadata flags, rejected key-value flags, read-only dotenv input and missing-entry prompts.
