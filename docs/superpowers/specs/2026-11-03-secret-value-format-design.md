# Explicit secret value formats

Status: approved and implemented on 2026-11-03. User selected explicit format selection for new versions and requested automatic classification of existing versions.

## Intent

Support existing Clerk encryption keys written as 64 hexadecimal characters without changing their text. Record a secret's declared representation per immutable value version, so administrators can distinguish plain text, Base64 and 64-character hexadecimal values.

## Approaches

- **Explicit selection — selected:** the administrator chooses Plain text, Base64, or Hex (64 characters). The server validates the declaration. This avoids interpreting ordinary text as encoded data.
- **Automatic detection for new versions — rejected:** ordinary strings can also be valid Base64. Detection cannot establish the intended representation reliably.

## Behavior

- Add optional `valueFormat` metadata to secret versions, with values `text`, `base64`, and `hex64`. Require an explicit choice in the UI for new secret versions. For existing API clients that omit the field, store their newly created values as `text` for compatibility.
- Plain text preserves the existing secret-string contract and size limit. Base64 requires canonical standard Base64, including required padding. Hex requires exactly 64 ASCII hexadecimal characters; either letter case is accepted and preserved.
- Never trim, normalize, decode, convert, regenerate or replace a secret value based on its declared format. The format describes the stored text. Consumers retain their own mapping-specific requirements, including exactly 32 decoded bytes where required for cryptographic keys.
- Backfill every retained existing secret version that lacks metadata: exactly 64 ASCII hexadecimal characters becomes `hex64`; otherwise canonical, nonempty standard Base64 becomes `base64`; everything else becomes `text`. Hex64 takes precedence because a hexadecimal string may also be valid Base64. This is best-effort classification, not a claim about the original intent. Preserve any existing explicit declaration. Persist the inferred result without changing the value, version ID or application pin. Administrators can correct formats through metadata editing; the server validates against the stored value without returning that value to a metadata-only writer.
- The backfill includes the APP and Explorer Clerk encryption-key versions as `hex64`. Keep activation mode unchanged. Provide an idempotent migration command with sanitized counts and a dry-run option, using existing encrypted store access and compare-and-swap writes to preserve concurrent updates.
- Return format metadata in secret metadata/value responses, inventory, version history and application resource details. Show it in the Vault's secret create/edit form, secret details and application-linked-secret table. RSA key resources do not receive a secret value format.
- Preserve declared formats through internal secret rotation and provisioning paths. New replacement values must satisfy the retained declaration, or the caller must explicitly choose a new format for the new version.
- Update the APP and Explorer frontend Clerk loaders to accept either canonical Base64 encoding of 32 bytes or exactly 64 hex characters. Publish the original string unchanged. Reject malformed values before publishing any mappings. Do not loosen unrelated key validators.

## Constraints and scope

Use the existing API, encrypted storage, UI and consumer repositories. No new dependencies, services, grant changes, data re-encryption, activation or deployment. The Explorer startup manifest is a separate remaining task.

## Verification

Test all three formats, malformed and noncanonical representations, unchanged mixed-case hex and Base64 strings, backward compatibility, idempotent backfill of historical versions with hex-first precedence, preservation of explicit declarations, metadata-only editing without value disclosure, and UI create/edit/display behavior. Test APP and Explorer loaders with both supported Clerk formats and rejected invalid keys. Verify the existing live Clerk versions retain identical values and pins after metadata classification; do not start or restart applications.
