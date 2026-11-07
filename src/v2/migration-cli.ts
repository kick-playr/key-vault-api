import { CompositeMigrationSource, PublicEnvironmentMigrationSource, ReviewedClerkEnvironmentMigrationSource } from "./environment-migration-source.js";
import { readFile } from "node:fs/promises";
import { MongoStore } from "../store.js";
import {
  LegacyMigrationSource,
  type LegacyResourceMapping,
} from "./legacy-migration-source.js";
import { previewMigration } from "./migration.js";
import { assertDatabaseName, databaseNames } from "./database-names.js";
/** Read-only inventory. Live staging/cutover must use the separately reviewed maintenance configuration. */
async function main() {
  if (process.argv[2] !== "preview" || !process.argv[3])
    throw Error(
      "Usage: migrate:static-vault -- preview <reviewed-mapping.json>",
    );
  const sourceUri = process.env.MIGRATION_SOURCE_MONGODB_URI,
    encoded = process.env.MIGRATION_SOURCE_MASTER_KEY,
    review = process.env.MIGRATION_REVIEW_KEY,
    target = process.env.MIGRATION_TARGET_MONGODB_URI;
  if (!sourceUri || !encoded || !review || !target)
    throw Error(
      "Migration source, explicit target and private review key are required",
    );
  assertDatabaseName(target, databaseNames.vault);
  const masterKey = Buffer.from(encoded, "base64"),
    reviewKey = Buffer.from(review, "base64");
  if (masterKey.length !== 32 || reviewKey.length !== 32)
    throw Error("Invalid migration key configuration");
  let source: MongoStore | undefined;
  try {
    const mapping = JSON.parse(
      await readFile(process.argv[3], "utf8"),
    );
    const resources = Array.isArray(mapping) ? mapping : mapping.resources;
    const publicEnvironment = Array.isArray(mapping) ? [] : mapping.publicEnvironment ?? [];
    const reviewedClerkEnvironment = Array.isArray(mapping) ? [] : mapping.reviewedClerkEnvironment ?? [];
    if (!Array.isArray(resources) || !Array.isArray(publicEnvironment) || !Array.isArray(reviewedClerkEnvironment)
      || (!Array.isArray(mapping) && Object.keys(mapping).some(key => !["resources", "publicEnvironment", "reviewedClerkEnvironment"].includes(key))))
      throw Error("Expected an explicit reviewed source profile");
    source = await MongoStore.open(
      { mongoUri: sourceUri, masterKey },
      { createVerifier: false },
    );
    const preview = await previewMigration(
      new CompositeMigrationSource([
        new LegacyMigrationSource(source, resources as LegacyResourceMapping[]),
        new PublicEnvironmentMigrationSource(publicEnvironment),
        new ReviewedClerkEnvironmentMigrationSource(reviewedClerkEnvironment, reviewKey),
      ]),
      reviewKey,
    );
    process.stdout.write(JSON.stringify(preview, null, 2) + "\n");
  } finally {
    masterKey.fill(0);
    reviewKey.fill(0);
    await source?.close();
  }
}
void main().catch(() => {
  process.stderr.write(
    "Migration preview failed. Check the explicit mapping, lifecycle classification, source access and target database names. No credentials are printed.\n",
  );
  process.exitCode = 1;
});
