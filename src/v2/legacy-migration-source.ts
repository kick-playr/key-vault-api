import { rewriteReviewedDatabaseTarget } from "./migration-database-target.js";
import type { MongoStore } from "../store.js";
import type { Scope } from "../types.js";
import { scopeFilter } from "./mongo-store.js";
import type { LegacyItem, MigrationSource } from "./migration.js";
export interface LegacyResourceMapping extends Omit<
  LegacyItem,
  "sourceId" | "revision" | "versions"
> {
  scope: Scope;
  purpose: string;
  collection: "secrets" | "keys";
}
/** Explicit reviewed mappings, never guessing which application should receive an old namespace. */
export class LegacyMigrationSource implements MigrationSource {
  constructor(
    private readonly source: Pick<MongoStore, "read">,
    private readonly mappings: readonly LegacyResourceMapping[],
  ) {}
  async inventory() {
    const scopes = new Map<string, Scope>();
    for (const mapping of this.mappings) {
      scopeFilter(mapping.owner);
      if (
        !mapping.scope ||
        typeof mapping.scope.environment !== "string" ||
        typeof mapping.scope.tenant !== "string" ||
        !mapping.purpose ||
        !["secrets", "keys"].includes(mapping.collection)
      )
        throw Error("Invalid legacy migration mapping");
      scopes.set(JSON.stringify(mapping.scope), mapping.scope);
    }
    const result: LegacyItem[] = [];
    for (const scope of scopes.values())
      await this.source.read(scope, (namespace) => {
        if (!namespace) throw Error("Legacy namespace not found");
        const allowed = [
          "runtimeEffectiveManifests",
          "runtimeTenantPublications",
          "runtimePublicationReservation",
          "runtimeLinkPublications",
          "runtimeIdentities",
          "runtimeConfiguration",
          "internalScope",
          "deletedApplications",
          "applicationReservations",
          "applications",
          "resourceAssociations",
          "applicationRevision",
          "runtimeInstances",
          "oauthCredentials",
          "generation",
          "keys",
          "secrets",
          "tombstones",
          "runtimeManifests",
          "reconciliation",
          "audit",
        ];
        if (Object.keys(namespace).some((key) => !allowed.includes(key)))
          throw Error("Unclassified legacy namespace fields");
        const mappings = this.mappings.filter(
            (m) =>
              m.scope.environment === scope.environment &&
              m.scope.tenant === scope.tenant,
          ),
          identities = new Set(
            mappings.map((m) => m.collection + "/" + m.purpose),
          );
        if (identities.size !== mappings.length)
          throw Error("Ambiguous legacy resource mapping");
        for (const collection of ["secrets", "keys"] as const)
          for (const purpose of Object.keys(namespace[collection]))
            if (!identities.has(collection + "/" + purpose))
              throw Error("Unclassified legacy resource: " + purpose);
        for (const mapping of mappings) {
          const versions = namespace[mapping.collection][mapping.purpose];
          if (!versions?.length)
            throw Error("Mapped source resource is missing");
          if (
            mapping.disposition !== "retain-legacy-backup" && (
            namespace.tombstones.includes(
              mapping.collection + "/" + mapping.purpose,
            ) ||
            versions.some(
              (v) =>
                !v.attributes.enabled ||
                v.attributes.exp !== undefined ||
                v.attributes.nbf !== undefined,
            ))
          )
            throw Error(
              "Explicit lifecycle migration is required for disabled or time-bound versions",
            );
          const parsed = versions.map((version) => {
            // A reviewed retained record is fingerprinted intact, never normalized,
            // imported, or written back to its encrypted legacy namespace.
            if (mapping.disposition === "retain-legacy-backup") return {id:version.version,value:structuredClone(version)};
            if (mapping.collection === "keys") {
              if (
                version.privateKey?.kty !== "oct" ||
                typeof version.privateKey.k !== "string"
              )
                throw Error(
                  "Only exportable symmetric keys are supported by this migration",
                );
              const bytes = Buffer.from(version.privateKey.k, "base64url");
              try {
                if (bytes.length !== 32)
                  throw Error("A 256-bit key is required");
                return {
                  id: version.version,
                  value:
                    mapping.valueFormat === "hex64"
                      ? bytes.toString("hex")
                      : bytes.toString("base64"),
                };
              } finally {
                bytes.fill(0);
              }
            }
            if (typeof version.value !== "string")
              throw Error("Legacy secret value missing");
            if(mapping.databaseTarget !== undefined) {
              if(mapping.kind !== "secret" || mapping.collection !== "secrets")throw Error("Database targets require a scalar secret mapping");
              return {id:version.version,value:rewriteReviewedDatabaseTarget(version.value,mapping.owner,mapping.databaseTarget)};
            }
            return {
              id: version.version,
              value:
                mapping.kind === "integration"
                  ? JSON.parse(version.value)
                  : version.value,
            };
          });
          const {
            scope: _,
            purpose: __,
            collection: ___,
            ...metadata
          } = mapping;
          result.push({
            ...metadata,
            sourceId: JSON.stringify([
              scope.environment,
              scope.tenant,
              mapping.collection,
              mapping.purpose,
            ]),
            revision: namespace.generation,
            versions: parsed,
          });
        }
      });
    return result;
  }
}
