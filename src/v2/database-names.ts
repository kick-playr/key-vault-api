import { databaseFromMongoUri } from "../mongodb-url.js";
const tenantPattern = /^[a-z0-9](?:[a-z0-9-]{0,50}[a-z0-9])?$/;
export function tenantIdentifier(value: unknown): string {
  if (
    typeof value !== "string" ||
    !tenantPattern.test(value) ||
    ["key-vault", "control"].includes(value)
  )
    throw Error("Invalid tenant identifier");
  return value;
}
export const databaseNames = Object.freeze({
  vault: "key-vault-kick-playr",
  control: "control-kick-playr",
  tenant: (tenantId: unknown) => `${tenantIdentifier(tenantId)}-kick-playr`,
});
/** Explicit migration target only: no implicit URI rewriting or live database rename. */
export function assertDatabaseName(uri: unknown, expected: string): void {
  if (databaseFromMongoUri(uri) !== expected)
    throw Error("MongoDB database does not match the approved target");
}
