import { ensureSchema, schemaVersionId } from "../../src/v2/schema-store.js";
it("binds custom schema versions to their owner and disallows runtime identities", () => {
  expect(
    schemaVersionId(
      { environment: "development", ownerType: "tenant", ownerId: "fcrww" },
      "mail",
      2,
    ),
  ).toBe("custom:development:tenant:fcrww:mail@2");
  expect(() =>
    schemaVersionId(
      { environment: "development", ownerType: "tenant", ownerId: "../other" },
      "mail",
      2,
    ),
  ).toThrow();
  expect(() =>
    schemaVersionId(
      { environment: "development", ownerType: "tenant", ownerId: "fcrww" },
      "mail",
      0,
    ),
  ).toThrow();
});

it("rejects another owner's custom schema even when cached", async () => {
  const schemas = { schema: () => ({ type: "object" }) };
  await expect(ensureSchema({} as any, schemas as any,
    { environment: "development", ownerType: "tenant", ownerId: "fcrww" },
    "custom:development:tenant:other:mail@1")).rejects.toThrow();
});
