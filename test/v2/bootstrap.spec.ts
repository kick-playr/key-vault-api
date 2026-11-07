import { bootstrapDigest } from "../../src/v2/bootstrap.js";
it("hashes only the authorized metadata view, never secret bytes", () => {
  const view = {
    applicationId: "club-api",
    environment: "development",
    grantRevision: 2,
    resources: [{ id: "secret", version: "v1" }],
    tenants: ["fcrww"],
  };
  expect(bootstrapDigest(view)).toBe(bootstrapDigest(structuredClone(view)));
  expect(bootstrapDigest(view)).not.toBe(
    bootstrapDigest({ ...view, grantRevision: 3 }),
  );
  expect(bootstrapDigest(view)).not.toBe(
    bootstrapDigest({ ...view, tenants: [] }),
  );
});
