import { createHash } from "node:crypto";
import { GrantService } from "../../src/v2/grants.js";
it("authorizes only enabled application grants bound to the requested application/environment", async () => {
  const token = "A".repeat(43),
    record = {
      _id: "g",
      grantClass: "application",
      applicationId: "club-api",
      environment: "development",
      enabled: true,
      revision: 1,
      tokenHash: createHash("sha256").update(token).digest("hex"),
      capabilities: ["secrets:read"],
    };
  const service = new GrantService(
    {
      grants: {
        findOne: async (filter: any) =>
          filter.tokenHash === record.tokenHash ? record : null,
      },
    } as any,
    {} as any,
    {} as any,
  );
  expect(
    (await service.authorize("Bearer " + token, "club-api", "development"))._id,
  ).toBe("g");
  await expect(
    service.authorize("Bearer " + token, "club-app", "development"),
  ).rejects.toThrow();
  await expect(
    service.authorize("Bearer " + token, "club-api", "production"),
  ).rejects.toThrow();
  record.enabled = false;
  await expect(
    service.authorize("Bearer " + token, "club-api", "development"),
  ).rejects.toThrow();
});
it("rejects malformed grant passwords before querying storage", async () => {
  let reads = 0;
  const service = new GrantService(
    {
      grants: {
        findOne: async () => {
          reads++;
          return null;
        },
      },
    } as any,
    {} as any,
    {} as any,
  );
  for (const header of [
    "",
    undefined,
    "Bearer short",
    "Basic " + "A".repeat(43),
    "Bearer " + "A".repeat(43) + "\n",
  ])
    await expect(
      service.authorize(header, "club-api", "development"),
    ).rejects.toThrow();
  expect(reads).toBe(0);
});
