import { Authorization } from "../../src/v2/authorization.js";
const tenant = {
    environment: "development",
    ownerType: "tenant" as const,
    ownerId: "fcrww",
  },
  app = {
    environment: "development",
    ownerType: "application" as const,
    ownerId: "club-api",
  };
const actor = { issuer: "https://identity.invalid", subject: "person" };
function fixture() {
  let policy = {
    revision: "1",
    globalAdmin: true,
    clubAdminTenantIds: [] as string[],
  };
  let consent = { enabled: false, revision: 1 };
  return {
    authorization: new Authorization(
      { roles: async () => policy },
      { read: async () => consent },
    ),
    setRole: (v: typeof policy) => {
      policy = v;
    },
    approve: () => {
      consent = { enabled: true, revision: consent.revision + 1 };
    },
    revoke: () => {
      consent = { enabled: false, revision: consent.revision + 1 };
    },
  };
}
it("permits global metadata, but denies tenant values and edits until club consent", async () => {
  const f = fixture();
  await expect(
    f.authorization.require(actor, "metadata:list", tenant),
  ).resolves.toBeDefined();
  await expect(
    f.authorization.require(actor, "values:read", tenant),
  ).rejects.toThrow();
  await expect(
    f.authorization.require(actor, "resources:write", tenant),
  ).rejects.toThrow();
  f.approve();
  await expect(
    f.authorization.require(actor, "values:read", tenant),
  ).resolves.toBeDefined();
  await expect(
    f.authorization.require(actor, "resources:write", tenant),
  ).resolves.toBeDefined();
});
it("allows club admins only their own tenant and denies global grant or application administration", async () => {
  const f = fixture();
  f.setRole({
    revision: "1",
    globalAdmin: false,
    clubAdminTenantIds: ["fcrww"],
  });
  await expect(
    f.authorization.require(actor, "resources:write", tenant),
  ).resolves.toBeDefined();
  await expect(
    f.authorization.require(actor, "consent:write", tenant),
  ).resolves.toBeDefined();
  await expect(
    f.authorization.require(actor, "resources:write", {
      ...tenant,
      ownerId: "other",
    }),
  ).rejects.toThrow();
  await expect(
    f.authorization.require(actor, "resources:write", app),
  ).rejects.toThrow();
  await expect(
    f.authorization.require(actor, "grants:admin", app),
  ).rejects.toThrow();
});
it("does not let the global role self-approve consent and rejects forged or revoked permits", async () => {
  const f = fixture();
  await expect(
    f.authorization.require(actor, "consent:write", tenant),
  ).rejects.toThrow();
  f.approve();
  const permit = await f.authorization.require(actor, "values:read", tenant);
  await expect(f.authorization.assertCurrent(permit)).resolves.toBeUndefined();
  f.revoke();
  await expect(f.authorization.assertCurrent(permit)).rejects.toThrow();
  await expect(
    f.authorization.assertCurrent({ allowed: true }),
  ).rejects.toThrow();
});
it("rechecks membership changes and does not trust caller-supplied admin flags", async () => {
  const f = fixture();
  const permit = await f.authorization.require(actor, "resources:write", app);
  f.setRole({ revision: "2", globalAdmin: false, clubAdminTenantIds: [] });
  await expect(f.authorization.assertCurrent(permit)).rejects.toThrow();
  await expect(
    f.authorization.require(
      { ...actor, globalAdmin: true } as any,
      "metadata:list",
      tenant,
    ),
  ).rejects.toThrow();
});
it("does not let a provisioning credential borrow capabilities from a global-admin identity", async () => {
  const { bindProvisioning } =
    await import("../../src/v2/provisioning-proof.js");
  const actor = bindProvisioning(
    { issuer: "https://global.example", subject: "global" },
    {
      grantId: "p",
      revision: 1,
      environment: "development",
      tokenHash: "a".repeat(64),
      capabilities: ["metadata:list"],
    },
  );
  const authorization = new Authorization(
    {
      roles: async () => ({
        revision: "1",
        globalAdmin: true,
        clubAdminTenantIds: [],
      }),
    },
    { read: async () => ({ enabled: true, revision: 1 }) },
  );
  await expect(
    authorization.require(actor, "metadata:list", {
      environment: "development",
      ownerType: "tenant",
      ownerId: "fcrww",
    }),
  ).resolves.toEqual({ allowed: true });
  await expect(
    authorization.require(actor, "values:read", {
      environment: "development",
      ownerType: "tenant",
      ownerId: "fcrww",
    }),
  ).rejects.toThrow();
});
