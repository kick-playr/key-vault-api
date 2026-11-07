import {
  effectiveCustody,
  assertAdministrativeValueAccess,
  isWorkloadAccessName,
} from "../../src/v2/resource-custody.js";
const application = {
  ownerType: "application" as const,
  kind: "secret" as const,
};
it("defaults unclassified application resources to workload-only, but preserves tenant administration", () => {
  expect(effectiveCustody(application)).toBe("workload-only");
  expect(() => assertAdministrativeValueAccess(application)).toThrow(
    "Vault access denied",
  );
  expect(effectiveCustody({ ...application, ownerType: "tenant" })).toBe(
    "admin-managed",
  );
  expect(effectiveCustody({ ...application, custody: "admin-managed" })).toBe(
    "admin-managed",
  );
});
it("application control keys remain workload-only regardless of an admin-managed label", () => {
  expect(
    effectiveCustody({
      ...application,
      kind: "encryption-key",
      custody: "admin-managed",
    }),
  ).toBe("workload-only");
  for (const name of [
    "TENANT_CONTROL_MONGODB_URI",
    "MONGODB_URI",
    "DATABASE_URL",
    "WORKFLOW_SHARED_WRAPPING_KEY_V1",
    "MANAGER_SETUP_CONTROL_KEY",
    "CLERK_ENCRYPTION_KEY",
    "EXPLORER_CREDENTIAL_KEY",
    "WORKFLOW_PROXY_KEY",
  ])
    expect(isWorkloadAccessName(name)).toBe(true);
  expect(isWorkloadAccessName("CLERK_SECRET_KEY")).toBe(true);
});

it("does not trust an operator-looking human identity or a renamed resource", () => {
  expect(() =>
    assertAdministrativeValueAccess(
      {
        ...application,
        environment: "development",
        ownerId: "explorer-api",
        custody: "workload-only",
      },
      { issuer: "vault:deployment-operator", subject: "admin" },
    ),
  ).toThrow("Vault access denied");
});
