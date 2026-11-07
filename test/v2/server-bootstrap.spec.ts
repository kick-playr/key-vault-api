import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const {
  createServerBootstrap,
} = require("../../runtime-client/server-bootstrap.cjs");
it("requires the expected canonical application and never fetches during memory reads", async () => {
  expect(() =>
    createServerBootstrap({ VAULT_APPLICATION_ID: "club-api" }, "club-app"),
  ).toThrow();
  let calls = 0;
  const env = {
    VAULT_URL: "http://127.0.0.1:4000",
    VAULT_APPLICATION_ID: "club-app",
    VAULT_ENVIRONMENT: "development",
    VAULT_GRANT: "a".repeat(43),
    CLERK_SECRET_KEY: "stale",
  };
  const source = createServerBootstrap(env, "club-app", {
    requiredMappings: ["CLERK_SECRET_KEY"],
    clientOptions: {
      registerInstances: false,
      schedule: () => () => {},
      fetch: async () => {
        calls++;
        return {
          status: 200,
          json: async () => ({
            format: 2,
            revision: "r1",
            applicationId: "club-app",
            environment: "development",
            application: {
              ready: true,
              values: [
                {
                  resourceId: "r",
                  versionId: "v",
                  name: "Clerk",
                  accessName: "CLERK_SECRET_KEY",
                  kind: "secret",
                  valueFormat: "text",
                  schemaIdentity: "secret:text@1",
                  value: "fresh",
                },
              ],
            },
            tenants: {},
          }),
        };
      },
    },
  });
  expect((await source.load()).CLERK_SECRET_KEY).toBe("fresh");
  await source.load();
  expect(calls).toBe(1);
  expect(source.status().state).toBe("applied");
  source.close();
});
it("public configuration exposes only explicitly allowed public fields", () => {
  const {
    publicConfiguration,
  } = require("../../runtime-client/server-bootstrap.cjs");
  const context = {
    ready: true,
    values: [
      { accessName: "CLERK_PUBLISHABLE_KEY", value: "pk_test_fixture" },
      { accessName: "API_PUBLIC_ORIGIN", value: "http://fcrww.localhost:4312" },
      { accessName: "CLERK_SECRET_KEY", value: "PRIVATE" },
      { accessName: "DATABASE_URL", value: "PRIVATE-URI" },
    ],
  };
  expect(publicConfiguration(context)).toEqual({
    clerkPublishableKey: "pk_test_fixture",
    apiOrigin: "http://fcrww.localhost:4312",
  });
  expect(JSON.stringify(publicConfiguration(context))).not.toContain("PRIVATE");
});
