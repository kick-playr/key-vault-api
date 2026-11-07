import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const {
  sealRuntime,
  openRuntime,
  assertRuntimeDatabase,
} = require("../../runtime-client/integration-runtime.cjs");
it("encrypts runtime values with tenant/integration/generation binding and enforces tenant database ownership", () => {
  const context = {
      tenantId: "fcrww",
      environment: "development",
      integrationId: "bexio-accounting",
      authorityGeneration: 2,
      revision: 3,
      staticVersion: "v1",
    },
    key = Buffer.alloc(32, 9),
    value = {
      accessToken: "PRIVATE-ACCESS",
      refreshToken: "PRIVATE-REFRESH",
      expiresAt: Date.now() + 1000,
    };
  const sealed = sealRuntime(context, value, key, "k1");
  expect(JSON.stringify(sealed)).not.toContain("PRIVATE");
  expect(openRuntime(context, sealed, new Map([["k1", key]]))).toEqual(value);
  expect(() =>
    openRuntime(
      { ...context, tenantId: "other" },
      sealed,
      new Map([["k1", key]]),
    ),
  ).toThrow();
  expect(() =>
    openRuntime(
      { ...context, authorityGeneration: 3 },
      sealed,
      new Map([["k1", key]]),
    ),
  ).toThrow();
  expect(() =>
    assertRuntimeDatabase("key-vault-kick-playr", "fcrww"),
  ).toThrow();
  expect(() =>
    assertRuntimeDatabase("fcrww-kick-playr", "fcrww"),
  ).not.toThrow();
});
