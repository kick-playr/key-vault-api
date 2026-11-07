import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const {
  validateIntegration,
} = require("../../runtime-client/integration-validation.cjs");
it("validates server-provided immutable schemas before publishing integration memory", () => {
  const row = {
    schemaIdentity: "builtin:fixture@1",
    schema: {
      type: "object",
      properties: { clientId: { type: "string" } },
      required: ["clientId"],
      additionalProperties: false,
    },
    value: { clientId: "valid" },
  };
  expect(validateIntegration(row)).toEqual({ clientId: "valid" });
  expect(() =>
    validateIntegration({ ...row, value: { clientId: 2 } }),
  ).toThrow();
  expect(() =>
    validateIntegration({ ...row, value: { accessToken: "runtime" } }),
  ).toThrow();
  expect(() =>
    validateIntegration({
      ...row,
      schema: { $ref: "https://untrusted.example/schema" },
    }),
  ).toThrow();
});
