import { IntegrationSchemas } from "../../src/v2/integration-schemas.js";
const scope = {
  environment: "development",
  ownerType: "tenant" as const,
  ownerId: "fcrww",
};
it("validates static provider credentials and rejects runtime material without guessing token values", () => {
  const schemas = new IntegrationSchemas(),
    config = {
      clientId: "client",
      clientSecret: "PRIVATE",
      accountReference: "account",
    };
  expect(schemas.validate("builtin:bexio@1", config)).toEqual(config);
  expect(() =>
    schemas.validate("builtin:bexio@1", { ...config, accessToken: "runtime" }),
  ).toThrow();
  expect(() =>
    schemas.validate("builtin:bexio@1", {
      ...config,
      refresh_token: "runtime",
    }),
  ).toThrow();
  expect(() =>
    schemas.validate("builtin:bexio@1", { clientId: "missing-secret" }),
  ).toThrow();
  expect(
    schemas.validate("builtin:pingen@1", {
      apiToken: "STATIC-ADMIN-CREDENTIAL",
      organizationId: "org",
    }),
  ).toHaveProperty("apiToken");
  expect(() =>
    schemas.validate("builtin:email@1", {
      protocol: "smtp",
      host: "mail.invalid",
      port: "587",
      tls: "starttls",
      username: "u",
      password: "p",
    }),
  ).toThrow();
});
it("isolates immutable custom schemas by owner and returns independent configurations for repeated integration types", () => {
  const schemas = new IntegrationSchemas(),
    schema = {
      type: "object",
      properties: { apiKey: { type: "string", minLength: 1 } },
      required: ["apiKey"],
      additionalProperties: false,
    };
  const id = schemas.registerCustom(scope, "crm", 1, schema);
  const other = schemas.registerCustom(
    { ...scope, ownerId: "other" },
    "crm",
    1,
    schema,
  );
  expect(other).not.toBe(id);
  expect(schemas.validate(id, { apiKey: "ONE" })).toEqual({ apiKey: "ONE" });
  expect(schemas.validate(id, { apiKey: "TWO" })).toEqual({ apiKey: "TWO" });
  expect(() =>
    schemas.registerCustom(scope, "crm", 1, { ...schema, required: [] }),
  ).toThrow();
  expect(() =>
    schemas.validate(id, { apiKey: "ONE", nested: { idToken: "runtime" } }),
  ).toThrow();
});
it("rejects remote references, forbidden runtime fields and unsafe or oversized custom schemas", () => {
  const schemas = new IntegrationSchemas();
  for (const schema of [
    { $ref: "https://attacker.invalid/schema" },
    { type: "object", properties: { refreshToken: { type: "string" } } },
    {
      type: "object",
      properties: { apiKey: { type: "string", pattern: "(a+)+$" } },
    },
    { type: "object", description: "x".repeat(32769) },
  ])
    expect(() => schemas.registerCustom(scope, "bad", 1, schema)).toThrow();
  expect(() => schemas.validate("missing-schema", {})).toThrow();
});

it("treats property names as data and rejects asynchronous schema validation", () => {
  const schemas = new IntegrationSchemas();
  const id = schemas.registerCustom(scope, "format-settings", 1, {
    type: "object",
    properties: { format: { type: "string" } },
    required: ["format"],
    additionalProperties: false,
  });
  expect(schemas.validate(id, { format: "json" })).toEqual({ format: "json" });
});
it("rejects asynchronous schema validation", () => {
  const schemas = new IntegrationSchemas();
  expect(() =>
    schemas.registerCustom(scope, "async", 1, {
      $async: true,
      type: "object",
      properties: { apiKey: { type: "string" } },
      required: ["apiKey"],
      additionalProperties: false,
    }),
  ).toThrow();
});
