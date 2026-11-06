import { validateLink } from "../../src/v2/links.js";
it("requires explicit assignment for tenant links and preserves their owner", () => {
  const resource = {
    environment: "development",
    ownerType: "tenant" as const,
    ownerId: "fcrww",
    enabled: true,
  };
  expect(
    validateLink(
      resource,
      "club-api",
      "development",
      "fcrww",
      true,
      "BEXIO",
      "latest",
    ),
  ).toEqual({
    tenantId: "fcrww",
    accessName: "BEXIO",
    versionPolicy: "latest",
  });
  expect(() =>
    validateLink(
      resource,
      "club-api",
      "development",
      "other",
      true,
      "BEXIO",
      "latest",
    ),
  ).toThrow();
  expect(() =>
    validateLink(
      resource,
      "club-api",
      "development",
      "fcrww",
      false,
      "BEXIO",
      "latest",
    ),
  ).toThrow();
  expect(() =>
    validateLink(
      resource,
      "club-api",
      "production",
      "fcrww",
      true,
      "BEXIO",
      "latest",
    ),
  ).toThrow();
});
it("restricts app-owned links to that application and validates ENV names", () => {
  const resource = {
    environment: "development",
    ownerType: "application" as const,
    ownerId: "club-api",
    enabled: true,
  };
  expect(() =>
    validateLink(
      resource,
      "club-app",
      "development",
      undefined,
      false,
      "KEY",
      "latest",
    ),
  ).toThrow();
  expect(() =>
    validateLink(
      resource,
      "club-api",
      "development",
      undefined,
      false,
      "bad-name",
      "latest",
    ),
  ).toThrow();
  expect(() =>
    validateLink(
      { ...resource, enabled: false },
      "club-api",
      "development",
      undefined,
      false,
      "KEY",
      "latest",
    ),
  ).toThrow();
});
