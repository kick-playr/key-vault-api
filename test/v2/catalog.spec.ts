import { applicationIdentity } from "../../src/v2/catalog.js";
it("uses canonical app slugs without embedding tenant identity", () => {
  expect(applicationIdentity("club-api")).toBe("club-api");
  expect(applicationIdentity("explorer-app")).toBe("explorer-app");
  expect(() => applicationIdentity("app")).toThrow();
  expect(applicationIdentity("custom-app")).toBe("custom-app");
  expect(() => applicationIdentity("app name")).toThrow();
});
