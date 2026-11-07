import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const {
  createMemoryRuntime,
} = require("../../runtime-client/memory-runtime.cjs");
it("adapts legacy process/tenant readers without triggering request-time fetches", async () => {
  let loads = 0;
  const row = (name: string, value: string) => ({
    resourceId: name,
    versionId: "v1",
    name,
    accessName: name,
    kind: "secret",
    valueFormat: "text",
    schemaIdentity: "secret:text@1",
    value,
  });
  const source = {
    load: async () => {
      loads++;
      return { CLERK_SECRET_KEY: "app" };
    },
    status: () => ({ ready: true, revision: "r1" }),
    context: (id?: string) => ({
      ready: true,
      values: [row("CLERK_SECRET_KEY", id ? "tenant" : "app")],
    }),
    close: () => {},
  };
  const runtime = createMemoryRuntime(source, "club-api", "development");
  await runtime.loadProcess("club-api", {
    allowedMappings: ["CLERK_SECRET_KEY"],
    requiredMappings: ["CLERK_SECRET_KEY"],
  });
  for (let n = 0; n < 100; n++) {
    const snapshot = await runtime.loadTenant("fcrww", 1);
    expect(snapshot.secrets[0].value).toBe("tenant");
  }
  expect(loads).toBe(1);
  runtime.close();
});
