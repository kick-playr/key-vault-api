"use strict";
const { performance } = require("node:perf_hooks");
const { createBootstrapClient } = require("../runtime-client/bootstrap.cjs");
(async () => {
  let fetches = 0;
  const value = (id) => ({
      resourceId: id,
      versionId: "v1",
      name: "Synthetic purpose",
      accessName: "SYNTHETIC_SECRET",
      kind: "secret",
      valueFormat: "text",
      schemaIdentity: "secret:text@1",
      value: "synthetic-only",
    }),
    snapshot = {
      format: 2,
      applicationId: "club-api",
      environment: "development",
      revision: "benchmark-fixture",
      application: { ready: true, values: [value("application")] },
      tenants: Object.fromEntries(
        Array.from({ length: 200 }, (_, i) => [
          "tenant-" + i,
          { ready: true, values: [value("tenant-" + i)] },
        ]),
      ),
    };
  const bytes = Buffer.byteLength(JSON.stringify(snapshot)),
    before = process.memoryUsage().heapUsed,
    client = createBootstrapClient({
      url: "http://127.0.0.1:4000",
      applicationId: "club-api",
      environment: "development",
      grant: "a".repeat(43),
      env: {},
      schedule: () => () => {},
      fetch: async () => {
        fetches++;
        return { status: 200, json: async () => snapshot };
      },
    });
  const start = performance.now();
  await client.start();
  const bootstrapMs = performance.now() - start,
    readStart = performance.now();
  for (let i = 0; i < 100000; i++) client.tenant("tenant-" + (i % 200));
  const readsMs = performance.now() - readStart;
  console.log(
    JSON.stringify({
      fixture: true,
      tenants: 200,
      bytes,
      bootstrapMs: Number(bootstrapMs.toFixed(2)),
      memoryReads: 100000,
      readsMs: Number(readsMs.toFixed(2)),
      heapDeltaBytes: process.memoryUsage().heapUsed - before,
      secretFetches: fetches,
      businessRequestSecretFetches: fetches - 1,
      note: "Synthetic in-process SDK measurement; excludes live HTTP, MongoDB, Clerk and Bexio latency",
    }),
  );
  client.close();
})().catch(() => {
  process.stderr.write("Synthetic bootstrap benchmark failed\n");
  process.exitCode = 1;
});
