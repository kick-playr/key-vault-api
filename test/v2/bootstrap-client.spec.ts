import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { createBootstrapClient } = require("../../runtime-client/bootstrap.cjs");
const snapshot = (
  rev: string,
  value = "app-secret",
  tenant = "tenant-secret",
) => ({
  format: 2,
  applicationId: "club-api",
  environment: "development",
  revision: rev,
  application: {
    ready: true,
    values: [
      {
        resourceId: "a",
        versionId: "v1",
        accessName: "CLERK_SECRET_KEY",
        name: "Clerk",
        kind: "secret",
        valueFormat: "text",
        schemaIdentity: "secret:text@1",
        value,
      },
    ],
  },
  tenants: {
    fcrww: {
      ready: true,
      values: [
        {
          resourceId: "t",
          versionId: "v1",
          accessName: "CLERK_SECRET_KEY",
          name: "Clerk",
          kind: "secret",
          valueFormat: "text",
          schemaIdentity: "secret:text@1",
          value: tenant,
        },
      ],
    },
  },
});
it("serves memory only, throttles refresh and preserves identities on 304 and outage", async () => {
  let now = 0,
    calls = 0,
    mode = 200;
  const env: Record<string, string> = {};
  const client = createBootstrapClient({
    url: "http://127.0.0.1:4000",
    applicationId: "club-api",
    environment: "development",
    grant: "a".repeat(43),
    env,
    now: () => now,
    schedule: () => () => {},
    fetch: async () => {
      calls++;
      if (mode === 500) throw Error("transport with private content");
      return { status: mode, json: async () => snapshot("r1") };
    },
  });
  await client.start();
  expect(client.status().ready).toBe(true);
  expect(env.CLERK_SECRET_KEY).toBe("app-secret");
  expect(client.tenant("fcrww").values[0].value).toBe("tenant-secret");
  const before = client.application();
  for (let i = 0; i < 100; i++) client.application();
  expect(calls).toBe(1);
  await client.refresh();
  expect(calls).toBe(1);
  now = 60000;
  mode = 304;
  await client.refresh();
  expect(client.application()).toBe(before);
  now = 120000;
  mode = 500;
  await client.refresh();
  expect(client.application()).toBe(before);
  expect(client.status().ready).toBe(true);
  expect(client.status().connected).toBe(false);
  client.close();
  expect(env.CLERK_SECRET_KEY).toBeUndefined();
});
it("stays unready before bootstrap and removes revoked material on successful denial", async () => {
  let now = 0,
    mode = 503;
  const env: Record<string, string> = {};
  const client = createBootstrapClient({
    url: "http://127.0.0.1:4000",
    applicationId: "club-api",
    environment: "development",
    grant: "a".repeat(43),
    env,
    now: () => now,
    schedule: () => () => {},
    fetch: async () => ({ status: mode, json: async () => snapshot("r1") }),
  });
  await client.refresh();
  expect(client.status().ready).toBe(false);
  expect(client.status().message).toBe("Key Vault is not connected");
  expect(() => client.application()).toThrow();
  now = 60000;
  mode = 200;
  await client.refresh();
  now = 120000;
  mode = 403;
  await client.refresh();
  expect(client.status().ready).toBe(false);
  expect(() => client.tenant("fcrww")).toThrow();
  expect(env.CLERK_SECRET_KEY).toBeUndefined();
  client.close();
});
it("isolates concurrent callers and removes one tenant without touching another", async () => {
  let now = 0,
    calls = 0;
  let next: any = snapshot("r1");
  next.tenants.other = structuredClone(next.tenants.fcrww);
  const client = createBootstrapClient({
    url: "http://127.0.0.1:4000",
    applicationId: "club-api",
    environment: "development",
    grant: "a".repeat(43),
    env: {},
    now: () => now,
    schedule: () => () => {},
    fetch: async () => {
      calls++;
      await Promise.resolve();
      return { status: 200, json: async () => next };
    },
  });
  await Promise.all([client.start(), client.refresh(), client.refresh()]);
  expect(calls).toBe(1);
  expect(Object.isFrozen(client.tenant("fcrww").values)).toBe(true);
  now = 60000;
  next = snapshot("r2");
  next.tenants.other = structuredClone(next.tenants.fcrww);
  delete next.tenants.fcrww;
  await client.refresh();
  expect(() => client.tenant("fcrww")).toThrow();
  expect(client.tenant("other").ready).toBe(true);
  client.close();
});
it("rejects polling intervals below one minute", () => {
  expect(() =>
    createBootstrapClient({
      url: "http://127.0.0.1:4000",
      applicationId: "club-api",
      environment: "development",
      grant: "a".repeat(43),
      refreshIntervalMs: 5000,
    }),
  ).toThrow();
});
it("acknowledges a staged usable key before publishing readiness and retains keys across uncertain ACK", async () => {
  let prepared = false,
    client: any,
    acknowledged = false;
  const data = snapshot("keys");
  data.application.values = [
    {
      resourceId: "key",
      versionId: "old",
      name: "Data",
      accessName: "DATA_KEY",
      kind: "encryption-key",
      valueFormat: "base64",
      schemaIdentity: "encryption-key:base64@1",
      value: Buffer.alloc(32, 1).toString("base64"),
      keyVersions: [
        {
          versionId: "old",
          state: "active-for-encryption",
          value: Buffer.alloc(32, 1).toString("base64"),
        },
        {
          versionId: "new",
          state: "prepared",
          rotationId: "rotation",
          value: Buffer.alloc(32, 2).toString("base64"),
        },
      ],
    },
  ] as any;
  client = createBootstrapClient({
    url: "http://127.0.0.1:4000",
    applicationId: "club-api",
    environment: "development",
    grant: "a".repeat(43),
    registerInstances: true,
    acknowledgeKey: () => true,
    env: {},
    schedule: () => () => {},
    onChange: () => {
      prepared = true;
    },
    fetch: async (url: string, init: any) => {
      if (url.endsWith("/v2/instances"))
        return {
          status: 201,
          json: async () => ({
            instanceId: "instance",
            password: "b".repeat(43),
          }),
        };
      if (url.endsWith("/acknowledge")) {
        expect(prepared).toBe(true);
        expect(client.status().ready).toBe(false);
        expect(client.key("key", "new").equals(Buffer.alloc(32, 2))).toBe(true);
        acknowledged = true;
        return { status: 201, json: async () => ({ acknowledged: true }) };
      }
      return { status: 200, json: async () => data };
    },
  });
  await client.start();
  expect(acknowledged).toBe(true);
  expect(client.status().ready).toBe(true);
  client.close();
  expect(() => client.key("key", "new")).toThrow();
});
it("does not acknowledge a prepared key without an installed crypto adapter", async () => {
  let calls = 0,
    now = 0;
  const data = snapshot("pending");
  data.application.values = [
    {
      resourceId: "key",
      versionId: "old",
      name: "Data",
      accessName: "DATA_KEY",
      kind: "encryption-key",
      valueFormat: "base64",
      schemaIdentity: "encryption-key:base64@1",
      value: Buffer.alloc(32, 1).toString("base64"),
      keyVersions: [
        {
          versionId: "old",
          state: "active-for-encryption",
          value: Buffer.alloc(32, 1).toString("base64"),
        },
        {
          versionId: "new",
          state: "prepared",
          rotationId: "rotation",
          value: Buffer.alloc(32, 2).toString("base64"),
        },
      ],
    },
  ] as any;
  const client = createBootstrapClient({
    url: "http://127.0.0.1:4000",
    applicationId: "club-api",
    environment: "development",
    grant: "a".repeat(43),
    registerInstances: true,
    env: {},
    schedule: () => () => {},
    now: () => now,
    fetch: async (url: string) => {
      if (url.endsWith("/v2/instances"))
        return {
          status: 201,
          json: async () => ({ instanceId: "i", password: "b".repeat(43) }),
        };
      if (url.endsWith("/acknowledge")) calls++;
      return { status: 200, json: async () => data };
    },
  });
  await client.refresh();
  expect(calls).toBe(0);
  expect(client.status().ready).toBe(false);
  expect(client.status().message).toMatch(/crypto adapter/);
  client.close();
});
it("schedules retries when start follows an unsuccessful manual refresh", async () => {
  let scheduled = 0;
  const client = createBootstrapClient({url:"http://127.0.0.1:4000", applicationId:"club-api",
    environment:"development", grant:"a".repeat(43), now:()=>0,
    schedule:()=>{scheduled++;return ()=>{}}, fetch:async()=>{throw Error("offline")} });
  await client.refresh();
  const pending=client.start().catch(()=>{});
  expect(scheduled).toBe(1);
  client.close();await pending;
});
it("aborts in-flight transport when closed", async () => {
  let signal: AbortSignal | undefined;
  const client = createBootstrapClient({url:"http://127.0.0.1:4000", applicationId:"club-api",
    environment:"development", grant:"a".repeat(43),
    fetch:async (_url: string, options: RequestInit)=>{signal=options.signal as AbortSignal;return new Promise(resolve=>signal!.addEventListener("abort",()=>resolve({status:503})));} });
  const pending=client.refresh();
  client.close();
  expect(signal!.aborted).toBe(true);
  await pending;
});
it("removes old secrets when an authoritative revocation cannot be applied", async () => {
 let now=0,revoked=false,invalidations=0;
 const env:Record<string,string>={},messages:string[]=[];
 const client=createBootstrapClient({url:'http://127.0.0.1:4000',applicationId:'club-api',environment:'development',grant:'a'.repeat(43),env,now:()=>now,schedule:()=>()=>{},onDiagnostic:(message:string)=>messages.push(message),
 fetch:async()=>({status:200,json:async()=>{const next=snapshot(revoked?'r2':'r1');if(revoked)next.tenants.fcrww={ready:false,values:[]};return next;}}),
 onChange:(next:any)=>{if(!next){invalidations++;return;}if(revoked)throw Error('private composition failure');}});
 await client.start();await client.refresh();expect(client.tenant('fcrww').ready).toBe(true);revoked=true;now=60000;await client.refresh();
 expect(client.status().ready).toBe(false);expect(()=>client.tenant('fcrww')).toThrow();expect(env.CLERK_SECRET_KEY).toBeUndefined();expect(invalidations).toBe(1);expect(messages.join()).not.toContain('private composition failure');client.close();
});
