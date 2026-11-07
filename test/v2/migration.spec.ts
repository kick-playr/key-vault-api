import {
  classifyIntegration,
  canonicalApplication,
  previewMigration,
} from "../../src/v2/migration.js";
it("splits mixed integration bundles by explicit lifecycle schema without changing static values", () => {
  const split = classifyIntegration(
    "bexio",
    {
      clientId: "id",
      clientSecret: "secret",
      accessToken: "access",
      refreshToken: "refresh",
      expiresAt: 123,
    },
    "account",
  );
  expect(split.staticValue).toEqual({
    clientId: "id",
    clientSecret: "secret",
    accountReference: "account",
  });
  expect(split.runtimeValue).toEqual({
    accessToken: "access",
    refreshToken: "refresh",
    expiresAt: 123,
  });
  expect(() =>
    classifyIntegration(
      "bexio",
      { clientId: "id", clientSecret: "secret", unexpected: "unknown" },
      "account",
    ),
  ).toThrow();
  expect(canonicalApplication("app")).toBe("club-app");
  expect(canonicalApplication("explorer")).toBe("explorer-app");
});
it("preview is read only and binds source changes to a reviewed digest", async () => {
  let writes = 0;
  const source = {
    inventory: async () => [
      {
        sourceId: "legacy",
        revision: 1,
        owner: {
          environment: "development",
          ownerType: "tenant" as const,
          ownerId: "fcrww",
        },
        name: "Bexio",
        kind: "integration" as const,
        provider: "bexio" as const,
        accountReference: "account",
        versions: [
          {
            id: "v1",
            value: {
              clientId: "id",
              clientSecret: "secret",
              accessToken: "access",
              refreshToken: "refresh",
              expiresAt: 123,
            },
          },
        ],
      },
    ],
  };
  const result = await previewMigration(source, Buffer.alloc(32, 1));
  expect(writes).toBe(0);
  expect(result.counts.staticVersions).toBe(1);
  expect(result.counts.runtimeVersions).toBe(1);
  expect(JSON.stringify(result)).not.toContain("secret");
  expect(JSON.stringify(result)).not.toContain("accessToken");
});
it("reviews custody classification and keeps unclassified application material workload-only", async () => {
  const item = {
    sourceId: "app-db",
    revision: 1,
    owner: {
      environment: "development",
      ownerType: "application" as const,
      ownerId: "explorer-api",
    },
    name: "Control Mongo",
    kind: "secret" as const,
    versions: [{ id: "v1", value: "mongodb://PRIVATE/control-kick-playr" }],
  };
  const preview = await previewMigration(
    { inventory: async () => [item] },
    Buffer.alloc(32, 4),
  );
  expect(preview.items[0]?.custody).toBe("workload-only");
  expect(JSON.stringify(preview)).not.toContain("PRIVATE");
  await expect(
    previewMigration(
      {
        inventory: async () => [
          {
            ...item,
            kind: "encryption-key",
            custody: "admin-managed",
            valueFormat: "base64",
            versions: [
              { id: "v1", value: Buffer.alloc(32).toString("base64") },
            ],
          },
        ],
      },
      Buffer.alloc(32, 4),
    ),
  ).rejects.toThrow("workload-only");
});
it('requires explicit reviewed runtime lifecycle metadata rather than inventing capabilities',async()=>{
 const item={sourceId:'runtime-meta',revision:1,owner:{environment:'development',ownerType:'tenant' as const,ownerId:'fcrww'},name:'Accounting',kind:'integration' as const,provider:'bexio' as const,accountReference:'account',versions:[{id:'v1',value:{clientId:'client',clientSecret:'private',accessToken:'access',refreshToken:'refresh',expiresAt:123}}]};
 expect((await previewMigration({inventory:async()=>[item]},Buffer.alloc(32,4))).items[0]?.requiresReauthorization).toBe(true);
 const runtimeMetadata={schema:1 as const,connectionId:'bexio',provider:'bexio',purpose:'oauth',capabilities:['contacts:read'],securityEpoch:3};
 expect((await previewMigration({inventory:async()=>[{...item,runtimeMetadata}]},Buffer.alloc(32,4))).items[0]?.requiresReauthorization).toBe(false);
 await expect(previewMigration({inventory:async()=>[{...item,runtimeMetadata:{...runtimeMetadata,clientSecret:'forbidden'}}]},Buffer.alloc(32,4))).rejects.toThrow();
});
it('retains explicitly reviewed obsolete bundles without importing or exposing their values',async()=>{
 const backup={sourceId:'obsolete',revision:7,owner:{environment:'development',ownerType:'application' as const,ownerId:'explorer'},name:'Obsolete personal Dropbox',kind:'integration' as const,provider:'dropbox' as const,disposition:'retain-legacy-backup' as const,retentionReason:'Disabled legacy personal-token connection; rollback backup only',versions:[{id:'v1',value:{accessToken:'PRIVATE-BACKUP-TOKEN',accountId:'old',archiveRoot:'/old'}}]};
 const result=await previewMigration({inventory:async()=>[backup]},Buffer.alloc(32,8));
 expect(result.counts.resources).toBe(0);expect(result.counts.staticVersions).toBe(0);expect(result.counts.runtimeVersions).toBe(0);
 expect(result.counts.retainedBackups).toBe(1);expect(result.counts.retainedVersions).toBe(1);
 expect(result.retainedBackups[0]).toMatchObject({name:backup.name,retentionReason:backup.retentionReason,versions:1});
 expect(JSON.stringify(result)).not.toContain('PRIVATE-BACKUP-TOKEN');expect(JSON.stringify(result)).not.toContain('accessToken');
 await expect(previewMigration({inventory:async()=>[{...backup,retentionReason:''}]},Buffer.alloc(32,8))).rejects.toThrow('retention');
 await expect(previewMigration({inventory:async()=>[{...backup,disposition:undefined,retentionReason:undefined}]},Buffer.alloc(32,8))).rejects.toThrow('Unclassified');
});
it('normalizes only explicit reviewed email aliases, defaults and mailbox metadata',()=>{
 const mapping={rename:{user:'username',fromAddress:'sender',inbox:'inboxFolder',archive:'archiveFolder'},defaults:{protocol:'imap',tls:'implicit'},metadataOnly:['mailboxId']} as const;
 const raw={host:'mail.example.com',port:993,user:'user',password:'PRIVATE',fromAddress:'sender@example.com',inbox:'INBOX',archive:'Archive',mailboxId:'mailbox'};
 const split=classifyIntegration('email',raw,'mailbox','builtin:email@2',mapping);
 expect(split.staticValue).toEqual({host:raw.host,port:993,username:'user',password:'PRIVATE',sender:'sender@example.com',inboxFolder:'INBOX',archiveFolder:'Archive',protocol:'imap',tls:'implicit'});
 expect(raw).toHaveProperty('user');expect(raw).not.toHaveProperty('username');
 expect(()=>classifyIntegration('email',{...raw,username:'collision'},'mailbox','builtin:email@2',mapping)).toThrow('collision');
 expect(()=>classifyIntegration('email',raw,'different','builtin:email@2',mapping)).toThrow('account');
 expect(()=>classifyIntegration('email',{...raw,accessToken:'runtime-secret'},'mailbox','builtin:email@2',{...mapping,metadataOnly:['mailboxId','accessToken']} as any)).toThrow();
 expect(()=>classifyIntegration('email',{...raw,unknownSecret:'secret'},'mailbox','builtin:email@2',mapping)).toThrow('Unclassified');
 expect(()=>classifyIntegration('email',raw,'mailbox','builtin:email@2',{...mapping,defaults:{password:'unsafe'}} as any)).toThrow();
 expect(()=>classifyIntegration('email',raw,'mailbox','builtin:email@2',{...mapping,defaults:{protocol:'imap',tls:true}} as any)).toThrow();
 expect(()=>classifyIntegration('email',raw,'mailbox','builtin:email@2',{...mapping,rename:{refreshToken:'username'}} as any)).toThrow();
 expect(()=>classifyIntegration('email',raw,'mailbox','builtin:email@1',mapping)).toThrow();
});
