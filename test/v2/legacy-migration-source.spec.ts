import { LegacyMigrationSource } from "../../src/v2/legacy-migration-source.js";
it("requires complete explicit classification and reads source namespaces without mutation", async () => {
  const ns = {
    generation: 1,
    keys: {},
    secrets: {
      legacy: [
        { version: "v1", attributes: { enabled: true }, value: "UNCHANGED" },
      ],
    },
    tombstones: [],
    audit: [],
  };
  const source = {
    read: async (_scope: any, work: any) => work(structuredClone(ns)),
  };
  const mapping = {
    scope: { environment: "development", tenant: "fcrww" },
    purpose: "legacy",
    collection: "secrets" as const,
    owner: {
      environment: "development",
      ownerType: "tenant" as const,
      ownerId: "fcrww",
    },
    name: "Readable purpose",
    kind: "secret" as const,
    valueFormat: "text" as const,
  };
  const inventory = await new LegacyMigrationSource(source as any, [
    mapping,
  ]).inventory();
  expect(inventory[0]?.versions[0]?.value).toBe("UNCHANGED");
  await expect(
    new LegacyMigrationSource(source as any, [
      { ...mapping, purpose: "missing" },
    ]).inventory(),
  ).rejects.toThrow("Unclassified");
  expect(ns.generation).toBe(1);
});
it('keeps a reviewed disabled backup intact without silently accepting it as an active integration',async()=>{
 const version={version:'old',attributes:{enabled:false},value:JSON.stringify({accessToken:'PRIVATE-LEGACY',accountId:'old',archiveRoot:'/old'})};
 const ns={generation:3,keys:{},secrets:{legacy:[version]},tombstones:['secrets/legacy'],audit:[]};
 const source={read:async(_scope:any,work:any)=>work(structuredClone(ns))};
 const mapping={scope:{environment:'development',tenant:'fcrww'},purpose:'legacy',collection:'secrets' as const,owner:{environment:'development',ownerType:'tenant' as const,ownerId:'fcrww'},name:'Old Dropbox',kind:'integration' as const,provider:'dropbox' as const};
 await expect(new LegacyMigrationSource(source as any,[mapping]).inventory()).rejects.toThrow('lifecycle');
 const inventory=await new LegacyMigrationSource(source as any,[{...mapping,disposition:'retain-legacy-backup',retentionReason:'Obsolete disabled personal-token bundle'}]).inventory();
 expect(inventory[0]?.versions[0]?.value).toEqual(version);
 expect(ns.secrets.legacy[0]).toEqual(version);
 const {previewMigration}=await import('../../src/v2/migration.js');
 const preview=await previewMigration({inventory:async()=>inventory},Buffer.alloc(32,3));
 expect(preview.counts.resources).toBe(0);expect(JSON.stringify(preview)).not.toContain('PRIVATE-LEGACY');
 const changed=structuredClone(inventory);(changed[0]!.versions[0]!.value as any).attributes.enabled=true;
 expect((await previewMigration({inventory:async()=>changed},Buffer.alloc(32,3))).digest).not.toBe(preview.digest);
});
