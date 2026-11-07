import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PublicEnvironmentMigrationSource} from '../../src/v2/environment-migration-source.js';
it('imports only explicitly selected public configuration without importing private environment fields',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vault-public-source-'));
 try{
  const envFile=join(root,'.env.local');await writeFile(envFile,'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_fixture\nCLERK_SECRET_KEY=PRIVATE-DO-NOT-IMPORT\nNEXT_PUBLIC_API_ENDPOINT=""\n');
  const source=new PublicEnvironmentMigrationSource([{envFile,environment:'development',applicationId:'club-app',key:'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY'},{envFile,environment:'development',applicationId:'club-app',key:'NEXT_PUBLIC_API_ENDPOINT',skipIfEmpty:true}]);
  const rows=await source.inventory();expect(rows).toHaveLength(1);expect(rows[0]?.versions[0]?.value).toBe('pk_test_fixture');expect(JSON.stringify(rows)).not.toContain('PRIVATE');
  await expect(new PublicEnvironmentMigrationSource([{envFile,environment:'development',applicationId:'club-app',key:'CLERK_SECRET_KEY'} as any]).inventory()).rejects.toThrow();
 }finally{await rm(root,{recursive:true,force:true});}
});
it('uses an explicit operator-only Clerk seed and private version fingerprints, never arbitrary bootstrap credentials',async()=>{
 const {ReviewedClerkEnvironmentMigrationSource}=await import('../../src/v2/environment-migration-source.js');
 const root=await mkdtemp(join(tmpdir(),'vault-clerk-source-'));
 try{
  const filename=join(root,'.env');await writeFile(filename,'CLERK_SECRET_KEY=sk_test_PRIVATE\nNEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_fixture\nVAULT_MASTER_KEY=DO-NOT-IMPORT\n');
  const mapping={envFile:filename,environment:'development',applicationId:'club-app'};
  const first=await new ReviewedClerkEnvironmentMigrationSource([mapping],Buffer.alloc(32,1)).inventory();
  const second=await new ReviewedClerkEnvironmentMigrationSource([mapping],Buffer.alloc(32,2)).inventory();
  expect(first[0]?.custody).toBe('workload-only');expect(first[0]?.versions[0]?.value).toBe('sk_test_PRIVATE');expect(first[0]?.versions[0]?.id).not.toBe(second[0]?.versions[0]?.id);expect(JSON.stringify(first)).not.toContain('DO-NOT-IMPORT');
 }finally{await rm(root,{recursive:true,force:true});}
});
it('retains original public and private provenance and review digest when reading a cutover backup',async()=>{
 const {ReviewedClerkEnvironmentMigrationSource,CompositeMigrationSource}=await import('../../src/v2/environment-migration-source.js');
 const {previewMigration}=await import('../../src/v2/migration.js');
 const root=await mkdtemp(join(tmpdir(),'vault-backup-source-'));
 try{
  const original=join(root,'.env.local'),backup=join(root,'.env.local.pre-static-v2-20261107.old');
  const old='CLERK_SECRET_KEY=sk_test_ORIGINAL\nNEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_original\nNEXT_PUBLIC_API_ENDPOINT=http://localhost:4311\n';
  await writeFile(original,old,{mode:0o600});await writeFile(backup,old,{mode:0o600});
  const reviewKey=Buffer.alloc(32,7);
  const sources=(envFile:string,sourceIdentityFile?:string)=>new CompositeMigrationSource([
   new PublicEnvironmentMigrationSource([{envFile,sourceIdentityFile,environment:'development',applicationId:'club-app',key:'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY'},{envFile,sourceIdentityFile,environment:'development',applicationId:'club-app',key:'NEXT_PUBLIC_API_ENDPOINT'}]),
   new ReviewedClerkEnvironmentMigrationSource([{envFile,sourceIdentityFile,environment:'development',applicationId:'club-app'}],reviewKey),
  ]);
  const before=sources(original),inventory=await before.inventory(),review=await previewMigration(before,reviewKey);
  await writeFile(original,'CLERK_SECRET_KEY=sk_test_CUTOVER\nNEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_cutover\nNEXT_PUBLIC_API_ENDPOINT=http://localhost:4400\n');
  const resumed=sources(backup,original);
  expect(await resumed.inventory()).toEqual(inventory);
  expect((await previewMigration(resumed,reviewKey)).digest).toBe(review.digest);
  expect((await sources(backup).inventory())[2]?.versions[0]?.id).not.toBe(inventory[2]?.versions[0]?.id);
  await writeFile(backup,old.replace('sk_test_ORIGINAL','sk_test_CHANGED'));
  const changed=await resumed.inventory();
  expect(changed[2]?.versions[0]?.id).not.toBe(inventory[2]?.versions[0]?.id);
  expect((await previewMigration(resumed,reviewKey)).digest).not.toBe(review.digest);
 }finally{await rm(root,{recursive:true,force:true});}
});
