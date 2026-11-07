import { MigrationService,previewMigration,type LegacyItem } from '../../src/v2/migration.js';
function fixture(){
 const collections=new Map<string,any[]>();
 const matches=(doc:any,query:any)=>Object.entries(query).every(([key,value]:any)=>value&&typeof value==='object'&&'$in'in value?value.$in.includes(doc[key]):doc[key]===value);
 const collection=(name:string)=>{
  const rows=collections.get(name)??[];collections.set(name,rows);
  return {
   findOne:async(query:any)=>rows.find(row=>matches(row,query))??null,
   insertOne:async(row:any)=>{rows.push(structuredClone(row));return {insertedId:row._id}},
   countDocuments:async(query:any)=>rows.filter(row=>matches(row,query)).length,
   updateOne:async(query:any,update:any,options?:any)=>{let row=rows.find(row=>matches(row,query));if(!row&&options?.upsert){row={...query,...structuredClone(update.$setOnInsert??{})};rows.push(row)}if(row){Object.assign(row,structuredClone(update.$set??{}));return {matchedCount:1}}return {matchedCount:0}},
  };
 };
 const store={transaction:async(work:any)=>work({db:{collection},session:{}}),resources:collection('resources'),versions:collection('versions'),sealValue:()=>{throw Error('Backup cannot be resealed')},readValue:()=>{throw Error('Backup cannot be read from active target')}};
 const item:LegacyItem={sourceId:'old',revision:1,owner:{environment:'development',ownerType:'application',ownerId:'explorer'},name:'Obsolete duplicate Clerk',kind:'secret',disposition:'retain-legacy-backup',retentionReason:'Tenant-owned replacement is authoritative; preserve original encrypted namespace',versions:[{id:'v1',value:'PRIVATE-ORIGINAL'}]};
 const runtime={stage:async()=>{throw Error('Backup cannot migrate runtime values')},verify:async()=>{},activate:async()=>{},rollback:async()=>{},hasPostCutoverWrites:async()=>false};
 return {collections,store,item,service:new MigrationService(store as any,{inventory:async()=>[item]},runtime,Buffer.alloc(32,5)),source:{inventory:async()=>[item]}};
}
it('stages only a durable metadata ledger, verifies unchanged backups and rejects ledger/target tampering',async()=>{
 const f=fixture(),preview=await previewMigration(f.source,Buffer.alloc(32,5));
 await f.service.stage(preview.digest,'retention-job');
 const ledger=f.collections.get('vault_migration_retained_backups')!;
 expect(ledger).toHaveLength(1);expect(JSON.stringify(ledger)).not.toContain('PRIVATE-ORIGINAL');
 expect(ledger[0]).toMatchObject({sourceRevision:1,sourceVersionIds:['v1'],retentionReason:f.item.retentionReason});
 expect(f.collections.get('resources')).toEqual([]);expect(f.collections.get('versions')).toEqual([]);
 await expect(f.service.verify('retention-job')).resolves.toMatchObject({phase:'verified'});
 const original=ledger[0].retentionReason;ledger[0].retentionReason='tampered';
 await expect(f.service.verify('retention-job')).rejects.toThrow('retention verification');ledger[0].retentionReason=original;
 f.item.versions[0]!.value='CHANGED';await expect(f.service.verify('retention-job')).rejects.toThrow('source changed');f.item.versions[0]!.value='PRIVATE-ORIGINAL';
 f.collections.get('resources')!.push({_id:ledger[0]._id.split('/').at(-1)});
 await expect(f.service.verify('retention-job')).rejects.toThrow('active migration target');
});
it('cannot activate retained rollback backups while legacy readers remain unfenced',async()=>{
 const f=fixture(),preview=await previewMigration(f.source,Buffer.alloc(32,5));await f.service.stage(preview.digest,'cutover');
 const evidence={assertConsumersStopped:async()=>{},assertLegacyWritersFenced:async()=>{},assertLegacyReadersFenced:async()=>{throw Error('Legacy readers remain')},assertFreshGrantsDelivered:async()=>{},assertTenantEnrollmentApproved:async()=>{}};
 await expect(f.service.activate('cutover',evidence)).rejects.toThrow('Legacy readers remain');
 expect(f.collections.get('vault_platform_settings')).toEqual([]);
 await expect(f.service.activate('cutover',{...evidence,assertLegacyReadersFenced:async()=>{}})).resolves.toMatchObject({phase:'active'});
 expect(f.collections.get('vault_platform_settings')?.[0]).toMatchObject({enabled:true,legacyReadersFenced:true,legacyWritersFenced:true});
});
