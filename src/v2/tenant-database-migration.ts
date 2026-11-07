import {createHmac, timingSafeEqual} from 'node:crypto';
import {BSON, type Document, type MongoClient, type CreateCollectionOptions, type IndexDescription} from 'mongodb';
import {databaseNames, tenantIdentifier} from './database-names.js';

export const TENANT_MIGRATION_EXCLUDED = ['tokens','integration_sessions','integration_token_locks'] as const;
export const TENANT_MIGRATION_NATIVE = ['integration_runtime_credentials','integration_refresh_operations'] as const;
export const TENANT_MIGRATION_LEDGER = 'tenant_database_migrations';
export interface TenantDatabaseMigrationOptions {sourceDatabase:string;targetDatabase:string;tenantId:string;reviewKey:Buffer}
type Snapshot = {name:string;options:Document;indexes:Document[];documents:Document[]};
const fail=()=>Error('Tenant database migration validation failed');
export class TenantDatabaseMigrationConflictError extends Error {
  readonly code='TENANT_TARGET_COLLECTION_CONFLICT';
  constructor(readonly collectionName:string){super('Tenant database migration validation failed')}
}
// BSON serialization retains field/index-key ordering, dates, integer types and binary subtypes.
const bytes=(value:Document)=>Buffer.from(BSON.serialize(value));
const same=(a:Document,b:Document)=>bytes(a).equals(bytes(b));
function collectionOptions(input:Document):Document {
  const result={...input};delete result.uuid;delete result.idIndex;return result;
}
function indexOptions(input:Document):Document {
  const result={...input};delete result.ns;delete result.v;return result;
}
/** Explicit offline clone. Callers must fence source writers during review/stage/verify.
 * No source writes, drops, overwrites or credential collection copies are performed. */
export class TenantDatabaseMigrationService {
  private readonly key:Buffer;
  constructor(private readonly client:MongoClient,private readonly options:TenantDatabaseMigrationOptions){
    tenantIdentifier(options.tenantId);
    if(options.targetDatabase!==databaseNames.tenant(options.tenantId)||!options.sourceDatabase||options.sourceDatabase===options.targetDatabase||options.reviewKey.length!==32||([databaseNames.control,databaseNames.vault] as readonly string[]).includes(options.sourceDatabase))throw fail();
    this.key=Buffer.from(options.reviewKey);
  }
  private ignored(name:string){return [...TENANT_MIGRATION_EXCLUDED,...TENANT_MIGRATION_NATIVE,TENANT_MIGRATION_LEDGER].includes(name as any)}
  private async snapshot(database:string,includeExcluded=false):Promise<Snapshot[]>{
    const db=this.client.db(database),rows=await db.listCollections({}, {nameOnly:false}).toArray(),result:Snapshot[]=[];
    for(const row of rows.sort((a,b)=>a.name.localeCompare(b.name))){
      if(this.ignored(row.name)&&!(includeExcluded&&(TENANT_MIGRATION_EXCLUDED as readonly string[]).includes(row.name)))continue;
      if(row.type!=='collection'||row.name.startsWith('system.'))throw fail();
      const collection=db.collection(row.name);
      const documents=await collection.find({}, {promoteValues:false,promoteLongs:false,promoteBuffers:false}).toArray();
      documents.sort((a,b)=>Buffer.compare(bytes(a),bytes(b)));
      const indexes=(await collection.listIndexes().toArray()).map(indexOptions).sort((a,b)=>String(a.name).localeCompare(String(b.name)));
      result.push({name:row.name,options:collectionOptions(row.options??{}),indexes,documents});
    }
    return result;
  }
  private digest(rows:Snapshot[]){
    const h=createHmac('sha256',this.key);
    for(const value of [{source:this.options.sourceDatabase,target:this.options.targetDatabase,tenantId:this.options.tenantId},...rows]){const data=bytes(value);h.update(String(data.length)+':');h.update(data)}
    return h.digest('hex');
  }
  private equalDigest(a:unknown,b:string){return typeof a==='string'&&/^[a-f0-9]{64}$/.test(a)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'))}
  async preview(){const rows=await this.snapshot(this.options.sourceDatabase,true);return {sourceDatabase:this.options.sourceDatabase,targetDatabase:this.options.targetDatabase,tenantId:this.options.tenantId,collections:rows.map(r=>({name:r.name,count:r.documents.length,indexCount:r.indexes.length})),excludedCollections:[...TENANT_MIGRATION_EXCLUDED],preservedCollections:[...TENANT_MIGRATION_NATIVE],digest:this.digest(rows)}}
  async stage(reviewedDigest:string,jobId:string){
    if(!/^[A-Za-z0-9_-]{1,100}$/.test(jobId))throw fail();
    const reviewed=await this.snapshot(this.options.sourceDatabase,true),digest=this.digest(reviewed),rows=reviewed.filter(r=>!this.ignored(r.name)),copyDigest=this.digest(rows);
    if(!this.equalDigest(reviewedDigest,digest))throw fail();
    const target=this.client.db(this.options.targetDatabase),ledger=target.collection<Document>(TENANT_MIGRATION_LEDGER),job=await ledger.findOne({_id:jobId} as Document);
    if(job&&(job.digest!==digest||job.sourceDatabase!==this.options.sourceDatabase||job.tenantId!==this.options.tenantId))throw fail();
    const existing=await target.listCollections({}, {nameOnly:true}).toArray();
    const unknown=existing.find(r=>!this.ignored(r.name)&&(!job||!job.collections?.includes(r.name)));
    if(unknown)throw new TenantDatabaseMigrationConflictError(unknown.name);
    if(existing.some(r=>(TENANT_MIGRATION_EXCLUDED as readonly string[]).includes(r.name)))throw fail();
    if(!job){
      await ledger.insertOne({_id:jobId,sourceDatabase:this.options.sourceDatabase,tenantId:this.options.tenantId,digest,copyDigest,collections:rows.map(r=>r.name),state:'staging'} as Document);
    }
    for(const row of rows){
      const present=await target.listCollections({name:row.name},{nameOnly:false}).next();
      if(!present)await target.createCollection(row.name,row.options as CreateCollectionOptions);
      else if(!same(collectionOptions(present.options??{}),row.options))throw fail();
      const collection=target.collection(row.name);
      const targetIndexes=(await collection.listIndexes().toArray()).map(indexOptions);
      if(targetIndexes.some(index=>!row.indexes.some(expected=>same(index,expected))))throw fail();
      for(const index of row.indexes)if(!targetIndexes.some(actual=>same(actual,index)))await collection.createIndexes([index as IndexDescription]);
      const current=await collection.find({}, {promoteValues:false,promoteLongs:false,promoteBuffers:false}).toArray();
      const identity=(doc:Document)=>bytes({_id:doc._id}).toString('hex');
      const expectedById=new Map(row.documents.map(doc=>[identity(doc),doc]));
      const currentById=new Map(current.map(doc=>[identity(doc),doc]));
      if(current.some(doc=>{const expected=expectedById.get(identity(doc));return !expected||!same(doc,expected)}))throw fail();
      for(const doc of row.documents){
        const old=currentById.get(identity(doc));
        if(old){if(!same(old,doc))throw fail()}else await collection.insertOne(doc);
      }
    }
    await this.verify(jobId);
    return {jobId,digest,state:'verified' as const};
  }
  async verify(jobId:string){
    const ledger=this.client.db(this.options.targetDatabase).collection<Document>(TENANT_MIGRATION_LEDGER),job=await ledger.findOne({_id:jobId} as Document);
    if(!job||job.sourceDatabase!==this.options.sourceDatabase||job.tenantId!==this.options.tenantId)throw fail();
    const source=await this.snapshot(this.options.sourceDatabase,true),target=await this.snapshot(this.options.targetDatabase);
    if(!this.equalDigest(job.digest,this.digest(source))||!this.equalDigest(job.copyDigest,this.digest(target)))throw fail();
    const targetNames=await this.client.db(this.options.targetDatabase).listCollections({}, {nameOnly:true}).toArray();
    if(targetNames.some(r=>(TENANT_MIGRATION_EXCLUDED as readonly string[]).includes(r.name)))throw fail();
    await ledger.updateOne({_id:jobId,digest:job.digest} as Document,{$set:{state:'verified'}});
    return {jobId,digest:job.digest as string,state:'verified' as const};
  }
  close(){this.key.fill(0)}
}
