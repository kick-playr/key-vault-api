import {BSON, Binary, Long, MongoClient, ObjectId, type Document} from 'mongodb';
import {mongoUri} from '../mongo.js';
import {TenantDatabaseMigrationService,TENANT_MIGRATION_LEDGER} from '../../src/v2/tenant-database-migration.js';
let client:MongoClient,service:TenantDatabaseMigrationService;
const source='original-club',target='fcrww-kick-playr';
beforeAll(async()=>{client=await new MongoClient(mongoUri).connect()});
afterAll(async()=>{await client?.close()});
beforeEach(async()=>{
 await client.db(source).dropDatabase();await client.db(target).dropDatabase();
 service=new TenantDatabaseMigrationService(client,{sourceDatabase:source,targetDatabase:target,tenantId:'fcrww',reviewKey:Buffer.alloc(32,8)});
 const db=client.db(source);
 await db.createCollection('business',{validator:{quantity:{$type:'long'}},validationLevel:'moderate'});
 await db.collection<Document & {_id:any}>('business').createIndex({second:-1,first:1},{name:'ordered_compound',unique:true,partialFilterExpression:{first:{$exists:true}}});
 await db.collection<Document & {_id:any}>('business').insertOne({_id:new ObjectId(),quantity:Long.fromString('9007199254740993'),second:1,first:2,date:new Date(123456),payload:new Binary(Buffer.from([1,2,3]),128),nested:{z:1,a:2}});
 await db.collection<Document & {_id:any}>('integration_connections').insertOne({_id:'encrypted',envelope:{ciphertext:'unchanged'}});
 for(const name of ['tokens','integration_sessions','integration_token_locks'])await db.collection<Document & {_id:any}>(name).insertOne({_id:'legacy',encrypted:'backup-only'});
 await client.db(target).collection<Document & {_id:any}>('integration_runtime_credentials').insertOne({_id:'native',generation:7});
 await client.db(target).collection<Document & {_id:any}>('integration_refresh_operations').insertOne({_id:'native-refresh',status:'complete'});
});
afterEach(()=>service.close());
async function dump(database:string){
 const result:Record<string,string[]>={};for(const {name} of await client.db(database).listCollections().toArray())result[name]=(await client.db(database).collection(name).find({},{promoteValues:false,promoteLongs:false}).toArray()).map(doc=>Buffer.from(BSON.serialize(doc)).toString('hex')).sort();return result;
}
test('copies BSON, collection options and indexes; leaves source and native targets intact; resumes',async()=>{
 const original=await dump(source),native=await client.db(target).collection<Document & {_id:any}>('integration_runtime_credentials').findOne({});
 const preview=await service.preview();expect(JSON.stringify(preview)).not.toContain('ciphertext');
 await service.stage(preview.digest,'job');await service.stage(preview.digest,'job');await service.verify('job');
 expect(await dump(source)).toEqual(original);
 expect((await dump(target)).business).toEqual(original.business);
 expect((await dump(target)).integration_connections).toEqual(original.integration_connections);
 expect(await client.db(target).collection<Document & {_id:any}>('integration_runtime_credentials').findOne({})).toEqual(native);
 expect(await client.db(target).collection<Document & {_id:any}>('integration_refresh_operations').countDocuments()).toBe(1);
 const names=(await client.db(target).listCollections().toArray()).map(r=>r.name);expect(names).not.toContain('tokens');expect(names).not.toContain('integration_sessions');expect(names).not.toContain('integration_token_locks');
 expect((await client.db(target).listCollections({name:'business'},{nameOnly:false}).next())?.options).toEqual((await client.db(source).listCollections({name:'business'},{nameOnly:false}).next())?.options);
 expect(await client.db(target).collection<Document & {_id:any}>('business').listIndexes().toArray()).toEqual(await client.db(source).collection<Document & {_id:any}>('business').listIndexes().toArray());
 expect(await client.db(target).collection(TENANT_MIGRATION_LEDGER).findOne({_id:'job'} as any)).toMatchObject({state:'verified'});
});
test('rejects reviewed source drift including excluded old token authorities before writes',async()=>{
 const review=await service.preview();await client.db(source).collection<Document & {_id:any}>('tokens').updateOne({_id:'legacy'} as any,{$set:{encrypted:'changed'}});
 await expect(service.stage(review.digest,'job')).rejects.toThrow('validation failed');expect(await client.db(target).collection(TENANT_MIGRATION_LEDGER).countDocuments()).toBe(0);
});
test('refuses pre-existing unknown targets and detects later target mutation',async()=>{
 const review=await service.preview();await client.db(target).collection<Document & {_id:any}>('unknown').insertOne({_id:'unknown',value:1});await expect(service.stage(review.digest,'job')).rejects.toThrow();await client.db(target).collection<Document & {_id:any}>('unknown').drop();
 await service.stage(review.digest,'job');await client.db(target).collection<Document & {_id:any}>('business').updateOne({},{$set:{first:99}});
 await expect(service.verify('job')).rejects.toThrow();await expect(service.stage(review.digest,'job')).rejects.toThrow();
});
test('detects index conflicts and source drift after staging',async()=>{
 const review=await service.preview();await service.stage(review.digest,'job');await client.db(target).collection<Document & {_id:any}>('business').createIndex({date:1},{name:'unexpected'});
 await expect(service.stage(review.digest,'job')).rejects.toThrow();await client.db(target).collection<Document & {_id:any}>('business').dropIndex('unexpected');
 await client.db(source).collection<Document & {_id:any}>('business').updateOne({},{$set:{first:3}});await expect(service.verify('job')).rejects.toThrow();
});
test('an empty unknown collection is an explicit conflict and never gets dropped or adopted',async()=>{
 const review=await service.preview();await client.db(target).createCollection('test');
 await expect(service.stage(review.digest,'job')).rejects.toMatchObject({code:'TENANT_TARGET_COLLECTION_CONFLICT',collectionName:'test'});
 expect(await client.db(target).collection('test').countDocuments()).toBe(0);
 expect(await client.db(target).collection(TENANT_MIGRATION_LEDGER).countDocuments()).toBe(0);
 expect((await client.db(target).listCollections({name:'test'}).toArray())).toHaveLength(1);
});
