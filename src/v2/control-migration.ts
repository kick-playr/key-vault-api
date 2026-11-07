import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { BSON, type ClientSession, type Document, type MongoClient } from 'mongodb';

export const CONTROL_COLLECTIONS = ['localWorkflowInstallation','tenantDefinitions','tenantDeletionOperations','tenantDeletionSnapshots','tenantExplorerAudit','tenantExplorerConfiguration','tenantHostBindings','tenantManagerInvitations','tenantManagerSetupProofs','tenantRuntimeAuthorities','tenantWorkflowConfiguration'] as const;
export interface ControlMigrationOptions {
  sourceDatabase: string;
  targetDatabase: string;
  environment: string;
  wrappingKey: Buffer;
  reviewKey: Buffer;
  additionalAuthorizedParties?: string[];
  tenantDatabaseTargets?: Record<string,string>;
}
const fail = () => Error('Control migration validation failed');
function canonical(value: unknown): string {
  function sort(v: any): any {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])]));
    return v;
  }
  return JSON.stringify(sort(BSON.EJSON.serialize(value, { relaxed: false })));
}
function indexIdentity(index: Document) {
  const {key,...options}=index;
  return canonical({orderedKey:Buffer.from(BSON.serialize(key)).toString('base64'),options});
}
function schemaIdentity(schema: Record<string,{options:Document;indexes:Document[]}>) {
  return Object.fromEntries(Object.entries(schema).map(([name,s])=>[name,{options:s.options,indexes:s.indexes.map(indexIdentity)}]));
}
function aad(database: string) { return Buffer.from(JSON.stringify(['kick-playr:tenant-workflow-configuration', database, 1])); }
function base64(value: unknown, max: number, exact?: number) {
  if (typeof value !== 'string' || !value || value.length > Math.ceil(max / 3) * 4) throw fail();
  const b = Buffer.from(value, 'base64');
  if (b.length > max || b.toString('base64') !== value || (exact !== undefined && b.length !== exact)) throw fail();
  return b;
}
export function decodeControlRuntime(row: Document, key: Buffer, database: string): Document {
  let plain: Buffer | undefined;
  try {
    if (key.length !== 32 || Object.keys(row).sort().join() !== '_id,ciphertext,nonce,tag,version' || row._id !== 'runtime:development' || !(row.version === 1 || (row.version instanceof BSON.Int32 && row.version.valueOf() === 1))) throw fail();
    const decipher = createDecipheriv('aes-256-gcm', key, base64(row.nonce,12,12));
    decipher.setAAD(aad(database)); decipher.setAuthTag(base64(row.tag,16,16));
    plain = Buffer.concat([decipher.update(base64(row.ciphertext,2*1024*1024)),decipher.final()]);
    if (plain.length > 2*1024*1024) throw fail();
    const value = JSON.parse(plain.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail();
    return value;
  } catch { throw fail(); } finally { plain?.fill(0); }
}
export function encodeControlRuntime(value: Document, key: Buffer, database: string): Document {
  let plain: Buffer | undefined;
  try {
    if (key.length !== 32) throw fail();
    plain = Buffer.from(JSON.stringify(value));
    if (plain.length > 2*1024*1024) throw fail();
    const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm',key,nonce);
    cipher.setAAD(aad(database));
    const ciphertext = Buffer.concat([cipher.update(plain),cipher.final()]);
    return {_id:'runtime:development',version:1,nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
  } catch { throw fail(); } finally { plain?.fill(0); }
}
function origin(value: unknown, httpsOnly = false): string {
  if (typeof value !== 'string') throw fail();
  let u: URL;
  try { u = new URL(value); } catch { throw fail(); }
  if (u.origin !== value || u.username || u.password || (u.protocol !== 'https:' && (httpsOnly || u.protocol !== 'http:' || !(['localhost','127.0.0.1','[::1]'].includes(u.hostname) || u.hostname.endsWith('.localhost'))))) throw fail();
  return value;
}
function strings(value: unknown): string[] {
  if (!Array.isArray(value) || !value.length || value.length > 256 || value.some(v => typeof v !== 'string' || !v || v.length > 4096) || new Set(value).size !== value.length) throw fail();
  return value;
}
/** Read-only source, fail-closed target inserts; callers fence source writers before review/stage/cutover. */
export class ControlMigrationService {
  constructor(private readonly client: MongoClient, private readonly options: ControlMigrationOptions) {
    const o = options;
    if (o.targetDatabase !== 'control-kick-playr' || o.sourceDatabase === o.targetDatabase || ![o.sourceDatabase,o.targetDatabase].every(v => /^[A-Za-z0-9_-]{1,63}$/.test(v)) || o.environment !== 'development' || o.reviewKey.length !== 32 || o.wrappingKey.length !== 32) throw fail();
    for (const [id, db] of Object.entries(o.tenantDatabaseTargets ?? {})) if (!/^[a-z0-9][a-z0-9-]{0,127}$/.test(id) || db !== id+'-kick-playr') throw fail();
    (o.additionalAuthorizedParties ?? []).forEach(v => origin(v));
  }
  private digest(value: unknown) { return createHmac('sha256',this.options.reviewKey).update(canonical(value)).digest('hex'); }
  private async transaction<T>(fn: (session: ClientSession) => Promise<T>): Promise<T> {
    const session = this.client.startSession();
    try { return (await session.withTransaction(() => fn(session), {readConcern:{level:'snapshot'},writeConcern:{w:'majority'}}))!; }
    finally { await session.endSession(); }
  }
  private async schema() {
    const source = this.client.db(this.options.sourceDatabase);
    const collections = await source.listCollections({}, {nameOnly:false}).toArray();
    const result: Record<string,{options:Document;indexes:Document[]}> = {};
    for (const c of collections) {
      if (!(CONTROL_COLLECTIONS as readonly string[]).includes(c.name)) {
        if (!['tenantDeletionTargets','tenantManagerSetupClients','tenantManagerSetupOAuth'].includes(c.name) || await source.collection(c.name).countDocuments({}) !== 0) throw Error('Unreviewed control source collection');
      }
      if (c.type !== 'collection' || Object.keys(c.options ?? {}).some(k=>!['validator','validationLevel','validationAction','collation','capped','size','max','changeStreamPreAndPostImages'].includes(k))) throw Error('Unsupported control collection options');
      const indexes = (await source.collection(c.name).listIndexes().toArray()).map(({v,ns,background,...i})=>i).sort((a,b)=>String(a.name).localeCompare(String(b.name)));
      result[c.name] = {options:c.options ?? {},indexes};
    }
    result.vault_identity_policies={options:{},indexes:[{name:'_id_',key:{_id:1}},{name:'control_identity_environment',key:{environment:1},unique:true}]};
    result.vault_identity_realms={options:{},indexes:[{name:'_id_',key:{_id:1}},{name:'control_identity_realm',key:{environment:1,issuer:1},unique:true}]};
    return result;
  }
  private async prepareSchema(schema: Awaited<ReturnType<ControlMigrationService['schema']>>, insert = false) {
    const target = this.client.db(this.options.targetDatabase);
    const existing = await target.listCollections({}, {nameOnly:false}).toArray();
    for (const [name, expected] of Object.entries(schema)) {
      const actual = existing.find(c=>c.name===name);
      if (actual && canonical(actual.options ?? {}) !== canonical(expected.options)) throw Error('Control migration collection options conflict');
      if (!actual) { if (!insert) throw Error('Control migration collection missing'); await target.createCollection(name,expected.options); }
      const indexes = await target.collection(name).listIndexes().toArray();
      for (const index of indexes) {
        const {v,ns,background,...clean} = index;
        const wanted = expected.indexes.find(i=>i.name===index.name);
        if (!wanted || indexIdentity(clean) !== indexIdentity(wanted)) throw Error('Control migration index conflict');
      }
      for (const index of expected.indexes) if (!indexes.some(i=>i.name===index.name)) { if (!insert) throw Error('Control migration index missing'); await target.collection(name).createIndexes([index as any]); }
    }
  }
  private async inventory(session: ClientSession, schema: Awaited<ReturnType<ControlMigrationService['schema']>>) {
    const o = this.options, source = this.client.db(o.sourceDatabase), rows: Record<string,Document[]> = {};
    for (const name of CONTROL_COLLECTIONS) {
      rows[name] = await source.collection(name).find({}, {session,promoteValues:false,promoteLongs:false}).limit(100001).toArray();
      if (rows[name]!.length > 100000) throw fail();
      rows[name]!.sort((a,b) => canonical(a._id).localeCompare(canonical(b._id)));
    }
    for (const name of ['tenantDeletionTargets','tenantManagerSetupClients','tenantManagerSetupOAuth']) if (schema[name]) {
      if (await source.collection(name).countDocuments({}, {session}) !== 0) throw Error('Unreviewed control source collection');
      rows[name]=[];
    }
    for (const row of rows.tenantExplorerConfiguration!) for (const field of ['credentials','integrations']) {
      const value = row[field];
      if (value !== undefined && value !== null && (typeof value !== 'object' || Object.keys(value).length)) throw Error('Unsupported credential-bearing control configuration');
    }
    if (rows.tenantWorkflowConfiguration!.length !== 1) throw fail();
    const payload = decodeControlRuntime(rows.tenantWorkflowConfiguration![0]!,o.wrappingKey,o.sourceDatabase), e = payload.explorer;
    if (!e || typeof e !== 'object' || Array.isArray(e)) throw fail();
    const targetPayload = BSON.EJSON.parse(BSON.EJSON.stringify(payload));
    for (const [tenantId, database] of Object.entries(o.tenantDatabaseTargets ?? {})) {
      const tenant = targetPayload.tenants?.find((t:any)=>t.id===tenantId);
      if (!tenant || typeof tenant.mongoUri !== 'string') throw Error('Reviewed tenant database binding missing');
      if (!tenant.mongoUri.startsWith('vault:')) {
        const uri = new URL(tenant.mongoUri);
        if (!['mongodb:','mongodb+srv:'].includes(uri.protocol)) throw fail();
        uri.pathname = '/'+database; tenant.mongoUri = uri.toString();
      }
      if (tenant.databaseName !== undefined) tenant.databaseName=database;
    }
    for (const binding of targetPayload.explorer?.keyBindings?.bindings ?? []) if (binding.controlDatabase === o.sourceDatabase) binding.controlDatabase = o.targetDatabase;
    const issuer = origin(e.issuer,true), admins = strings(e.adminSubjects);
    if (admins.some(v => !/^[A-Za-z0-9_-]{1,128}$/.test(v))) throw fail();
    const parties = (value: unknown) => [...new Set([...strings(value).map(v => origin(v)),...(o.additionalAuthorizedParties ?? []).map(v => origin(v))])];
    if (!Array.isArray(e.clubRealms) || e.clubRealms.length > 100) throw fail();
    const realms = [{issuer,authorizedParties:parties(e.authorizedParties)}, ...e.clubRealms.map((r: any) => ({issuer:origin(r.issuer,true),authorizedParties:parties(r.authorizedParties)}))];
    if (new Set(realms.map(r=>r.issuer)).size !== realms.length) throw fail();
    const seeds: Record<string,Document[]> = {
      vault_identity_policies:[{_id:o.environment,environment:o.environment,issuer,adminSubjects:admins,revision:1,enabled:true}],
      vault_identity_realms:realms.map(r=>({_id:this.digest([o.environment,r.issuer]),environment:o.environment,...r,jwksUrl:r.issuer+'/.well-known/jwks.json',enabled:true})),
    };
    return { rows, payload:targetPayload, seeds, schema, digest:this.digest({tenantDatabaseTargets:o.tenantDatabaseTargets ?? {},targetPayload,schema:schemaIdentity(schema),source:o.sourceDatabase,target:o.targetDatabase,environment:o.environment,additionalAuthorizedParties:o.additionalAuthorizedParties ?? [],rows,seeds}) };
  }
  async preview() {
    const schema = await this.schema();
    return this.transaction(async session => {
      const i = await this.inventory(session,schema);
      return {digest:i.digest,counts:Object.fromEntries(Object.entries({...i.rows,...i.seeds}).map(([n,r])=>[n,r.length]))};
    });
  }
  private async compare(i: Awaited<ReturnType<ControlMigrationService['inventory']>>, session: ClientSession, insert: boolean) {
    const o = this.options, target = this.client.db(o.targetDatabase);
    for (const [name, rows] of Object.entries({...i.rows,...i.seeds})) {
      const collection = target.collection<Document>(name);
      for (const row of rows) {
        const existing = await collection.findOne({_id:row._id},{session,promoteValues:false,promoteLongs:false});
        const runtime = name === 'tenantWorkflowConfiguration';
        if (existing) {
          if (canonical(runtime ? decodeControlRuntime(existing,o.wrappingKey,o.targetDatabase) : existing) !== canonical(runtime ? i.payload : row)) throw Error('Control migration target conflict');
        } else if (insert) await collection.insertOne(runtime ? encodeControlRuntime(i.payload,o.wrappingKey,o.targetDatabase) : row,{session});
        else throw Error('Control migration target incomplete');
      }
      if (await collection.countDocuments({}, {session}) !== rows.length) throw Error('Control migration target conflict');
    }
  }
  async stage(reviewedDigest: string, jobId: string) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(jobId)) throw fail();
    const schema = await this.schema();
    await this.transaction(async session => { if ((await this.inventory(session,schema)).digest !== reviewedDigest) throw Error('Control migration source changed'); });
    await this.prepareSchema(schema,true);
    return this.transaction(async session => {
      const i = await this.inventory(session,schema);
      if (i.digest !== reviewedDigest) throw Error('Control migration source changed');
      const jobs = this.client.db(this.options.targetDatabase).collection<any>('vault_control_migration_jobs');
      const old = await jobs.findOne({_id:jobId},{session});
      if (old && old.digest !== i.digest) throw Error('Control migration job conflict');
      await this.compare(i,session,true);
      if (!old) await jobs.insertOne({_id:jobId,digest:i.digest,phase:'staged'},{session});
      return {jobId,phase:'staged' as const,digest:i.digest};
    });
  }
  async verify(jobId: string) {
    const schema = await this.schema();
    await this.prepareSchema(schema);
    return this.transaction(async session => {
      const i = await this.inventory(session,schema);
      const jobs = this.client.db(this.options.targetDatabase).collection<any>('vault_control_migration_jobs');
      const job = await jobs.findOne({_id:jobId},{session});
      if (!job || job.digest !== i.digest) throw Error('Control migration source changed or stage incomplete');
      await this.compare(i,session,false);
      await jobs.updateOne({_id:jobId},{$set:{phase:'verified'}},{session});
      return {jobId,phase:'verified' as const,digest:i.digest};
    });
  }
}
