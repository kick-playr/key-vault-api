import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { Collection, Db, MongoClient, MongoServerError } from 'mongodb';
import { describeSystemError, fail } from './errors.js';
import { emptyNamespace, Namespace, Scope, scopeId } from './types.js';
import { scopePart } from './validation.js';
import type { StoredGrant } from './grants.js';
import { databaseFromMongoUri } from './mongodb-url.js';
import type { AuditEvent } from './audit.js';

export interface StoreConfig { mongoUri: string; masterKey: Buffer }
interface Envelope { _id: string; schema: 1; revision: number; iv: string; tag: string; data: string }
const MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024;
const duplicate = (e: unknown) => e instanceof MongoServerError && e.code === 11000;

/** Namespace callbacks may be retried after a CAS conflict; keep them free of external side effects. */
export class MongoStore {
  private closed = false;
  private readonly queues = new Map<string, Promise<unknown>>();
  private readonly collection: Collection<Envelope>;
  private readonly database: Db;
  private constructor(private readonly client: MongoClient, private readonly config: StoreConfig, database: string) {
    this.database = client.db(database);
    this.collection = this.database.collection<Envelope>('vault_namespaces');
  }
  static async open(config: StoreConfig, options: { createVerifier?: boolean } = {}): Promise<MongoStore> {
    const database = databaseFromMongoUri(config.mongoUri);
    if (!Buffer.isBuffer(config.masterKey) || config.masterKey.length !== 32 ||
        !/^mongodb(?:\+srv)?:\/\/\S+$/.test(config.mongoUri)) fail(500, 'InvalidBootstrap');
    let client: MongoClient | undefined;
    const copy = { ...config, masterKey: Buffer.from(config.masterKey) };
    let stage = 'MongoDB URL parsing';
    try {
      client = new MongoClient(config.mongoUri, {
        serverSelectionTimeoutMS: 3000, connectTimeoutMS: 3000, socketTimeoutMS: 5000,
        readPreference: 'primary', readConcern: { level: 'majority' },
        writeConcern: { w: 'majority', wtimeoutMS: 5000 }, retryWrites: false,
      });
      stage = 'MongoDB connection';
      await client.connect();
      stage = 'MongoDB database selection';
      const store = new MongoStore(client, copy, database);
      // Shared encrypted key verifier; unique _id makes simultaneous first starts safe.
      const metadata = store.database.collection<Envelope>('vault_metadata');
      stage = 'MongoDB key verifier access';
      let marker = await metadata.findOne({ _id: 'master-key-check' });
      if (!marker && options.createVerifier === false) {
        stage = 'Existing vault metadata verification; initialize the vault separately before generating bindings';
        throw Error();
      }
      if (!marker) {
        const candidate = store.encode('master-key-check', 0, { marker: 'local-vault-key-check-v1' });
        try { await metadata.insertOne(candidate); } catch (e) { if (!duplicate(e)) throw e; }
        marker = await metadata.findOne({ _id: 'master-key-check' });
      }
      stage = 'MongoDB master-key verification';
      if (!marker || (store.decode(marker) as { marker?: string }).marker !== 'local-vault-key-check-v1') throw new Error();
      return store;
    } catch (error) {
      await client?.close().catch(() => undefined); copy.masterKey.fill(0);
      const hint = stage === 'MongoDB master-key verification'
        ? 'VAULT_MASTER_KEY cannot decrypt the stored verifier, or the verifier is corrupt. Use the original master key for this database.'
        : describeSystemError(error);
      fail(503, 'StoreUnavailable', `${stage}: ${hint}`);
    }
  }
  private id(scope: Scope) {
    scopePart(scope.environment); scopePart(scope.tenant);
    return createHash('sha256').update(scopeId(scope)).digest('hex');
  }
  private encode(id: string, revision: number, value: unknown): Envelope {
    const plaintext = Buffer.from(JSON.stringify(value));
    if (plaintext.length > MAX_PLAINTEXT_BYTES) fail(507, 'NamespaceTooLarge');
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.config.masterKey, iv);
    cipher.setAAD(Buffer.from(JSON.stringify(['mongodb-vault-v1', id, revision])));
    const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { _id: id, schema: 1, revision, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
  }
  private decode(envelope: Envelope): unknown {
    try {
      if (envelope.schema !== 1 || !Number.isSafeInteger(envelope.revision) || envelope.revision < 0) throw new Error();
      const decipher = createDecipheriv('aes-256-gcm', this.config.masterKey, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(Buffer.from(JSON.stringify(['mongodb-vault-v1', envelope._id, envelope.revision])));
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]).toString('utf8'));
    } catch { fail(503, 'StoreUnavailable'); }
  }
  private async fetch(id: string, collection = this.collection): Promise<Envelope | null> {
    if (this.closed) fail(503, 'StoreUnavailable');
    try { return await collection.findOne({ _id: id }); } catch { fail(503, 'StoreUnavailable'); }
  }
  async read<T>(scope: Scope, fn: (namespace: Namespace | undefined) => T): Promise<T> {
    const envelope = await this.fetch(this.id(scope));
    const ns = envelope ? this.decode(envelope) as Namespace : undefined;
    return structuredClone(fn(ns));
  }
  transaction<T>(scope: Scope, fn: (namespace: Namespace) => T | Promise<T>): Promise<T> {
    return this.transactionDocument(this.collection, this.id(scope), emptyNamespace, fn);
  }
  async readGrants(): Promise<StoredGrant[]> {
    const envelope = await this.fetch('grants:registry', this.database.collection<Envelope>('vault_grants'));
    return envelope ? this.decode(envelope) as StoredGrant[] : [];
  }
  async appendAudit(event: AuditEvent): Promise<void> {
    if (this.closed) fail(503, 'StoreUnavailable');
    try {
      await this.database.collection<AuditEvent & { _id: string }>('vault_audit').insertOne({ ...event, _id: event.requestId });
    } catch { fail(503, 'StoreUnavailable'); }
  }
  transactionGrants<T>(fn: (grants: StoredGrant[]) => T): Promise<T> {
    return this.transactionDocument(this.database.collection<Envelope>('vault_grants'), 'grants:registry', () => [] as StoredGrant[], fn);
  }
  private transactionDocument<State, T>(collection: Collection<Envelope>, id: string, initial: () => State, fn: (value: State) => T | Promise<T>): Promise<T> {
    const queueId = `${collection.collectionName}:${id}`;
    const operation = (this.queues.get(queueId) ?? Promise.resolve()).catch(() => undefined).then(async () => {
      for (let attempt = 0; attempt < 20; attempt++) {
        const current = await this.fetch(id, collection);
        const ns = current ? this.decode(current) as State : initial();
        const result = await fn(ns);
        const revision = (current?.revision ?? 0) + 1;
        if (!Number.isSafeInteger(revision)) fail(503, 'StoreUnavailable');
        const next = this.encode(id, revision, ns);
        try {
          if (current) {
            const written = await collection.replaceOne({ _id: id, revision: current.revision }, next);
            if (written.matchedCount !== 1) continue;
          } else {
            try { await collection.insertOne(next); } catch (e) { if (duplicate(e)) continue; throw e; }
          }
          return structuredClone(result);
        } catch { fail(503, 'StoreUnavailable'); }
      }
      fail(409, 'StorageConflict');
    });
    this.queues.set(queueId, operation);
    void operation.finally(() => { if (this.queues.get(queueId) === operation) this.queues.delete(queueId); }).catch(() => undefined);
    return operation;
  }
  async close() {
    if (this.closed) return;
    this.closed = true;
    await Promise.allSettled([...this.queues.values()]);
    await this.client.close(); this.config.masterKey.fill(0);
  }
}
