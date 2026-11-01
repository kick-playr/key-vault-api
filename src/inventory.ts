import { createHmac, timingSafeEqual } from 'node:crypto';
import { fail, requireCondition as check } from './errors.js';
import { Scope, scopeId } from './types.js';
import { object } from './validation.js';
import { Kind, VaultService } from './vault.js';

type Query = Record<string, string>;
interface Cursor { scope: string; endpoint: string; fingerprint: string; generation: number; after: string; expires: number }
export class InventoryService {
  private readonly signingKey: Buffer;
  constructor(private readonly vault: VaultService, masterKey: Buffer) {
    this.signingKey = createHmac('sha256', masterKey).update('vault-inventory-cursor-v1').digest();
  }
  private mac(value: string) { return createHmac('sha256', this.signingKey).update(value).digest(); }
  private parseQuery(input: unknown, local: boolean): Query {
    const query = object(input, ['maxresults', '$skiptoken', ...(local ? ['kind', 'name', 'namePrefix', 'purpose', 'enabled', 'expiresBefore', 'tagName', 'tagValue'] : ['api-version'])]);
    check(Object.values(query).every(v => typeof v === 'string'));
    const q = query as Query;
    check(q.maxresults === undefined || /^(?:[1-9]|1[0-9]|2[0-5])$/.test(q.maxresults));
    if (local) {
      check(q.kind === undefined || q.kind === 'key' || q.kind === 'secret');
      for (const name of ['name', 'namePrefix', 'purpose']) check(q[name] === undefined || /^[a-zA-Z0-9-]{1,127}$/.test(q[name]!));
      check(q.enabled === undefined || q.enabled === 'true' || q.enabled === 'false');
      check(q.expiresBefore === undefined || /^\d+$/.test(q.expiresBefore) && Number.isSafeInteger(Number(q.expiresBefore)));
      check((q.tagName === undefined) === (q.tagValue === undefined));
      check(q.tagName === undefined || q.tagName.length > 0 && q.tagName.length <= 512 && q.tagValue!.length <= 512);
    }
    return q;
  }
  list(scope: Scope, endpoint: Kind | 'local/inventory', input: unknown) {
    const local = endpoint === 'local/inventory', q = this.parseQuery(input, local);
    const limit = Number(q.maxresults ?? 25);
    const filter = Object.fromEntries(Object.entries({ ...q, maxresults: String(limit) }).filter(([k]) => k !== '$skiptoken').sort(([a], [b]) => a.localeCompare(b)));
    const fingerprint = createHmac('sha256', this.signingKey).update(JSON.stringify(filter)).digest('hex');
    let cursor: Cursor | undefined;
    if (q.$skiptoken !== undefined) {
      try {
        check(q.$skiptoken.length <= 4096 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(q.$skiptoken));
        const [data, signature] = q.$skiptoken.split('.') as [string, string];
        const provided = Buffer.from(signature, 'base64url');
        check(provided.length === 32 && provided.toString('base64url') === signature && timingSafeEqual(this.mac(data), provided));
        cursor = JSON.parse(Buffer.from(data, 'base64url').toString('utf8')) as Cursor;
        check(cursor.scope === scopeId(scope) && cursor.endpoint === endpoint && cursor.fingerprint === fingerprint);
        check(Number.isSafeInteger(cursor.generation) && cursor.generation >= 0 && typeof cursor.after === 'string' && cursor.after.length <= 256);
        check(Number.isSafeInteger(cursor.expires) && cursor.expires > Date.now());
      } catch { fail(400, 'InvalidContinuationToken'); }
    }
    return this.vault.store.read(scope, ns => {
      const generation = ns?.generation ?? 0;
      if (cursor && cursor.generation !== generation) fail(409, 'PaginationInvalidated');
      const rows: { order: string; metadata: Record<string, unknown> }[] = [];
      const kinds: Kind[] = local ? (q.kind ? [q.kind === 'key' ? 'keys' : 'secrets'] : ['keys', 'secrets']) : [endpoint as Kind];
      for (const kind of kinds) for (const [name, versions] of Object.entries(ns?.[kind] ?? {})) {
        const item = versions.at(-1); if (!item) continue;
        const order = kind + '/' + name;
        if (cursor && order <= cursor.after) continue;
        if (q.name !== undefined && name !== q.name || q.namePrefix !== undefined && !name.startsWith(q.namePrefix)) continue;
        const purpose = item.tags && Object.hasOwn(item.tags, 'purpose') ? item.tags.purpose : undefined;
        if (q.purpose !== undefined && purpose !== q.purpose) continue;
        if (q.enabled !== undefined && item.attributes.enabled !== (q.enabled === 'true')) continue;
        if (q.expiresBefore !== undefined && (item.attributes.exp === undefined || item.attributes.exp > Number(q.expiresBefore))) continue;
        if (q.tagName !== undefined && (!item.tags || !Object.hasOwn(item.tags, q.tagName) || item.tags[q.tagName] !== q.tagValue)) continue;
        const baseId = `${this.vault.baseUrl}/namespaces/${scope.environment}/${scope.tenant}/${kind}/${name}`;
        const common = { attributes: item.attributes, ...(item.tags && { tags: item.tags }), ...(kind === 'secrets' && item.contentType !== undefined && { contentType: item.contentType }) };
        const metadata = local
          ? { ...common, kind: kind === 'keys' ? 'key' : 'secret', name, id: baseId, version: item.version, versionId: this.vault.id(scope, kind, name, item.version), ...(purpose !== undefined && { purpose }) }
          : { ...common, [kind === 'keys' ? 'kid' : 'id']: baseId };
        rows.push({ order, metadata });
      }
      rows.sort((a, b) => a.order < b.order ? -1 : a.order > b.order ? 1 : 0);
      const page = rows.slice(0, limit);
      const result: { value: Record<string, unknown>[]; nextLink?: string } = { value: page.map(r => r.metadata) };
      if (rows.length > limit) {
        const next: Cursor = { scope: scopeId(scope), endpoint, fingerprint, generation, after: page.at(-1)!.order, expires: cursor?.expires ?? Date.now() + 15 * 60 * 1000 };
        const data = Buffer.from(JSON.stringify(next)).toString('base64url');
        const url = new URL(`${this.vault.baseUrl}/namespaces/${scope.environment}/${scope.tenant}/${endpoint}`);
        for (const [key, value] of Object.entries(q)) if (key !== '$skiptoken') url.searchParams.set(key, value);
        url.searchParams.set('$skiptoken', data + '.' + this.mac(data).toString('base64url'));
        result.nextLink = url.href;
      }
      return result;
    });
  }
}
