import { createPrivateKey, createPublicKey, generateKeyPair, privateDecrypt, publicEncrypt, randomUUID, constants } from 'node:crypto';
import { promisify } from 'node:util';
import { EncryptedStore } from './store';
import { Attributes, Namespace, Scope, Version, namespace, scopeId } from './types';
import { fail, requireCondition as check } from './errors';
import { attributes, identifier, object, tags } from './validation';

const generate = promisify(generateKeyPair);
export type Kind = 'keys' | 'secrets';
export function active(version: Version) {
  const now = Math.floor(Date.now() / 1000), a = version.attributes;
  if (!a.enabled || (a.exp !== undefined && a.exp <= now) || (a.nbf !== undefined && a.nbf > now)) fail(403, 'Forbidden');
}
export function changed(ns: Namespace, action: string, name: string) {
  ns.generation++;
  ns.audit.push({ time: Math.floor(Date.now() / 1000), action, name });
  if (ns.audit.length > 1000) ns.audit.shift();
}
export function find(ns: Namespace | undefined, kind: Kind, name: string, version?: string): Version {
  identifier(name);
  const versions = ns && Object.hasOwn(ns[kind], name) ? ns[kind][name] : undefined;
  const item = version ? versions?.find(v => v.version === version) : versions?.at(-1);
  if (!item) fail(404, kind === 'keys' ? 'KeyNotFound' : 'SecretNotFound');
  return item;
}
function makeAttributes(input: unknown): Attributes {
  const now = Math.floor(Date.now() / 1000);
  return { enabled: true, ...attributes(input), created: now, updated: now, recoveryLevel: 'Purgeable' };
}
export function secretInput(input: unknown) {
  const body = object(input, ['value', 'attributes', 'tags', 'contentType']);
  check(typeof body.value === 'string' && Buffer.byteLength(body.value) <= 25600);
  check(body.contentType === undefined || typeof body.contentType === 'string' && body.contentType.length <= 255);
  return { value: body.value, attributes: makeAttributes(body.attributes), tags: tags(body.tags), contentType: body.contentType as string | undefined };
}
export function keyInput(input: unknown) {
  const body = object(input, ['kty', 'key_size', 'key_ops', 'attributes', 'tags']);
  check(body.kty === 'RSA');
  const size = body.key_size ?? 2048;
  check(size === 2048 || size === 3072);
  const ops = body.key_ops ?? ['encrypt', 'decrypt'];
  check(Array.isArray(ops) && ops.length > 0 && ops.length <= 2 && new Set(ops).size === ops.length && ops.every(op => op === 'encrypt' || op === 'decrypt'));
  return { size: size as number, ops: ops as string[], attributes: makeAttributes(body.attributes), tags: tags(body.tags) };
}
export async function newKey(input: unknown): Promise<Version> {
  const parsed = keyInput(input);
  const pair = await generate('rsa', { modulusLength: parsed.size, publicExponent: 65537 });
  return { version: randomUUID().replaceAll('-', ''), attributes: parsed.attributes, tags: parsed.tags,
    privateKey: pair.privateKey.export({ format: 'jwk' }), publicKey: pair.publicKey.export({ format: 'jwk' }), keySize: parsed.size, keyOps: parsed.ops };
}
export function newSecret(input: unknown): Version {
  return { version: randomUUID().replaceAll('-', ''), ...secretInput(input) };
}

export class VaultService {
  constructor(readonly store: EncryptedStore, readonly baseUrl: string) {}
  id(scope: Scope, kind: Kind, name: string, version: string) {
    return `${this.baseUrl}/namespaces/${scope.environment}/${scope.tenant}/${kind}/${name}/${version}`;
  }
  bundle(scope: Scope, kind: Kind, name: string, item: Version, metadata = false): Record<string, unknown> {
    const common = { attributes: item.attributes, ...(item.tags && { tags: item.tags }) };
    if (kind === 'secrets') return { ...common, id: this.id(scope, kind, name, item.version),
      ...(item.contentType !== undefined && { contentType: item.contentType }), ...(!metadata && { value: item.value }) };
    return metadata ? { ...common, kid: this.id(scope, kind, name, item.version) } :
      { ...common, key: { ...item.publicKey, kid: this.id(scope, kind, name, item.version), key_ops: item.keyOps } };
  }
  async create(scope: Scope, kind: Kind, name: string, body: unknown) {
    identifier(name);
    // Generate inside the transaction so rotation and provisioning cannot interleave.
    return this.store.transaction(async state => {
      const ns = namespace(state, scope);
      const item = kind === 'keys' ? await newKey(body) : newSecret(body);
      const versions = Object.hasOwn(ns[kind], name) ? ns[kind][name]! : [];
      versions.push(item); ns[kind][name] = versions;
      ns.tombstones = ns.tombstones.filter(x => x !== `${kind}/${name}`);
      changed(ns, 'create:' + kind, name);
      return this.bundle(scope, kind, name, item);
    });
  }
  get(scope: Scope, kind: Kind, name: string, version?: string) {
    return this.store.read(state => {
      const item = find(state.namespaces[scopeId(scope)], kind, name, version); active(item);
      return this.bundle(scope, kind, name, item);
    });
  }
  versions(scope: Scope, kind: Kind, name: string) {
    return this.store.read(state => {
      const ns = state.namespaces[scopeId(scope)]; find(ns, kind, name);
      return { value: ns![kind][name]!.map(item => this.bundle(scope, kind, name, item, true)) };
    });
  }
  async update(scope: Scope, kind: Kind, name: string, version: string, input: unknown) {
    const body = object(input, kind === 'keys' ? ['attributes', 'tags', 'key_ops'] : ['attributes', 'tags', 'contentType']);
    const attr = attributes(body.attributes), tag = tags(body.tags);
    if (body.contentType !== undefined) check(typeof body.contentType === 'string' && body.contentType.length <= 255);
    return this.store.transaction(state => {
      const ns = namespace(state, scope), item = find(ns, kind, name, version);
      if (body.key_ops !== undefined) {
        const parsed = keyInput({ kty: 'RSA', key_ops: body.key_ops }); item.keyOps = parsed.ops;
      }
      item.attributes = { ...item.attributes, ...attr, updated: Math.floor(Date.now() / 1000) };
      check(item.attributes.nbf === undefined || item.attributes.exp === undefined || item.attributes.nbf < item.attributes.exp);
      if (tag !== undefined) item.tags = tag;
      if (body.contentType !== undefined) item.contentType = body.contentType as string;
      changed(ns, 'update:' + kind, name);
      // Metadata writers must not gain read access to an existing secret value.
      return this.bundle(scope, kind, name, item, kind === 'secrets');
    });
  }
  async delete(scope: Scope, kind: Kind, name: string) {
    return this.store.transaction(state => {
      const ns = namespace(state, scope), item = find(ns, kind, name);
      const result = this.bundle(scope, kind, name, item, true);
      delete ns[kind][name]; ns.tombstones.push(`${kind}/${name}`); changed(ns, 'delete:' + kind, name);
      return result;
    });
  }
  crypto(scope: Scope, name: string, version: string, operation: 'encrypt' | 'decrypt', input: unknown) {
    const body = object(input, ['alg', 'value']);
    check(body.alg === 'RSA-OAEP-256' && typeof body.value === 'string' && /^[A-Za-z0-9_-]*$/.test(body.value) && body.value.length <= 8192);
    const value = Buffer.from(body.value, 'base64url'); check(value.toString('base64url') === body.value);
    return this.store.read(state => {
      const item = find(state.namespaces[scopeId(scope)], 'keys', name, version); active(item);
      if (!item.keyOps?.includes(operation)) fail(403, 'Forbidden');
      try {
        const options = { padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' };
        const result = operation === 'encrypt'
          ? publicEncrypt({ ...options, key: createPublicKey({ key: item.publicKey!, format: 'jwk' }) }, value)
          : privateDecrypt({ ...options, key: createPrivateKey({ key: item.privateKey!, format: 'jwk' }) }, value);
        return { kid: this.id(scope, 'keys', name, version), value: result.toString('base64url') };
      } catch { fail(400, 'BadParameter'); }
    });
  }
}
