import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { CipherPart, ResourceScope, ValueEnvelope } from "./records.js";
import { tenantIdentifier } from "./database-names.js";
const unavailable = () => Error("Vault value unavailable");
const text = (v: unknown) =>
  typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/.test(v);
const exact = (v: unknown, fields: string[]): v is Record<string, unknown> => {
  if (!v || typeof v !== "object") return false;
  const proto = Object.getPrototypeOf(v);
  if (proto !== null && Object.getPrototypeOf(proto) !== null) return false;
  const own = Object.getOwnPropertyDescriptors(v);
  return (
    Reflect.ownKeys(v).every(
      (key) =>
        typeof key === "string" && own[key]?.enumerable && "value" in own[key]!,
    ) && Object.keys(own).sort().join(",") === [...fields].sort().join(",")
  );
};
function decode(value: unknown, length?: number, max = 1048576): Buffer {
  if (typeof value !== "string" || value.length > Math.ceil(max / 3) * 4)
    throw unavailable();
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.toString("base64") !== value ||
    bytes.length > max ||
    (length !== undefined && bytes.length !== length)
  )
    throw unavailable();
  return bytes;
}
/** Per-version encryption only. Metadata stays independently indexed and plaintext. */
export class ValueCipher {
  private readonly master: Buffer;
  private closed = false;
  constructor(master: Buffer) {
    if (!Buffer.isBuffer(master) || master.length !== 32) throw unavailable();
    this.master = Buffer.from(master);
  }
  private aad(
    scope: ResourceScope,
    resourceId: string,
    versionId: string,
    schemaIdentity: string,
    purpose: "value" | "data-key",
  ): Buffer {
    if (
      this.closed ||
      !scope ||
      !text(scope.environment) ||
      !["application", "tenant"].includes(scope.ownerType) ||
      !text(scope.ownerId) ||
      !text(resourceId) ||
      !text(versionId) ||
      !text(schemaIdentity)
    )
      throw unavailable();
    if (scope.ownerType === "tenant") tenantIdentifier(scope.ownerId);
    return Buffer.from(
      JSON.stringify([
        "vault-v2",
        purpose,
        scope.environment,
        scope.ownerType,
        scope.ownerId,
        resourceId,
        versionId,
        schemaIdentity,
      ]),
    );
  }
  private encrypt(key: Buffer, aad: Buffer, value: Buffer): CipherPart {
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(value), cipher.final()]);
    return Object.freeze({
      iv: iv.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
    });
  }
  private decrypt(
    key: Buffer,
    aad: Buffer,
    part: CipherPart,
    max: number,
  ): Buffer {
    if (!exact(part, ["iv", "ciphertext", "tag"])) throw unavailable();
    const iv = decode(part.iv, 12, 12),
      tag = decode(part.tag, 16, 16),
      ciphertext = decode(part.ciphertext, undefined, max);
    const decipher = createDecipheriv("aes-256-gcm", key, iv),
      chunks: Buffer[] = [];
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    try {
      chunks.push(decipher.update(ciphertext));
      chunks.push(decipher.final());
      return Buffer.concat(chunks);
    } finally {
      for (const chunk of chunks) chunk.fill(0);
    }
  }
  seal(
    scope: ResourceScope,
    resourceId: string,
    versionId: string,
    schemaIdentity: string,
    value: Buffer,
  ): ValueEnvelope {
    let dataKey: Buffer | undefined;
    try {
      const aad = this.aad(
        scope,
        resourceId,
        versionId,
        schemaIdentity,
        "value",
      );
      if (!Buffer.isBuffer(value) || value.length > 1048576)
        throw unavailable();
      dataKey = randomBytes(32);
      const payload = this.encrypt(dataKey, aad, value),
        wrappedKey = this.encrypt(
          this.master,
          this.aad(scope, resourceId, versionId, schemaIdentity, "data-key"),
          dataKey,
        );
      return Object.freeze({
        format: 1,
        algorithm: "A256GCM",
        ...payload,
        wrappedKey,
      });
    } catch {
      throw unavailable();
    } finally {
      dataKey?.fill(0);
    }
  }
  open(
    scope: ResourceScope,
    resourceId: string,
    versionId: string,
    schemaIdentity: string,
    value: ValueEnvelope,
  ): Buffer {
    let dataKey: Buffer | undefined;
    try {
      const aad = this.aad(
        scope,
        resourceId,
        versionId,
        schemaIdentity,
        "value",
      );
      if (
        !exact(value, [
          "format",
          "algorithm",
          "iv",
          "ciphertext",
          "tag",
          "wrappedKey",
        ]) ||
        value.format !== 1 ||
        value.algorithm !== "A256GCM"
      )
        throw unavailable();
      dataKey = this.decrypt(
        this.master,
        this.aad(scope, resourceId, versionId, schemaIdentity, "data-key"),
        value.wrappedKey,
        32,
      );
      if (dataKey.length !== 32) throw unavailable();
      return this.decrypt(
        dataKey,
        aad,
        { iv: value.iv, ciphertext: value.ciphertext, tag: value.tag },
        1048576,
      );
    } catch {
      throw unavailable();
    } finally {
      dataKey?.fill(0);
    }
  }
  close(): void {
    this.closed = true;
    this.master.fill(0);
  }
}
