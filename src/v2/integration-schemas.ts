import { Ajv, type AnySchema, type ValidateFunction } from "ajv";
import { createHash } from "node:crypto";
import { scopeFilter } from "./mongo-store.js";
import type { ResourceScope } from "./records.js";
const invalid = () =>
  Error("Integration data does not match its static schema");
const forbidden = new Set([
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "sessiontoken",
  "jwt",
  "oauthstate",
  "pkceverifier",
]);
const runtimeField = (key: string) =>
  forbidden.has(key.replace(/[_-]/g, "").toLowerCase());
function snapshot(value: unknown, maxBytes: number): any {
  let nodes = 0;
  const parents = new Set<object>();
  const visit = (v: unknown, depth: number): any => {
    if (++nodes > 4096 || depth > 16) throw invalid();
    if (v === null || typeof v === "string" || typeof v === "boolean") return v;
    if (typeof v === "number") {
      if (!Number.isFinite(v) || Object.is(v, -0)) throw invalid();
      return v;
    }
    if (!v || typeof v !== "object" || parents.has(v)) throw invalid();
    const proto = Object.getPrototypeOf(v),
      array = Array.isArray(v);
    if (!array && proto !== null && Object.getPrototypeOf(proto) !== null)
      throw invalid();
    const descriptors = Object.getOwnPropertyDescriptors(v);
    parents.add(v);
    try {
      if (array) {
        if (Reflect.ownKeys(v).length !== (v as unknown[]).length + 1)
          throw invalid();
        const result = [];
        for (let i = 0; i < (v as unknown[]).length; i++) {
          const item = descriptors[String(i)];
          if (!item?.enumerable || !("value" in item)) throw invalid();
          result.push(visit(item.value, depth + 1));
        }
        return result;
      }
      const result: Record<string, unknown> = {};
      for (const key of Reflect.ownKeys(v)) {
        if (
          typeof key !== "string" ||
          ["__proto__", "prototype", "constructor"].includes(key)
        )
          throw invalid();
        const item = descriptors[key];
        if (!item?.enumerable || !("value" in item)) throw invalid();
        result[key] = visit(item.value, depth + 1);
      }
      return result;
    } finally {
      parents.delete(v);
    }
  };
  const result = visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(result)) > maxBytes) throw invalid();
  return result;
}
function checkSchema(node: any): void {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    if (node.length > 64) throw invalid();
    node.forEach(checkSchema);
    return;
  }
  for (const [key, value] of Object.entries(node)) {
    if (
      [
        "$ref",
        "$dynamicRef",
        "$async",
        "pattern",
        "patternProperties",
        "format",
        "$data",
      ].includes(key)
    )
      throw invalid();
    if (key === "properties" || key === "definitions" || key === "$defs") {
      if (!value || typeof value !== "object" || Array.isArray(value))
        throw invalid();
      if (key === "properties" && Object.keys(value).some(runtimeField))
        throw invalid();
      Object.values(value).forEach(checkSchema);
    } else if (
      key === "required" &&
      Array.isArray(value) &&
      value.some((v) => typeof v === "string" && runtimeField(v))
    )
      throw invalid();
    else if (
      [
        "allOf",
        "anyOf",
        "oneOf",
        "items",
        "additionalItems",
        "additionalProperties",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
      ].includes(key)
    )
      checkSchema(value);
    else if (key === "dependencies" && value && typeof value === "object")
      for (const dependency of Object.values(value))
        if (!Array.isArray(dependency)) checkSchema(dependency);
  }
}
function rejectRuntimeFields(node: any): void {
  if (!node || typeof node !== "object") return;
  for (const [key, value] of Object.entries(node)) {
    if (runtimeField(key)) throw invalid();
    rejectRuntimeFields(value);
  }
}
const string = { type: "string", minLength: 1, maxLength: 16384 };
const definition = (
  properties: Record<string, unknown>,
  required: string[],
) => ({ type: "object", properties, required, additionalProperties: false });
const builtin: Record<string, unknown> = {
  bexio: definition(
    {
      clientId: string,
      clientSecret: string,
      accountReference: string,
      redirectUri: string,
    },
    ["clientId", "clientSecret", "accountReference"],
  ),
  dropbox: definition(
    {
      clientId: string,
      clientSecret: string,
      accountReference: string,
      archiveRoot: string,
      redirectUri: string,
    },
    ["clientId", "clientSecret", "accountReference"],
  ),
  pingen: definition(
    { apiToken: string, organizationId: string, apiOrigin: string },
    ["apiToken", "organizationId"],
  ),
  email: definition(
    {
      protocol: { enum: ["smtp", "imap"] },
      host: string,
      port: { type: "integer", minimum: 1, maximum: 65535 },
      tls: { enum: ["implicit", "starttls", "none"] },
      username: string,
      password: string,
      sender: string,
    },
    ["protocol", "host", "port", "tls", "username", "password"],
  ),
};
interface Prepared {
  hash: string;
  schema: unknown;
  validate: ValidateFunction;
}
export class IntegrationSchemas {
  private readonly definitions = new Map<string, Prepared>();
  constructor() {
    for (const [type, schema] of Object.entries(builtin))
      this.install("builtin:" + type + "@1", schema);
  }
  private install(identity: string, input: unknown): string {
    const schema = snapshot(input, 32768);
    if (!schema || schema.type !== "object") throw invalid();
    checkSchema(schema);
    const hash = createHash("sha256")
        .update(JSON.stringify(schema))
        .digest("hex"),
      old = this.definitions.get(identity);
    if (old) {
      if (old.hash !== hash)
        throw Error("Integration schema version already exists");
      return identity;
    }
    if (this.definitions.size >= 512)
      throw Error("Integration schema capacity reached");
    const ajv = new Ajv({
      strict: true,
      allErrors: false,
      ownProperties: true,
      coerceTypes: false,
      useDefaults: false,
      removeAdditional: false,
      validateFormats: false,
    });
    for (const keyword of ["x-secret", "x-public"])
      ajv.addKeyword({ keyword, schemaType: "boolean" });
    let validate: ValidateFunction;
    try {
      validate = ajv.compile(schema as AnySchema);
    } catch {
      throw Error("Invalid static integration schema");
    }
    this.definitions.set(identity, { hash, schema, validate });
    return identity;
  }
  registerCustom(
    scope: ResourceScope,
    name: string,
    version: number,
    schema: unknown,
  ): string {
    const owner = scopeFilter(scope);
    if (
      !/^[a-z][a-z0-9-]{0,63}$/.test(name) ||
      !Number.isSafeInteger(version) ||
      version < 1
    )
      throw invalid();
    return this.install(
      `custom:${owner.environment}:${owner.ownerType}:${owner.ownerId}:${name}@${version}`,
      schema,
    );
  }
  schema(identity: string): unknown {
    const prepared = this.definitions.get(identity);
    if (!prepared) throw invalid();
    return snapshot(prepared.schema, 32768);
  }
  validate(identity: string, value: unknown): Record<string, unknown> {
    const prepared = this.definitions.get(identity);
    if (!prepared) throw invalid();
    const data = snapshot(value, 65536);
    rejectRuntimeFields(data);
    if (!prepared.validate(data)) throw invalid();
    return data as Record<string, unknown>;
  }
}
