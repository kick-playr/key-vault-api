import { createHash } from "node:crypto";
import { bindingDigest } from "@kick-playr/local-key-vault/runtime-client";
import type { MongoStore } from "./store.js";
import type { Namespace, OAuthCredential, Scope } from "./types.js";
import { fail } from "./errors.js";
import { object } from "./validation.js";
import { vaultName } from "./manifest.js";
import { active, changed, find, newSecret } from "./vault.js";
import { validatedManifest } from "./runtime-manifests.js";
const base = ["application", "mapping", "provider"];
const identity = [...base, "bindingRevision", "bindingDigest"];
const tokenFields = ["accessToken", "refreshToken", "expiresAt"];
function validate(
  scope: Scope,
  input: unknown,
  extra: string[],
  enrollment = false,
) {
  const b = object(input, [...(enrollment ? base : identity), ...extra]);
  if (
    scope.tenant === "_shared" ||
    b.application !== "club-api" ||
    typeof b.mapping !== "string" ||
    !/^RUNTIME_CREDENTIAL_[A-Z0-9_]{1,100}$/.test(b.mapping) ||
    !["bexio", "dropbox"].includes(b.provider as string)
  )
    fail(400, "InvalidOAuthCredential");
  if (
    !enrollment &&
    (!Number.isSafeInteger(b.bindingRevision) ||
      (b.bindingRevision as number) < 1 ||
      typeof b.bindingDigest !== "string" ||
      !/^[a-f0-9]{64}$/.test(b.bindingDigest))
  )
    fail(400, "InvalidOAuthCredential");
  return b;
}
function payload(value: unknown, provider: string) {
  if (typeof value !== "string" || Buffer.byteLength(value) > 25600)
    fail(400, "InvalidOAuthCredential");
  let p: Record<string, unknown>;
  try {
    p = JSON.parse(value);
  } catch {
    fail(400, "InvalidOAuthCredential");
  }
  const fields = [
    "clientId",
    "clientSecret",
    ...tokenFields,
    ...(provider === "dropbox" ? ["archiveRoot"] : []),
  ];
  p = object(p!, fields);
  for (const key of fields.filter((k) => k !== "expiresAt"))
    if (
      typeof p[key] !== "string" ||
      !(p[key] as string).trim() ||
      (p[key] as string).length > 16384
    )
      fail(400, "InvalidOAuthCredential");
  if (!Number.isSafeInteger(p.expiresAt) || (p.expiresAt as number) <= 0)
    fail(400, "InvalidOAuthCredential");
  return p;
}
const canonical = (p: Record<string, unknown>) =>
  JSON.stringify(
    Object.fromEntries(
      Object.entries(p).sort(([a], [b]) => a.localeCompare(b)),
    ),
  );
const digest = (p: Record<string, unknown>) =>
  createHash("sha256").update(canonical(p)).digest("hex");
export class OAuthCredentialService {
  constructor(
    private readonly store: Pick<MongoStore, "read" | "transaction">,
  ) {}
  private descriptor(
    ns: Namespace | undefined,
    scope: Scope,
    b: Record<string, unknown>,
    current = false,
  ) {
    const saved = ns?.runtimeManifests?.["club-api"];
    const manifest =
      saved?.versions[
        String(current ? saved.currentRevision : b.bindingRevision)
      ];
    if (!manifest) fail(404, "OAuthCredentialNotFound");
    const m = validatedManifest(manifest);
    if (
      m.scope.environment !== scope.environment ||
      m.scope.tenant !== scope.tenant ||
      m.application !== "club-api" ||
      (!current && bindingDigest(m.request) !== b.bindingDigest)
    )
      fail(409, "OAuthBindingMismatch");
    const descriptors = m.request.secrets.filter(
      (s) => s.mapping === b.mapping,
    );
    if (descriptors.length !== 1) fail(409, "OAuthBindingMismatch");
    return descriptors[0]!;
  }
  private resource(
    ns: Namespace | undefined,
    scope: Scope,
    b: Record<string, unknown>,
  ) {
    const d = this.descriptor(ns, scope, b),
      r = ns?.oauthCredentials?.[b.mapping as string];
    if (
      !r ||
      r.application !== b.application ||
      r.provider !== b.provider ||
      r.purpose !== d.purpose ||
      !r.versions.includes(d.version)
    )
      fail(409, "OAuthBindingMismatch");
    return r;
  }
  private value(
    ns: Namespace,
    scope: Scope,
    r: OAuthCredential,
    version: unknown,
  ) {
    if (typeof version !== "string" || !r.versions.includes(version))
      fail(409, "OAuthVersionMismatch");
    const item = find(
      ns,
      "secrets",
      vaultName(scope, "secret", r.purpose),
      version,
    );
    active(item);
    if (item.tags?.purpose !== undefined && item.tags.purpose !== r.purpose)
      fail(409, "OAuthBindingMismatch");
    payload(item.value, r.provider);
    return item;
  }
  async enroll(scope: Scope, input: unknown) {
    const b = validate(scope, input, [], true);
    return this.store.transaction(scope, (ns) => {
      const d = this.descriptor(ns, scope, b, true),
        existing = ns.oauthCredentials?.[b.mapping as string];
      if (existing) {
        if (
          existing.application !== b.application ||
          existing.provider !== b.provider ||
          existing.purpose !== d.purpose ||
          existing.anchorVersion !== d.version
        )
          fail(409, "OAuthBindingMismatch");
        return structuredClone(existing);
      }
      const r: OAuthCredential = {
        application: "club-api",
        provider: b.provider as "bexio" | "dropbox",
        purpose: d.purpose,
        anchorVersion: d.version,
        currentVersion: d.version,
        versions: [d.version],
        attempts: [],
      };
      this.value(ns, scope, r, d.version);
      const item = find(
        ns,
        "secrets",
        vaultName(scope, "secret", d.purpose),
        d.version,
      );
      if (item.tags?.envName !== undefined && item.tags.envName !== b.mapping)
        fail(409, "OAuthBindingMismatch");
      if (
        Object.values(ns.oauthCredentials ?? {}).some(
          (x) => x.purpose === r.purpose,
        )
      )
        fail(409, "OAuthBindingMismatch");
      ns.oauthCredentials ??= {};
      ns.oauthCredentials[b.mapping as string] = r;
      changed(ns, "oauth.enroll", b.mapping as string);
      return structuredClone(r);
    });
  }
  async read(scope: Scope, input: unknown) {
    const b = validate(scope, input, ["version"]);
    return this.store.read(scope, (ns) => {
      const r = this.resource(ns, scope, b),
        v = this.value(ns!, scope, r, b.version);
      return { version: v.version, value: v.value! };
    });
  }
  private claim(b: Record<string, unknown>) {
    if (
      typeof b.operationId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        b.operationId,
      ) ||
      typeof b.expectedVersion !== "string" ||
      !/^[0-9a-f]{32}$/.test(b.expectedVersion)
    )
      fail(400, "InvalidOAuthCredential");
  }
  async begin(scope: Scope, input: unknown) {
    const b = validate(scope, input, ["expectedVersion", "operationId"]);
    this.claim(b);
    return this.store.transaction(scope, (ns) => {
      const r = this.resource(ns, scope, b);
      if (
        find(ns, "secrets", vaultName(scope, "secret", r.purpose)).version !==
          b.expectedVersion ||
        r.currentVersion !== b.expectedVersion ||
        r.attempts.some((a) => !a.version || a.operationId === b.operationId)
      )
        fail(409, "OAuthRenewalConflict");
      this.value(ns, scope, r, b.expectedVersion);
      r.attempts.push({
        operationId: b.operationId as string,
        expectedVersion: b.expectedVersion as string,
      });
      changed(ns, "oauth.begin", b.mapping as string);
      return {
        operationId: b.operationId as string,
        expectedVersion: b.expectedVersion as string,
      };
    });
  }
  async commit(scope: Scope, input: unknown) {
    const b = validate(scope, input, [
      "expectedVersion",
      "operationId",
      "value",
    ]);
    this.claim(b);
    const p = payload(b.value, b.provider as string),
      hash = digest(p);
    return this.store.transaction(scope, (ns) => {
      const r = this.resource(ns, scope, b),
        a = r.attempts.find(
          (x) =>
            x.operationId === b.operationId &&
            x.expectedVersion === b.expectedVersion,
        );
      if (!a) fail(409, "OAuthRenewalConflict");
      if (a.version) {
        if (a.digest !== hash) fail(409, "OAuthRenewalConflict");
        return { version: a.version };
      }
      if (
        find(ns, "secrets", vaultName(scope, "secret", r.purpose)).version !==
          b.expectedVersion ||
        r.currentVersion !== b.expectedVersion
      )
        fail(409, "OAuthRenewalConflict");
      const old = this.value(ns, scope, r, b.expectedVersion),
        prior = payload(old.value, r.provider);
      if (
        Object.keys(prior).sort().join() !== Object.keys(p).sort().join() ||
        Object.keys(prior).some(
          (k) => !tokenFields.includes(k) && prior[k] !== p[k],
        ) ||
        (p.expiresAt as number) <= Date.now() ||
        (p.expiresAt as number) <= (prior.expiresAt as number)
      )
        fail(400, "InvalidOAuthCredential");
      const next = newSecret({
        value: canonical(p),
        tags: old.tags,
        contentType: old.contentType,
        attributes: {
          enabled: old.attributes.enabled,
          ...(old.attributes.exp !== undefined
            ? { exp: old.attributes.exp }
            : {}),
          ...(old.attributes.nbf !== undefined
            ? { nbf: old.attributes.nbf }
            : {}),
        },
      });
      next.oauthRenewal = {
        mapping: b.mapping as string,
        operationId: b.operationId as string,
        previousVersion: old.version,
      };
      ns.secrets[vaultName(scope, "secret", r.purpose)]!.push(next);
      r.currentVersion = next.version;
      r.versions.push(next.version);
      a.version = next.version;
      a.digest = hash;
      changed(ns, "oauth.commit", b.mapping as string);
      return { version: next.version };
    });
  }
}
