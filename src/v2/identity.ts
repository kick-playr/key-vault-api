import {
  jwtVerify,
  decodeJwt,
  createRemoteJWKSet,
  type CryptoKey,
  type JWK,
  type JWTVerifyGetKey,
  type KeyObject,
} from "jose";
import { AccessDenied, type Actor } from "./authorization.js";
export interface TrustedRealm {
  issuer: string;
  audience?: string;
  authorizedParties?: readonly string[];
  key: CryptoKey | KeyObject | JWK | Uint8Array | JWTVerifyGetKey;
}
/** Construct realms only from the server's authoritative control-plane policy. Never from request URLs/JWT claims. */
export class HumanIdentityVerifier {
  constructor(private readonly realms: readonly TrustedRealm[]) {
    if (
      !realms.length ||
      realms.length > 101 ||
      realms.some((r) => !r.audience && !r.authorizedParties?.length)
    )
      throw Error("Invalid identity policy");
  }
  async verify(header: unknown): Promise<Actor> {
    try {
      if (
        typeof header !== "string" ||
        header.length > 16384 ||
        !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(header)
      )
        throw new AccessDenied();
      const token = header.slice(7),
        claims = decodeJwt(token),
        realm = this.realms.find((r) => r.issuer === claims.iss);
      if (!realm) throw new AccessDenied();
      const { payload } = await jwtVerify(token, realm.key as JWTVerifyGetKey, {
        issuer: realm.issuer,
        audience: realm.audience,
        algorithms: ["RS256", "ES256", "EdDSA"],
        requiredClaims: [
          "iss",
          "sub",
          "iat",
          "exp",
          ...(realm.audience ? ["aud"] : []),
        ],
        clockTolerance: 5,
        maxTokenAge: "1h",
      });
      if (
        realm.authorizedParties &&
        !realm.authorizedParties.includes(String(payload.azp))
      )
        throw new AccessDenied();
      if (
        typeof payload.sub !== "string" ||
        !payload.sub ||
        payload.sub.length > 128
      )
        throw new AccessDenied();
      return { issuer: realm.issuer, subject: payload.sub };
    } catch {
      throw new AccessDenied();
    }
  }
}
export function realmFromJwks(
  issuer: string,
  audience: string | undefined,
  jwksUrl: string,
  authorizedParties?: readonly string[],
): TrustedRealm {
  const url = new URL(jwksUrl),
    origin = new URL(issuer);
  if (
    url.protocol !== "https:" ||
    url.origin !== origin.origin ||
    url.username ||
    url.password ||
    url.hash ||
    url.search
  )
    throw Error("Invalid identity key source");
  return {
    issuer,
    audience,
    authorizedParties,
    key: createRemoteJWKSet(url, {
      timeoutDuration: 3000,
      cooldownDuration: 60000,
      cacheMaxAge: 300000,
    }),
  };
}
