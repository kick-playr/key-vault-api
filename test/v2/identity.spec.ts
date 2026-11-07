import { generateKeyPair, SignJWT, exportJWK } from "jose";
import { HumanIdentityVerifier } from "../../src/v2/identity.js";
it("validates issuer audience lifetime and signature without trusting caller roles", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const verifier = new HumanIdentityVerifier([
    { issuer: "https://identity.example", audience: "vault", key: publicKey },
  ]);
  const token = await new SignJWT({ roles: ["global-admin"] })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer("https://identity.example")
    .setAudience("vault")
    .setSubject("user")
    .setIssuedAt()
    .setExpirationTime("2m")
    .sign(privateKey);
  expect(await verifier.verify("Bearer " + token)).toEqual({
    issuer: "https://identity.example",
    subject: "user",
  });
  await expect(
    new HumanIdentityVerifier([
      { issuer: "https://identity.example", audience: "other", key: publicKey },
    ]).verify("Bearer " + token),
  ).rejects.toThrow();
  await expect(
    verifier.verify("Bearer " + token.slice(0, -5) + "xxxxx"),
  ).rejects.toThrow();
});
it("supports trusted Clerk session parties when no audience template is configured", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const verifier = new HumanIdentityVerifier([
    {
      issuer: "https://identity.example",
      authorizedParties: ["http://localhost:4001"],
      key: publicKey,
    },
  ]);
  const token = await new SignJWT({ azp: "http://localhost:4001" })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer("https://identity.example")
    .setSubject("user")
    .setIssuedAt()
    .setExpirationTime("2m")
    .sign(privateKey);
  expect(await verifier.verify("Bearer " + token)).toEqual({
    issuer: "https://identity.example",
    subject: "user",
  });
  await expect(
    new HumanIdentityVerifier([
      {
        issuer: "https://identity.example",
        authorizedParties: ["http://other.example"],
        key: publicKey,
      },
    ]).verify("Bearer " + token),
  ).rejects.toThrow();
});
