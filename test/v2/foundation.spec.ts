import {
  databaseNames,
  assertDatabaseName,
} from "../../src/v2/database-names.js";
import { ValueCipher } from "../../src/v2/value-cipher.js";
const scope = {
  environment: "development",
  ownerType: "tenant" as const,
  ownerId: "fcrww",
};
describe("v2 document foundation", () => {
  it("uses the exact approved database names and rejects unsafe tenant identities", () => {
    expect(databaseNames.vault).toBe("key-vault-kick-playr");
    expect(databaseNames.control).toBe("control-kick-playr");
    expect(databaseNames.tenant("fcrww")).toBe("fcrww-kick-playr");
    expect(databaseNames.tenant("123")).toBe("123-kick-playr");
    expect(databaseNames.tenant("a".repeat(52))).toHaveLength(63);
    for (const tenant of [
      "",
      "../admin",
      "_shared",
      "FCRWW",
      "key-vault",
      "control",
      "a/b",
      "a".repeat(53),
    ])
      expect(() => databaseNames.tenant(tenant)).toThrow();
    expect(() =>
      assertDatabaseName(
        "mongodb://127.0.0.1/key-vault-kick-playr",
        databaseNames.vault,
      ),
    ).not.toThrow();
    expect(() =>
      assertDatabaseName("mongodb://127.0.0.1/legacy", databaseNames.vault),
    ).toThrow();
  });
  it("encrypts the value only and authenticates every owner/version/schema boundary", () => {
    const master = Buffer.alloc(32, 7),
      cipher = new ValueCipher(master),
      bytes = Buffer.from("PRIVATE-CLIENT-SECRET");
    const value = cipher.seal(
      scope,
      "secret-one",
      "version-one",
      "bexio@1",
      bytes,
    );
    const document = {
      name: "bexio-accounting",
      type: "integration",
      tenant: "fcrww",
      version: 1,
      value,
    };
    expect(document.name).toBe("bexio-accounting");
    expect(JSON.stringify(document)).not.toContain(bytes.toString());
    expect(
      cipher.open(scope, "secret-one", "version-one", "bexio@1", value),
    ).toEqual(bytes);
    expect(
      cipher.open(
        scope,
        "secret-one",
        "version-one",
        "bexio@1",
        structuredClone(value),
      ),
    ).toEqual(bytes);
    for (const changed of [
      { ...scope, ownerId: "other" },
      { ...scope, environment: "production" },
      { ...scope, ownerType: "application" as const },
    ])
      expect(() =>
        cipher.open(changed, "secret-one", "version-one", "bexio@1", value),
      ).toThrow();
    expect(() =>
      cipher.open(scope, "secret-two", "version-one", "bexio@1", value),
    ).toThrow();
    expect(() =>
      cipher.open(scope, "secret-one", "version-two", "bexio@1", value),
    ).toThrow();
    expect(() =>
      cipher.open(scope, "secret-one", "version-one", "bexio@2", value),
    ).toThrow();
    expect(() =>
      cipher.open(scope, "secret-one", "version-one", "bexio@1", {
        ...value,
        ciphertext: Buffer.from("altered").toString("base64"),
      }),
    ).toThrow();
    cipher.close();
    expect(master).toEqual(Buffer.alloc(32, 7));
    expect(() =>
      cipher.open(scope, "secret-one", "version-one", "bexio@1", value),
    ).toThrow();
  });
  it("uses independent per-value keys and rejects malformed or oversized values without leaking them", () => {
    expect(() => new ValueCipher(Buffer.alloc(31))).toThrow();
    const cipher = new ValueCipher(Buffer.alloc(32, 8)),
      input = Buffer.from("PRIVATE");
    const a = cipher.seal(scope, "s", "v", "text", input),
      b = cipher.seal(scope, "s", "v", "text", input);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
    expect(() =>
      cipher.seal(scope, "s", "v", "text", Buffer.alloc(1048577)),
    ).toThrow();
    expect(() =>
      cipher.open(scope, "s", "v", "text", { ...a, iv: "invalid" }),
    ).toThrow();
    cipher.close();
  });
});
it("authenticates long namespaced custom schema identities without truncating them", () => {
  const cipher = new ValueCipher(Buffer.alloc(32, 5)),
    identity =
      "custom:development:tenant:" +
      "t".repeat(52) +
      ":" +
      "s".repeat(64) +
      "@1",
    input = Buffer.from("{}");
  const value = cipher.seal(scope, "resource", "version", identity, input);
  expect(cipher.open(scope, "resource", "version", identity, value)).toEqual(
    input,
  );
  cipher.close();
});
