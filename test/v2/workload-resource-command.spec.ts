import {
  mkdtemp,
  writeFile,
  readFile,
  stat,
  rm,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runWorkloadResourceCommand } from "../../src/v2/workload-resource-command.js";
it("requires private input and never overwrites an export or follows a symlink", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vault-operator-"));
  let creates = 0,
    reveals = 0;
  const bytes = Buffer.from("PRIVATE-OPERATOR-EXPORT");
  const port = {
    create: async () => {
      creates++;
    },
    update: async () => {},
    reveal: async () => {
      reveals++;
      return bytes;
    },
  };
  try {
    const input = join(dir, "input.json"),
      output = join(dir, "output"),
      link = join(dir, "link");
    await writeFile(
      input,
      JSON.stringify({ name: "Mongo", kind: "secret", value: "private" }),
      { mode: 0o644 },
    );
    await expect(
      runWorkloadResourceCommand(["create", input], port),
    ).rejects.toThrow("Private input");
    expect(creates).toBe(0);
    await rm(input);
    await writeFile(
      input,
      JSON.stringify({ name: "Mongo", kind: "secret", value: "private" }),
      { mode: 0o600 },
    );
    await runWorkloadResourceCommand(["create", input], port);
    expect(creates).toBe(1);
    await symlink(input, link);
    await expect(
      runWorkloadResourceCommand(["create", link], port),
    ).rejects.toThrow();
    await runWorkloadResourceCommand(["reveal", "id", "v1", output], port);
    expect((await stat(output)).mode & 0o777).toBe(0o600);
    expect(await readFile(output, "utf8")).toBe("PRIVATE-OPERATOR-EXPORT");
    expect(bytes.every((v) => v === 0)).toBe(true);
    await expect(
      runWorkloadResourceCommand(["reveal", "id", "v1", output], port),
    ).rejects.toThrow();
    expect(reveals).toBe(1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
