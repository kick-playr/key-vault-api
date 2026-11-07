import { constants } from "node:fs";
import { open } from "node:fs/promises";
import type { ResourceInput } from "./resources.js";
/** Deployment-local file boundary. Never accepts or prints credential values in argv/stdout. */
export interface WorkloadResourcePort {
  create(input: ResourceInput): Promise<unknown>;
  update(id: string, revision: number, input: ResourceInput): Promise<unknown>;
  reveal(id: string, version: string): Promise<Buffer>;
}
async function privateInput(filename: string): Promise<ResourceInput> {
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size > 65536)
      throw Error("Private input file required");
    const bytes = await file.readFile();
    try {
      return JSON.parse(bytes.toString("utf8")) as ResourceInput;
    } finally {
      bytes.fill(0);
    }
  } finally {
    await file.close();
  }
}
export async function runWorkloadResourceCommand(
  args: readonly string[],
  port: WorkloadResourcePort,
): Promise<void> {
  if (args[0] === "create" && args.length === 2) {
    await port.create(await privateInput(args[1]!));
    return;
  }
  if (
    args[0] === "update" &&
    args.length === 4 &&
    /^[1-9][0-9]*$/.test(args[2]!)
  ) {
    const revision = Number(args[2]);
    if (!Number.isSafeInteger(revision)) throw Error("Invalid revision");
    await port.update(args[1]!, revision, await privateInput(args[3]!));
    return;
  }
  if (args[0] === "reveal" && args.length === 4) {
    // Exclusive creation also rejects a destination symlink. Never truncate a
    // deployment secret, existing export or arbitrary operator-owned file.
    const file = await open(
      args[3]!,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_WRONLY |
        constants.O_NOFOLLOW,
      0o600,
    );
    let bytes: Buffer | undefined;
    try {
      bytes = await port.reveal(args[1]!, args[2]!);
      await file.writeFile(bytes);
      await file.sync();
    } finally {
      bytes?.fill(0);
      await file.close();
    }
    return;
  }
  throw Error(
    "Usage: create <private-input.json> | update <resource-id> <revision> <private-input.json> | reveal <resource-id> <version-id> <new-private-output-file>",
  );
}
