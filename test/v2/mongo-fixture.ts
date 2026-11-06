import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { MongoClient } from "mongodb";
export async function replicaFixture() {
  const directory = await mkdtemp(join(tmpdir(), "vault-v2-mongo-")),
    listener = createServer();
  await new Promise<void>((r) => listener.listen(0, "127.0.0.1", r));
  const port = (listener.address() as { port: number }).port;
  await new Promise<void>((r) => listener.close(() => r()));
  let child: ChildProcess | undefined,
    client: MongoClient | undefined,
    failed = false;
  const close = async () => {
    await client?.close();
    if (child && child.exitCode === null && child.pid) {
      const done = new Promise<void>((r) => child!.once("exit", () => r()));
      child.kill("SIGTERM");
      await done;
    }
    await rm(directory, { recursive: true, force: true });
  };
  try {
    child = spawn(
      process.env.MONGOD_BINARY ?? "mongod",
      [
        "--bind_ip",
        "127.0.0.1",
        "--port",
        String(port),
        "--dbpath",
        directory,
        "--replSet",
        "vaultv2",
        "--quiet",
        "--noauth",
        "--wiredTigerCacheSizeGB",
        "0.25",
      ],
      { stdio: "ignore" },
    );
    child.on("error", () => {
      failed = true;
    });
    child.on("exit", () => {
      failed = true;
    });
    client = new MongoClient(
      `mongodb://127.0.0.1:${port}/?directConnection=true`,
      { serverSelectionTimeoutMS: 200 },
    );
    const deadline = Date.now() + 20000;
    let connected = false;
    while (!failed && Date.now() < deadline) {
      try {
        await client.connect();
        connected = true;
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    if (!connected) throw Error("Disposable replica set did not start");
    await client
      .db("admin")
      .command({
        replSetInitiate: {
          _id: "vaultv2",
          members: [{ _id: 0, host: `127.0.0.1:${port}` }],
        },
      });
    let primary = false;
    while (!failed && Date.now() < deadline) {
      const hello = await client.db("admin").command({ hello: 1 });
      if (hello.isWritablePrimary) {
        primary = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    if (!primary) throw Error("Disposable replica set did not elect a primary");
    return {
      uri: `mongodb://127.0.0.1:${port}/key-vault-kick-playr?replicaSet=vaultv2`,
      client,
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
