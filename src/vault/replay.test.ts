import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { createVaultKey } from "../crypto/index.ts";
import { createSession } from "./session.ts";
import { VaultDatabase } from "./storage.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;

test("retained device rejects authenticated old source while fresh device lacks a freshness anchor", async () => {
  const key = await createVaultKey();
  const owner = "did:plc:replay-limit";
  const vault = crypto.randomUUID();
  const retained = createSession({ owner, vault, key });
  const fresh = createSession({ owner, vault, key });
  Object.defineProperty(fresh, "database", {
    value: new VaultDatabase(owner, `${vault}-fresh-device`),
  });
  try {
    const id = await retained.create("replay-limit.md");
    await retained.save(id, "authenticated older source");
    const older = await retained.database.items.get(id);
    if (!older) throw new Error("Missing older fixture");
    await retained.database.acknowledge(id, older.revision, "older-cid");
    await retained.save(id, "acknowledged newer source");
    const newer = await retained.database.items.get(id);
    if (!newer) throw new Error("Missing newer fixture");
    await retained.database.acknowledge(id, newer.revision, "newer-cid");
    const replay = {
      cid: "older-cid",
      record: {
        $type: "game.flow.note.item" as const,
        id,
        revision: older.revision,
        envelope: older.envelope,
        chunkHashes: older.chunkHashes,
        blobs: [],
      },
    };
    await expect(retained.applyRemote(replay)).rejects.toThrow(
      "stale revision",
    );
    expect(await retained.open(id)).toBe("acknowledged newer source");
    await fresh.applyRemote(replay);
    expect(await fresh.open(id)).toBe("authenticated older source");
    expect(new TextDecoder().decode((await fresh.export())[0]?.bytes)).toBe(
      "authenticated older source",
    );
    expect(await fresh.database.outbox.count()).toBe(0);
    const storage = JSON.stringify(await fresh.database.items.toArray());
    expect(storage).not.toContain("authenticated older source");
    expect(storage).not.toContain("replay-limit.md");
    expect(storage).not.toContain(
      Array.from(key, (byte) => byte.toString(16).padStart(2, "0")).join(""),
    );
    expect(storage).not.toContain('"key":');
  } finally {
    retained.lock();
    fresh.lock();
    key.fill(0);
    await retained.database.delete();
    await fresh.database.delete();
  }
});

test("pending edits retain an encrypted rollback anchor after history eviction and reopen", async () => {
  const key = await createVaultKey();
  const owner = "did:plc:pending-replay";
  const vault = crypto.randomUUID();
  let session = createSession({ owner, vault, key });
  try {
    const id = await session.create("private-name.md");
    await session.save(id, "older source");
    const older = await session.database.items.get(id);
    if (!older) throw new Error("Missing old revision");
    await session.database.acknowledge(id, older.revision, older.revision);
    await session.save(id, "acknowledged source");
    const base = await session.database.items.get(id);
    if (!base) throw new Error("Missing acknowledged revision");
    await session.database.acknowledge(id, base.revision, base.revision);
    for (let index = 0; index < 35; index++)
      await session.save(id, `pending source ${index}`);
    expect(
      (await session.database.outbox.get(id))?.baseRevision?.revision,
    ).toBe(base.revision);
    expect(
      (await session.database.history.where("id").equals(id).toArray()).some(
        (entry) => entry.revision === base.revision,
      ),
    ).toBe(false);
    session.lock();
    session = createSession({ owner, vault, key });
    await expect(
      session.applyRemote({
        cid: older.revision,
        record: {
          $type: "game.flow.note.item",
          id,
          revision: older.revision,
          envelope: older.envelope,
          chunkHashes: older.chunkHashes,
          blobs: [],
        },
      }),
    ).rejects.toThrow("stale revision");
    expect(await session.open(id)).toBe("pending source 34");
    const serialized = JSON.stringify(await session.database.outbox.toArray());
    expect(serialized).not.toContain("pending source");
    expect(serialized).not.toContain("acknowledged source");
    expect(serialized).not.toContain("private-name.md");
    expect(serialized).not.toContain("revisionCounter");
  } finally {
    session.lock();
    key.fill(0);
    await session.database.delete();
  }
});
