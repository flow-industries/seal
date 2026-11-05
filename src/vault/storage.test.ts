import { expect, spyOn, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { type StoredRevision, VaultDatabase } from "./storage.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
const value = (id: string, size = 1): Omit<StoredRevision, "sequence"> => ({
  id,
  revision: crypto.randomUUID(),
  baseCid: null,
  envelope: { version: 1, nonce: "test", ciphertext: "x".repeat(size) },
});
const database = () => new VaultDatabase("history-test", crypto.randomUUID());

test("key snapshots reuse unchanged payloads and observe same-revision writes from another connection", async () => {
  const vault = crypto.randomUUID();
  const db = new VaultDatabase("history-test", vault);
  const other = new VaultDatabase("history-test", vault);
  try {
    await db.save(value("note"), null);
    await db.items.put({
      ...value("asset"),
      sequence: 1,
      encryptedBlobs: [new Uint8Array(200_000)],
    });
    const initial = await db.readItems(new Map());
    const cache = new Map(initial.map((item) => [item.id, item]));
    const scan = spyOn(db.items, "toArray");
    const payloads = spyOn(db.items, "bulkGet");
    expect(await db.readItems(cache)).toEqual(initial);
    expect(payloads.mock.calls).toEqual([[[]]]);
    const note = cache.get("note");
    const asset = cache.get("asset");
    if (!note || !asset) throw new Error("Missing cached records");
    await other.acknowledge("note", note.revision, "acknowledged-cid");
    const acknowledged = await db.readItems(cache);
    expect(payloads.mock.calls.at(-1)).toEqual([["note"]]);
    expect(acknowledged.find((item) => item.id === "note")?.baseCid).toBe(
      "acknowledged-cid",
    );
    expect(acknowledged.find((item) => item.id === "asset")).toBe(asset);
    await other.items.put({ ...asset, encryptedBlobs: [] });
    const changed = await db.readItems(
      new Map(acknowledged.map((item) => [item.id, item])),
    );
    expect(payloads.mock.calls.at(-1)).toEqual([["asset"]]);
    expect(changed.find((item) => item.id === "asset")?.encryptedBlobs).toEqual(
      [],
    );
    expect(asset.encryptedBlobs?.[0]?.length).toBe(200_000);
    await other.items.delete("asset");
    await other.items.put({ ...value("added"), sequence: 1 });
    expect(
      (await db.readItems(new Map(changed.map((item) => [item.id, item])))).map(
        (item) => item.id,
      ),
    ).toEqual(["added", "note"]);
    expect(payloads.mock.calls.at(-1)).toEqual([["added"]]);
    expect(scan).not.toHaveBeenCalled();
    scan.mockRestore();
    payloads.mockRestore();
  } finally {
    other.close();
    await db.delete();
  }
});

test("key snapshots reject malformed indexed fields before loading payloads", async () => {
  const db = database();
  try {
    await db.table("items").put({ ...value("note"), sequence: "invalid" });
    const payloads = spyOn(db.items, "bulkGet");
    await expect(db.readItems(new Map())).rejects.toThrow(
      "Invalid item version index",
    );
    expect(payloads).not.toHaveBeenCalled();
    payloads.mockRestore();
  } finally {
    await db.delete();
  }
});

test("version two items gain local stamps without changing ciphertext or queued proofs", async () => {
  const db = database();
  const old = new Dexie(db.name);
  old.version(2).stores({
    items: "id",
    outbox: "id",
    history: "historyId,id,sequence,order,[id+sequence]",
    historyState: "id",
  });
  const item = {
    ...value("legacy"),
    sequence: 3,
    encryptedBlobs: [new Uint8Array([4, 9])],
  };
  const pending = { ...item, queuedAt: 10 };
  await old.table("items").put(item);
  await old.table("outbox").put(pending);
  old.close();
  try {
    const [upgraded] = await db.readItems(new Map());
    expect(upgraded).toEqual({ ...item, localVersion: expect.any(String) });
    expect(await db.outbox.get("legacy")).toEqual(pending);
    const current = await db.items.get("legacy");
    if (!current?.localVersion)
      throw new Error("Missing migrated local version");
    expect(await db.itemVersions()).toEqual([
      {
        id: item.id,
        revision: item.revision,
        sequence: 3,
        localVersion: current.localVersion,
      },
    ]);
  } finally {
    await db.delete();
  }
});

test("indexed history retains numeric latest thirty and rolls accounting back with save", async () => {
  const db = database();
  try {
    const fullScan = spyOn(db.history, "toArray");
    let prior = await db.save(value("note"), null);
    for (let n = 0; n < 40; n++)
      prior = await db.save(value("note"), prior.sequence);
    expect(fullScan).not.toHaveBeenCalled();
    fullScan.mockRestore();
    const sequences = (await db.history.where("id").equals("note").toArray())
      .map((row) => row.sequence)
      .sort((a, b) => a - b);
    expect(sequences).toEqual(Array.from({ length: 30 }, (_, i) => i + 11));
    const state = await db.historyState.get("budget");
    expect(state?.bytes).toBe(30);
    await expect(
      Promise.resolve(
        db.transaction(
          "rw",
          db.items,
          db.outbox,
          db.history,
          db.historyState,
          async () => {
            await db.save(value("note"), prior.sequence);
            throw new Error("abort");
          },
        ),
      ),
    ).rejects.toThrow("abort");
    expect(await db.historyState.get("budget")).toEqual(state);
    expect((await db.items.get("note"))?.sequence).toBe(prior.sequence);
  } finally {
    await db.delete();
  }
});

test("global history evicts oldest insertion across notes rather than lexicographic keys", async () => {
  const db = database();
  try {
    for (const id of ["z", "a", "m"]) {
      await db.save(value(id, 7_000_000), null);
      await db.save(value(id), 1);
    }
    expect(
      (await db.history.orderBy("order").toArray()).map((row) => row.id),
    ).toEqual(["a", "m"]);
    expect((await db.historyState.get("budget"))?.bytes).toBe(14_000_000);
  } finally {
    await db.delete();
  }
});

test("version one history upgrades deterministic numeric order and encrypted byte totals", async () => {
  const db = database();
  const old = new Dexie(db.name);
  old
    .version(1)
    .stores({ items: "id", outbox: "id", history: "historyId,id,sequence" });
  await old.table("history").bulkPut(
    [10, 2].map((sequence) => ({
      ...value("legacy", sequence),
      sequence,
      historyId: `legacy:${sequence}`,
      encryptedBlobs: [new Uint8Array(3)],
    })),
  );
  old.close();
  try {
    expect(
      (await db.history.orderBy("order").toArray()).map((row) => row.sequence),
    ).toEqual([2, 10]);
    expect((await db.historyState.get("budget"))?.bytes).toBe(18);
  } finally {
    await db.delete();
  }
});
