import { expect, test } from "bun:test";
import Dexie from "dexie";
import { IDBKeyRange, indexedDB } from "fake-indexeddb";
import { createVaultKey } from "../crypto/index.ts";
import { createSession } from "../vault/session.ts";
import { VaultDatabase } from "../vault/storage.ts";
import { SyncFailure } from "./records.ts";
import { VaultSyncEngine } from "./vault-engine.ts";
import {
  captureSnapshot,
  type SnapshotEntry,
  snapshotRemote,
  type VaultSnapshot,
  type VaultSnapshotTransport,
} from "./vault-snapshot.ts";

Dexie.dependencies.indexedDB = indexedDB;
Dexie.dependencies.IDBKeyRange = IDBKeyRange;
function repository() {
  let snapshot: VaultSnapshot | null = null;
  let writes = 0;
  let conflicts = 0;
  let beforeWrite: (() => Promise<void>) | null = null;
  const transport: VaultSnapshotTransport = {
    version: 2,
    async readSnapshot() {
      return structuredClone(snapshot);
    },
    async writeSnapshot(entries: SnapshotEntry[], expectedCid: string | null) {
      if (beforeWrite) {
        const run = beforeWrite;
        beforeWrite = null;
        await run();
      }
      if (conflicts > 0) {
        conflicts--;
        throw new SyncFailure("conflict", "CAS");
      }
      if ((snapshot?.cid ?? null) !== expectedCid)
        throw new SyncFailure("conflict", "CAS");
      snapshot = {
        cid: `vault-${++writes}`,
        entries: structuredClone(entries),
      };
      return { cid: snapshot.cid };
    },
  };
  return {
    transport,
    get writes() {
      return writes;
    },
    conflict() {
      conflicts++;
    },
    duringWrite(run: () => Promise<void>) {
      beforeWrite = run;
    },
  };
}
async function pair() {
  const key = await createVaultKey();
  const vault = crypto.randomUUID();
  const one = createSession({ owner: "did:plc:pair", vault, key });
  const two = createSession({ owner: "did:plc:pair", vault, key });
  Object.defineProperty(two, "database", {
    value: new VaultDatabase("did:plc:pair", `${vault}-two`),
  });
  const repo = repository();
  return {
    one,
    two,
    repo,
    a: new VaultSyncEngine(one, repo.transport),
    b: new VaultSyncEngine(two, repo.transport),
  };
}
test("whole-vault CAS merges different notes and retries a forced conflict", async () => {
  const { one, two, repo, a, b } = await pair();
  const first = await one.create("one.md");
  await one.save(first, "one");
  await a.sync();
  await b.sync();
  await one.save(first, "one edited");
  const second = await two.create("two.md");
  await two.save(second, "two");
  await a.sync();
  repo.conflict();
  await b.sync();
  await a.sync();
  expect(await one.open(second)).toBe("two");
  expect(await two.open(first)).toBe("one edited");
  expect(await two.database.outbox.count()).toBe(0);
  a.stop();
  b.stop();
  one.lock();
  two.lock();
});
test("concurrent same-note edits retain both sources without starving other outbox items", async () => {
  const { one, two, a, b } = await pair();
  const id = await one.create("shared.md");
  await one.save(id, "base");
  await a.sync();
  await b.sync();
  await one.save(id, "from one");
  await two.save(id, "from two");
  const other = await two.create("other.md");
  await two.save(other, "other");
  await a.sync();
  await b.sync();
  await a.sync();
  const sources = (await one.export()).map((file) =>
    new TextDecoder().decode(file.bytes),
  );
  expect(sources).toContain("from one");
  expect(sources).toContain("from two");
  expect(sources).toContain("other");
  expect(await two.database.outbox.count()).toBe(0);
  a.stop();
  b.stop();
  one.lock();
  two.lock();
});
test("edits made during a publication remain pending and the next pull cannot overwrite them", async () => {
  const { one, two, repo, a, b } = await pair();
  const id = await one.create("race.md");
  await one.save(id, "captured");
  repo.duringWrite(() => one.save(id, "newer local"));
  await a.sync();
  expect(await one.database.outbox.count()).toBe(1);
  expect(await one.open(id)).toBe("newer local");
  await a.sync();
  await b.sync();
  expect(await two.open(id)).toBe("newer local");
  expect(await one.database.outbox.count()).toBe(0);
  a.stop();
  b.stop();
  one.lock();
  two.lock();
});
test("attachments stay inside the snapshot and deletion preserves an offline draft", async () => {
  const { one, two, a, b } = await pair();
  const bytes = new Uint8Array([1, 0, 255, 7]);
  await one.import([{ path: "image.bin", bytes }]);
  const id = await one.create("remove.md");
  await one.save(id, "base");
  await a.sync();
  await b.sync();
  expect(
    (await two.export()).find((file) => file.path === "image.bin")?.bytes,
  ).toEqual(bytes);
  await one.permanentRemove(id);
  await two.save(id, "offline draft");
  await a.sync();
  await b.sync();
  await a.sync();
  expect((await two.listNotes()).some((note) => note.id === id)).toBe(false);
  expect(
    (await one.export()).map((file) => new TextDecoder().decode(file.bytes)),
  ).toContain("offline draft");
  a.stop();
  b.stop();
  one.lock();
  two.lock();
});

test.each([2, 35])(
  "unequal concurrent save counts converge after %i local edits",
  async (count) => {
    const { one, two, a, b } = await pair();
    try {
      const id = await one.create("shared.md");
      await one.save(id, "base");
      await a.sync();
      await b.sync();
      for (let index = 0; index < count; index++)
        await one.save(id, `local ${index}`);
      await two.save(id, "remote concurrent source");
      const other = await one.create("unrelated.md");
      await one.save(other, "unrelated pending source");
      await b.sync();
      await a.sync();
      await b.sync();
      await a.sync();
      for (const session of [one, two]) {
        const sources = (await session.export()).map((file) =>
          new TextDecoder().decode(file.bytes),
        );
        expect(sources).toContain(`local ${count - 1}`);
        expect(sources).toContain("remote concurrent source");
        expect(sources).toContain("unrelated pending source");
        expect(await session.database.outbox.count()).toBe(0);
      }
    } finally {
      a.stop();
      b.stop();
      one.lock();
      two.lock();
    }
  },
);

test.each(["local", "remote"])(
  "unequal concurrent deletion on the %s branch preserves the live source",
  async (deleted) => {
    const { one, two, a, b } = await pair();
    try {
      const id = await one.create("deleted.md");
      await one.save(id, "base");
      await a.sync();
      await b.sync();
      await one.save(id, "first offline edit");
      await one.save(id, "latest offline edit");
      if (deleted === "local") {
        await one.permanentRemove(id);
        await two.save(id, "remote live source");
      } else await two.permanentRemove(id);
      await b.sync();
      await a.sync();
      await b.sync();
      expect((await one.listNotes()).some((note) => note.id === id)).toBe(
        false,
      );
      expect((await two.listNotes()).some((note) => note.id === id)).toBe(
        false,
      );
      const sources = (await two.export()).map((file) =>
        new TextDecoder().decode(file.bytes),
      );
      expect(sources).toContain(
        deleted === "local" ? "remote live source" : "latest offline edit",
      );
      expect(await one.database.outbox.count()).toBe(0);
    } finally {
      a.stop();
      b.stop();
      one.lock();
      two.lock();
    }
  },
);

test("publication acknowledgments retain the exact encrypted base across many in-flight edits", async () => {
  const { one, two, repo, a, b } = await pair();
  try {
    const id = await one.create("in-flight.md");
    await one.save(id, "acknowledged base");
    await a.sync();
    const older = await one.database.items.get(id);
    if (!older) throw new Error("Missing base");
    await one.save(id, "published while editing");
    const published = await one.database.items.get(id);
    if (!published) throw new Error("Missing publication");
    repo.duringWrite(async () => {
      for (let index = 0; index < 35; index++)
        await one.save(id, `in flight ${index}`);
    });
    await a.sync();
    expect((await one.database.outbox.get(id))?.baseRevision?.revision).toBe(
      published.revision,
    );
    await expect(
      one.applyRemote({
        cid: older.revision,
        record: {
          $type: "game.flow.note.item",
          id,
          revision: older.revision,
          envelope: older.envelope,
          blobs: [],
          chunkHashes: older.chunkHashes,
        },
      }),
    ).rejects.toThrow("stale revision");
    await a.sync();
    await b.sync();
    expect(await two.open(id)).toBe("in flight 34");
    expect(await one.database.outbox.count()).toBe(0);
  } finally {
    a.stop();
    b.stop();
    one.lock();
    two.lock();
  }
});

test.each(["live", "tombstone"])(
  "acknowledgment during %s conflict merging cannot lower the replay anchor",
  async (kind) => {
    const { one, two, a, b } = await pair();
    let release = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let reached = () => {};
    const started = new Promise<void>((resolve) => {
      reached = resolve;
    });
    try {
      const id = await one.create("racing.md");
      await one.save(id, "base");
      await a.sync();
      await b.sync();
      await one.save(id, "older acknowledged source");
      await a.sync();
      const older = (await captureSnapshot(one.database)).entries[0];
      if (!older) throw new Error("Missing acknowledged revision");
      await one.save(id, "new publication");
      const publication = await one.database.items.get(id);
      if (!publication) throw new Error("Missing publication");
      await one.save(id, "latest pending source");
      if (kind === "tombstone") await two.permanentRemove(id);
      else await two.save(id, "lower concurrent fork");
      const fork = (await captureSnapshot(two.database)).entries[0];
      if (!fork) throw new Error("Missing remote fork");
      const save = one.database.save.bind(one.database);
      let paused = false;
      one.database.save = async (...args) => {
        const saved = await save(...args);
        if (args[0].id !== id && !paused) {
          paused = true;
          reached();
          await gate;
        }
        return saved;
      };
      const incoming = snapshotRemote(fork);
      const merged = one.applyRemote(incoming.remote, incoming.blobs);
      void merged.catch(() => {});
      await started;
      await one.database.acknowledge(
        id,
        publication.revision,
        publication.revision,
        publication,
      );
      release();
      await expect(merged).rejects.toThrow("Concurrent local edit");
      expect((await one.database.items.get(id))?.baseCid).toBe(
        publication.revision,
      );
      const replay = snapshotRemote(older);
      await expect(
        one.applyRemote(replay.remote, replay.blobs),
      ).rejects.toThrow("stale revision");
      expect(await one.open(id)).toBe("latest pending source");
    } finally {
      release();
      a.stop();
      b.stop();
      one.lock();
      two.lock();
    }
  },
);
